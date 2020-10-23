/**
 * Kickstart
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "ini.h"
#include "log.h"

static ini_t *ini;
static struct ks_config_mount_target *mount_targets;
static struct ks_config_verity_target *verity_targets;
static struct ks_config_keystore *keystores;
static struct ks_config *config;

int ks_config_dump(void)
{

    for (int i = 0; i < ini_section_count(ini); i++)
    {
        ks_log(KS_LOG_DEBUG, "%s\n", ini_section_name(ini, i));
    }

    return 0;
}

static int parse_keystore(int i, struct ks_config_keystore **ks_out)
{
    struct ks_config_keystore *ks = NULL;
    bool ks_found_name = false;
    bool ks_found_device = false;
    bool ks_found_device_type = false;

    ks = malloc(sizeof(*ks));
    memset(ks, 0, sizeof(*ks));

    for (int n = 0; n < ini_property_count(ini, i); n++) {
        if (strcmp(ini_property_name(ini, i, n), "name") == 0) {
            ks->name = ini_property_value(ini, i, n);
            ks_found_name = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device") == 0) {
            ks->device = ini_property_value(ini, i, n);
            ks_found_device = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device_type") == 0) {
            ks->device_type = ini_property_value(ini, i, n);
            ks_found_device_type = true;
        } else if (strcmp(ini_property_name(ini, i, n), "set") == 0) {
            char sys = ini_property_value(ini, i, n)[0];
            if (sys == 'A' || sys == 'a')
                ks->system = KS_SYSTEM_A;
            else if (sys == 'B' || sys == 'b')
                ks->system = KS_SYSTEM_B;
            else
                ks->system = KS_SYSTEM_INVALID;
        } else {
            ks_log(KS_LOG_ERROR, "%s: Unknown property %s.%s, ignoring\n",
                                    __func__,
                                    ini_section_name(ini, i),
                                    ini_property_name(ini, i, n));
        }
    }

    if (ks_found_name && ks_found_device && ks_found_device_type) {
        (*ks_out) = ks;
        return 0;
    } else {
        free(ks);
        ks_log(KS_LOG_ERROR, "%s: Parse error\n", __func__);
        return -1;
    }
}

static int parse_mount_target(int i, struct ks_config_mount_target **mt_out)
{
    bool mt_found_name = false;
    bool mt_found_dev = false;
    bool mt_found_type = false;
    bool mt_found_target = false;
    bool mt_found_device_type = false;

    (*mt_out) = NULL;

    struct ks_config_mount_target *mt = NULL;
    mt = malloc(sizeof(*mt));
    memset(mt, 0, sizeof(*mt));
    mt->options = "";

    for (int n = 0; n < ini_property_count(ini, i); n++) {
        if (strcmp(ini_property_name(ini, i, n), "name") == 0) {
            mt->name = ini_property_value(ini, i, n);
            mt_found_name = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device") == 0) {
            mt->device = ini_property_value(ini, i, n);
            mt_found_dev = true;
        } else if (strcmp(ini_property_name(ini, i, n), "options") == 0) {
            mt->options = ini_property_value(ini, i, n);
        } else if (strcmp(ini_property_name(ini, i, n), "device_type") == 0) {
            mt->device_type = ini_property_value(ini, i, n);
            mt_found_device_type = true;
        } else if (strcmp(ini_property_name(ini, i, n), "type") == 0) {
            mt->fs_type = ini_property_value(ini, i, n);
            mt_found_type = true;
        } else if (strcmp(ini_property_name(ini, i, n), "mount_target") == 0) {
            mt->mount_target = ini_property_value(ini, i, n);
            mt_found_target = true;
        } else if (strcmp(ini_property_name(ini, i, n), "move") == 0) {
            if (strcmp(ini_property_value(ini, i, n), "true") == 0)
                mt->move = true;
            else
                mt->move = false;
        } else if (strcmp(ini_property_name(ini, i, n), "early") == 0) {
            if (strcmp(ini_property_value(ini, i, n), "true") == 0)
                mt->early = true;
            else
                mt->early = false;
        } else {
            ks_log(KS_LOG_ERROR, "Unknown property %s.%s, ignoring\n",
                                    ini_section_name(ini, i),
                                    ini_property_name(ini, i, n));
        }
    }

    if (!mt_found_device_type)
        mt->device_type = "none";

    if (mt_found_name && mt_found_dev && mt_found_type && mt_found_target) {
        (*mt_out) = mt;
        return 0;
    } else {
        ks_log(KS_LOG_ERROR, "%s: mount target decode error\n", __func__);
        free(mt);
        return -1;
    }
}

static int parse_verity_target(int i, struct ks_config_verity_target **vt_out)
{
    bool vt_found_name = false;
    bool vt_found_dev = false;
    bool vt_found_device_type = false;

    (*vt_out) = NULL;

    struct ks_config_verity_target *vt = NULL;
    vt = malloc(sizeof(*vt));
    memset(vt, 0, sizeof(*vt));

    for (int n = 0; n < ini_property_count(ini, i); n++) {
        if (strcmp(ini_property_name(ini, i, n), "name") == 0) {
            vt->name = ini_property_value(ini, i, n);
            vt_found_name = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device") == 0) {
            vt->device = ini_property_value(ini, i, n);
            vt_found_dev = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device_type") == 0) {
            vt->device_type = ini_property_value(ini, i, n);
            vt_found_device_type = true;
        } else if (strcmp(ini_property_name(ini, i, n), "set") == 0) {
            char sys = ini_property_value(ini, i, n)[0];
            if (sys == 'A' || sys == 'a')
                vt->system = KS_SYSTEM_A;
            else if (sys == 'B' || sys == 'b')
                vt->system = KS_SYSTEM_B;
            else
                vt->system = KS_SYSTEM_INVALID;
        } else {
            ks_log(KS_LOG_ERROR, "Unknown property %s.%s, ignoring\n",
                                    ini_section_name(ini, i),
                                    ini_property_name(ini, i, n));
        }
    }

    if (vt_found_name && vt_found_dev && vt_found_device_type) {
        (*vt_out) = vt;
        return 0;
    } else {
        ks_log(KS_LOG_ERROR, "%s: verity target decode error\n", __func__);
        free(vt);
        return -1;
    }
}


static int parse_ks(int i, struct ks_config **conf_out)
{
    struct ks_config *conf = NULL;
    bool ks_found_log_level = false;
    bool ks_found_root_device = false;
    bool ks_found_init_handover = false;

    conf = malloc(sizeof(*conf));
    memset(conf, 0, sizeof(*conf));

    for (int n = 0; n < ini_property_count(ini, i); n++) {
        if (strcmp(ini_property_name(ini, i, n), "loglevel") == 0) {
            conf->log_level = (int) strtoul(ini_property_value(ini, i, n),
                                            NULL, 10);
            ks_found_log_level = true;
        } else if (strcmp(ini_property_name(ini, i, n), "device") == 0) {
            conf->root_device = ini_property_value(ini, i, n);
            ks_found_root_device = true;
        } else if (strcmp(ini_property_name(ini, i, n), "init_handover") == 0) {
            conf->init_handover = ini_property_value(ini, i, n);
            ks_found_init_handover = true;
        } else {
            ks_log(KS_LOG_ERROR, "%s: Unknown property %s.%s, ignoring\n",
                                    __func__,
                                    ini_section_name(ini, i),
                                    ini_property_name(ini, i, n));
        }
    }

    if (!ks_found_log_level)
        conf->log_level = KS_LOG_ERROR;
    if (!ks_found_root_device)
        conf->root_device = "/dev/mmcblk0";
    if (!ks_found_init_handover)
        conf->init_handover = "/init";

    (*conf_out) = conf;

    return 0;
}

int ks_config_init(const char *config_filename)
{
    int rc = 0;
    char *data = NULL;
    ssize_t file_sz_bytes = 0;
    FILE *fp = fopen(config_filename, "r" );

    if (fp == NULL)
    {
        ks_log(KS_LOG_ERROR, "%s: could not open '%s'\n", __func__,
                                                          config_filename);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    file_sz_bytes = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    data = (char*) malloc(file_sz_bytes + 1);

    if (data == NULL)
    {
        ks_log(KS_LOG_ERROR, "%s: malloc failed\n", __func__);
        rc = -1;
        goto err_close_out;
    }

    fread(data, 1, file_sz_bytes, fp);
    data[file_sz_bytes] = '\0';

    ini = ini_load(data, NULL);
    free(data);

    /* Parse config file */
    struct ks_config_mount_target *mt_prev = NULL;
    struct ks_config_verity_target *vt_prev = NULL;
    struct ks_config_keystore *ks_prev = NULL;
    struct ks_config *conf_prev = NULL;

    for (int i = 0; i < ini_section_count(ini); i++)
    {
        if (strcmp(ini_section_name(ini, i), "mount-target") == 0)
        {
            struct ks_config_mount_target *mt = NULL;
            rc = parse_mount_target(i, &mt);

            if (rc != 0)
                continue;

            if (mount_targets == NULL) {
                mount_targets = mt;
                mt_prev = mt;
            } else {
                mt_prev->next = mt;
                mt_prev = mt;
            }
        } else if (strcmp(ini_section_name(ini, i), "keystore") == 0) {
            struct ks_config_keystore *ks = NULL;

            rc = parse_keystore(i, &ks);

            if (rc != 0)
                continue;

            if (keystores == NULL) {
                keystores = ks;
                ks_prev = ks;
            } else {
                ks_prev->next = ks;
                ks_prev = ks;
            }
        } else if (strcmp(ini_section_name(ini, i), "verity-target") == 0) {
            struct ks_config_verity_target *vt = NULL;

            rc = parse_verity_target(i, &vt);

            if (rc != 0)
                continue;

            if (verity_targets == NULL) {
                verity_targets = vt;
                vt_prev = vt;
            } else {
                vt_prev->next = vt;
                vt_prev = vt;
            }
        } else if (strcmp(ini_section_name(ini, i), "ks") == 0) {
            rc = parse_ks(i, &config);

            if (rc != 0)
                continue;
        } else if (strcmp(ini_section_name(ini, i), "") == 0) {
            /* Supress this warning */
        } else {
            ks_log(KS_LOG_ERROR, "%s: Unhandeled config section '%s'\n", __func__,
                                    ini_section_name(ini, i));
        }
    }

err_close_out:
    fclose(fp);
    return rc;
}

struct ks_config_mount_target * ks_config_mount_targets(void)
{
    return mount_targets;
}

struct ks_config_verity_target * ks_config_verity_targets(void)
{
    return verity_targets;
}

struct ks_config_keystore * ks_config_keystore(void)
{
    return keystores;
}

struct ks_config * ks_config(void)
{
    return config;
}

void ks_config_free(void)
{
    /* Free mount target list */
    if (mount_targets != NULL) {
        struct ks_config_mount_target *next = mount_targets;
        struct ks_config_mount_target *tmp = NULL;

        do {
            tmp = next;
            next = next->next;
            free(tmp);
        } while (next != NULL);
    }

    /* Free verity target list */
    if (verity_targets != NULL) {
        struct ks_config_verity_target *next = verity_targets;
        struct ks_config_verity_target *tmp = NULL;

        do {
            tmp = next;
            next = next->next;
            free(tmp);
        } while (next != NULL);
    }

    /* Free keystore list */
    if (keystores != NULL) {
        struct ks_config_keystore *next = keystores;
        struct ks_config_keystore *tmp = NULL;

        do {
            tmp = next;
            next = next->next;
            free(tmp);
        } while(next != NULL);
    }

    free(config);

    ini_destroy(ini);
}
