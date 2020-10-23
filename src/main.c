/**
 * Kickstart
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>

#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/io.h>
#include <bpak/file.h>
#include <bpak/keystore.h>
#include <uuid.h>

#include "kickstart.h"
#include "gpt.h"
#include "verity.h"
#include "config.h"
#include "log.h"
#include "utils.h"
#include "crypto.h"
#include "keys.h"

int main(int argc, char **argv)
{
    int rc;
    struct ks_config_mount_target *mt;
    struct ks_config_verity_target *vt;
    struct ks_config *config;
    struct gpt_table *gpt;
    char part_name_buf[64];
    struct bpak_header h;
    int fd;

    ks_log_init(KS_LOG_DEBUG);
    ks_log(0, "Kickstart " PACKAGE_VERSION " starting...\n");

    /* Load and parse configuration */
    rc = ks_config_init("/ksinitrd.conf");

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could not load configuration\n");
        ks_do_panic(5);
    }

    config = ks_config();
    ks_log_set_loglevel(config->log_level);

    ks_log(KS_LOG_DEBUG, "Configuration loaded\n");

    /* Initialize crypto */
    rc = ks_crypto_init();

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could init crypto\n");
        ks_do_panic(5);
    }

    /* Process early 'mount-target' items */
    ks_log(KS_LOG_INFO, "Mounting early targets\n");

    for (mt = ks_config_mount_targets(); mt; mt = mt->next) {
        if (!mt->early)
            continue;

        ks_log(KS_LOG_DEBUG, "Mounting '%s' --> '%s'\n", mt->name,
                                                         mt->mount_target);

        rc = mount(mt->device, mt->mount_target, mt->fs_type, 0, "");

        if (rc == -1) {
            ks_log(KS_LOG_ERROR, "Could not mount '%s'\n", mt->name);
            ks_do_panic(5);
        }
    }

    /* Initialize the internal keystore */
    rc = ks_keys_init();

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could not initialize keystore\n");
        ks_do_panic(5);
    }

    /* Display information about which system is active */
    if (ks_active_system() == KS_SYSTEM_A)
        ks_log(KS_LOG_INFO, "Active System: A\n");
    else if (ks_active_system() == KS_SYSTEM_B)
        ks_log(KS_LOG_INFO, "Active System: B\n");
    else
        ks_log(KS_LOG_INFO, "Active System: Unknown\n");

    /* Load GPT partition table */
    rc = gpt_init(config->root_device, &gpt);

    if (rc != GPT_OK)
    {
        ks_log(KS_LOG_ERROR, "gpt_init failed!\n");
        ks_do_panic(5);
    }

    /* Process 'keystore' items */
    for (struct ks_config_keystore *ks = ks_config_keystore(); ks; ks = ks->next) {
        if (ks->system != ks_active_system())
            continue;

        if (strcmp(ks->device_type, "gpt") == 0) {
            uuid_t uu;
            uuid_parse(ks->device, uu);
            rc = gpt_uuid_to_device_name(gpt, uu, part_name_buf,
                                                    sizeof(part_name_buf));

            if (rc != 0) {
                ks_log(KS_LOG_ERROR, "Could not find partition '%s'\n",
                                        ks->device);
                continue;
            }

            rc = ks_keys_add_from_device(part_name_buf);
        } else {
            rc = ks_keys_add_from_device(ks->device);
        }

        if (rc != 0) {
            ks_log(KS_LOG_ERROR, "Failed to add keystore\n");
        }
    }

    /* Process 'verity-target' items */
    ks_log(KS_LOG_INFO, "Setting up dm-verity targets\n");
    for (vt = ks_config_verity_targets(); vt; vt = vt->next) {
        if (vt->system != ks_active_system())
            continue;

        ks_log(KS_LOG_DEBUG, "Setting up '%s'\n", vt->name);

        if (strcmp(vt->device_type, "gpt") == 0) {
            uuid_t uu;
            uuid_parse(vt->device, uu);
            rc = gpt_uuid_to_device_name(gpt, uu, part_name_buf,
                                                    sizeof(part_name_buf));

            if (rc != 0) {
                ks_log(KS_LOG_ERROR, "Could not find partition '%s'\n",
                                        vt->device);
                continue;
            }

            rc = ks_verity_setup(part_name_buf);
        } else {
            rc = ks_verity_setup(vt->device);
        }

        if (rc != 0) {
            ks_log(KS_LOG_ERROR, "Verity setup failed for '%s'\n", vt->name);
            ks_do_panic(5);
        }
    }

    /* Process 'mount-target' items */
    ks_log(KS_LOG_INFO, "Mounting early targets\n");

    for (mt = ks_config_mount_targets(); mt; mt = mt->next) {
        /* Skip early mounts */
        if (mt->early)
            continue;

        ks_log(KS_LOG_DEBUG, "Mounting '%s' [%s]  --> '%s'\n",
                                mt->name,
                                mt->device,
                                mt->mount_target);

        rc = mount(mt->device, mt->mount_target, mt->fs_type, MS_RDONLY,
                    mt->options);

        if (rc == -1) {
            ks_log(KS_LOG_ERROR, "Could not mount '%s'\n", mt->name);
            ks_do_panic(5);
        }
    }

    /* Process 'mount-target' that should be moved into the target */
    ks_log(KS_LOG_INFO, "Mounting early targets\n");
    char mount_target_str[256];

    for (mt = ks_config_mount_targets(); mt; mt = mt->next) {
        if (!mt->move)
            continue;

        ks_log(KS_LOG_DEBUG, "Moving '%s'\n", mt->name);

        snprintf(mount_target_str, sizeof(mount_target_str), "/target%s",
                    mt->mount_target);

        rc = mount(mt->mount_target, mount_target_str, NULL, MS_MOVE, NULL);

        if (rc == -1) {
            ks_log(KS_LOG_ERROR, "Could not move '%s'\n", mt->name);
            ks_do_panic(5);
        }
    }


    char *init_program = strdup(config->init_handover);

    ks_keys_free();
    ks_crypto_free();
    ks_config_free();

    rc = chdir("/target");

    if (rc != 0)
    {
        ks_log(KS_LOG_ERROR, "Could not change to /target\n");
        return -1;
    }

    if (mount("/target", "/", NULL, MS_MOVE, NULL) < 0)
    {
        ks_log(KS_LOG_ERROR, "Could not remount target\n");
        perror("Mount new root");
        return -1;
    }

    rc = chroot(".");

    if (rc != 0)
    {
        ks_log(KS_LOG_ERROR, "Could not chroot\n");
        return -1;
    }

    ks_log(0, "Handover to target init: %s\n", init_program);

    pid_t pid = fork();

    if (pid <= 0)
    {
        /* Remove files from initrd */
        unlink("/init");

        if (pid == 0)
            exit(0);
    }

    execv(init_program, argv);
    return -1;
}
