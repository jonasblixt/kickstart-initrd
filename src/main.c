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
#include <termios.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <dirent.h>

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/reboot.h>

#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/io.h>
#include <bpak/file.h>
#include <bpak/keystore.h>
#include <uuid.h>

#include "kcapi/kcapi.h"
#include "gpt.h"
#include "dm.h"
#include "config.h"
#include "log.h"
#include "utils.h"
#include "keys.h"

static int ks_switchroot(const char *root_device, const char *fs_type)
{
    int rc;

    ks_log(KS_LOG_DEBUG, "mount root begin\n");

    rc = mount("/dev/mapper/87258a48-64f2-42d0-b972-4db4aa86f2a6", "/target",
                     fs_type, MS_RDONLY | MS_NOATIME | MS_NODIRATIME, "");

    if (rc == -1)
    {
      perror("mount:");
      ks_log(KS_LOG_ERROR, "Could not mount /target\n");
      ks_do_panic(5);
    }

    ks_log(KS_LOG_DEBUG, "mount root end\n");

    ks_log(KS_LOG_DEBUG, "mount move begin\n");
    mount("/dev",  "/target/dev", NULL, MS_MOVE, NULL);
    mount("/proc", "/target/proc", NULL, MS_MOVE, NULL);
    mount("/sys",  "/target/sys", NULL, MS_MOVE, NULL);
    mount("/tmp",  "/target/tmp", NULL, MS_MOVE, NULL);
    mount("/data/tee",  "/target/data/tee", NULL, MS_MOVE, NULL);
    mount("/sys/kernel/config",  "/target/sys/kernel/config", NULL, MS_MOVE, NULL);

    ks_log(KS_LOG_DEBUG, "mount move end\n");
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

    pid_t pid = fork();

    if (pid <= 0)
    {
        /* Remove files from initrd */
        unlink("/init");
        ks_config_free();

        if (pid == 0)
            exit(0);
    }

    return 0;
}

#define ACTIVE_SYSTEM_BUF_SZ 16
#define KS_ROOTDEVICE "/dev/mmcblk0p3"

int main(int argc, char **argv)
{
    int rc;
    char active_system[ACTIVE_SYSTEM_BUF_SZ];
    char *root_device_str = NULL;
    struct ks_config_mount_target *mt;
    struct gpt_table *gpt;
    char part_name_buf[64];
    struct bpak_header h;
    int fd;

    ks_log_init(KS_LOG_DEBUG);

    ks_log(KS_LOG_INFO, "Kickstart " PACKAGE_VERSION " starting...\n");
    rc = ks_config_init("/ksinitrd.conf");

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could not load configuration\n");
        ks_do_panic(5);
    }

    ks_log(KS_LOG_DEBUG, "Configuration loaded\n");

    rc = ks_crypto_init();

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could init crypto\n");
        ks_do_panic(5);
    }

    ks_log(KS_LOG_INFO, "Mounting early targets\n");

    /* Process early 'mount-target' items */
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

    rc = ks_keys_init();

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "Could not initialize keystore\n");
        ks_do_panic(5);
    }

    /* Read information about which root system we are going to
     * try to mount. ks-initrd currently only supports the punchboot
     * boot loader */
    if (ks_readfile("/proc/device-tree/chosen/pb,active-system",
                    active_system, ACTIVE_SYSTEM_BUF_SZ) != 0)
    {
        ks_log(KS_LOG_ERROR, "Could not read active-system\n");
        ks_do_panic(5);
    }

    ks_log(KS_LOG_INFO, "Active System: %s\n",active_system);
    ks_log(KS_LOG_DEBUG, "Waiting for %s\n", KS_ROOTDEVICE);

    struct stat statbuf;
    while (stat(KS_ROOTDEVICE, &statbuf) != 0) {}

    /* TODO: Use value from config file */
    rc = gpt_init("/dev/mmcblk0", &gpt);

    if (rc != GPT_OK)
    {
        ks_log(KS_LOG_ERROR, "gpt_init failed!\n");
        ks_do_panic(5);
    }

    /* Process 'keystore' items */
    for (struct ks_config_keystore *ks = ks_config_keystore(); ks; ks = ks->next) {
        if (ks->set != active_system[0])
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


    gpt_part_name(gpt, 2, part_name_buf, sizeof(part_name_buf));
    ks_log(KS_LOG_DEBUG, "Reading %s\n", part_name_buf);

    fd = open(part_name_buf, O_RDONLY);

    if (fd == -1) {
        ks_log(KS_LOG_ERROR, "Error: could not open device\n");
        ks_do_panic(5);
    }

    lseek(fd, -4096, SEEK_END);

    if (read(fd, &h, sizeof(h)) != sizeof(h)) {
        ks_log(KS_LOG_ERROR, "Error: could not read header\n");
        ks_do_panic(5);
    }

    /* load_header(*gpt, uuid<...>, *h) */

    rc = bpak_valid_header(&h);

    if (rc != BPAK_OK)
    {
        ks_log(KS_LOG_ERROR, "Error: invalid bpak header, %s\n",
                            bpak_error_string(rc));
        ks_do_panic(5);
    }
    close(fd);

    ks_log(KS_LOG_DEBUG, "verity begin\n");
    dm_mount(&h);
    ks_log(KS_LOG_DEBUG, "verity end\n");

    ks_switchroot("", "squashfs");

    ks_log(KS_LOG_INFO, "Starting real init...\n");

    ks_keys_free();
    ks_crypto_free();
    ks_config_free();

    execv("/sbin/init", argv);

    while(1)
    {
        char c = getchar();

        if (c == 'r')
            reboot(0x1234567);
    }
}
