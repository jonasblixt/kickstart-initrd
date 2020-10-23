#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/kdev_t.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>

#include "log.h"

#define DM_IOCTL 0xfd
#define DM_MAX_TYPE_NAME 16
#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

struct dm_ioctl
{
    uint32_t version[3];
    uint32_t data_size;
    uint32_t data_start;
    uint32_t target_count;
    int32_t open_count;
    uint32_t flags;
    uint32_t event_nr;
    uint32_t padding;
    uint64_t dev;
    char name[DM_NAME_LEN];
    char uuid[DM_UUID_LEN];
    char data[7];
};

struct dm_target_spec
{
    uint64_t sector_start;
    uint64_t length;
    int32_t status;
    uint32_t next;
    char target_type[DM_MAX_TYPE_NAME];
};

enum
{
    DM_VERSION_CMD = 0,
    DM_REMOVE_ALL_CMD,
    DM_LIST_DEVICES_CMD,
    DM_DEV_CREATE_CMD,
    DM_DEV_REMOVE_CMD,
    DM_DEV_RENAME_CMD,
    DM_DEV_SUSPEND_CMD,
    DM_DEV_STATUS_CMD,
    DM_DEV_WAIT_CMD,
    DM_TABLE_LOAD_CMD,
    DM_TABLE_CLEAR_CMD,
    DM_TABLE_DEPS_CMD,
    DM_TABLE_STATUS_CMD,
};

#define DM_DEV_CREATE    _IOWR(DM_IOCTL, DM_DEV_CREATE_CMD, struct dm_ioctl)
#define DM_TABLE_LOAD    _IOWR(DM_IOCTL, DM_TABLE_LOAD_CMD, struct dm_ioctl)
#define DM_DEV_SUSPEND   _IOWR(DM_IOCTL, DM_DEV_SUSPEND_CMD, struct dm_ioctl)

#define DM_READONLY_FLAG    (1 << 0)

int dm_mount(struct bpak_header *h)
{
    int fd = open("/dev/mapper/control", O_RDWR);
    int rc;
    char *buf = malloc(1024*16);
    struct dm_ioctl *dmi = (struct dm_ioctl *) buf;
    struct dm_target_spec *spec  = (struct dm_target_spec *) (buf + sizeof(struct dm_ioctl));
    char *tbl = (buf + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec));
    dev_t dev;
    uint8_t *verity_salt = NULL;
    uint8_t *verity_root_hash = NULL;
    char verity_salt_str[65];
    char verity_root_hash_str[65];

    memset(buf, 0, 1024*16);

    if (fd == -1)
    {
        ks_log(KS_LOG_ERROR, "Could not open /dev/mapper/control\n");
        return -1;
    }

    rc = bpak_get_meta(h, 0xe68fc9be, (void **) &verity_root_hash);

    if (rc != BPAK_OK)
    {
        ks_log(KS_LOG_ERROR, "Could not read root hash meta");
        return -1;
    }

    rc = bpak_get_meta(h, 0x7c9b2f93, (void **) &verity_salt);

    if (rc != BPAK_OK)
    {
        ks_log(KS_LOG_ERROR, "Could not read salt meta");
        return -1;
    }

    bpak_bin2hex(verity_root_hash, 32, verity_root_hash_str, sizeof(verity_root_hash_str));
    bpak_bin2hex(verity_salt, 32, verity_salt_str, sizeof(verity_salt_str));

    dmi->version[0] = 4;
    dmi->version[1] = 2;
    dmi->version[2] = 0;

    snprintf(dmi->name, sizeof(dmi->name), "87258a48-64f2-42d0-b972-4db4aa86f2a6");
    snprintf(dmi->uuid, sizeof(dmi->uuid), "87258a48-64f2-42d0-b972-4db4aa86f2a6");

    dmi->data_size = 1024*16;
    dmi->data_start = sizeof(struct dm_ioctl);

    rc = ioctl(fd, DM_DEV_CREATE, dmi);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "DM_DEV_CREATE ioctl failed %i\n", rc);
        return rc;
    }

    rc = mknod("/dev/mapper/87258a48-64f2-42d0-b972-4db4aa86f2a6", S_IFBLK, dmi->dev);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "mknod failed %i\n", rc);
        return rc;
    }

    dev = dmi->dev;

    /* Load table */

    memset(buf, 0, 1024*16);

    dmi->version[0] = 4;
    dmi->version[1] = 36;
    dmi->version[2] = 0;

    dmi->target_count = 1;
    dmi->flags = DM_READONLY_FLAG;

    snprintf(dmi->uuid, sizeof(dmi->uuid), "87258a48-64f2-42d0-b972-4db4aa86f2a6");

    struct bpak_part_header *p = NULL;

    rc = bpak_get_part(h, bpak_id("fs"), &p);

    if (rc != BPAK_OK) {
        ks_log(KS_LOG_ERROR, "Could not get fs part!\n");
        return rc;
    }

    size_t part_size_4k_blocks = bpak_part_size(p) / 4096;

    ks_log(KS_LOG_DEBUG, "Fs size %zu bytes, %zu 512-byte blocks, %zu 4k blocks\n",
                bpak_part_size(p), bpak_part_size(p) / 512, bpak_part_size(p) / 4096);

    spec->sector_start = 0;
    spec->length = bpak_part_size(p) / 512;
    spec->next = 0;
    spec->status = 0;
    sprintf(spec->target_type, "verity");

    snprintf(tbl, 1024,
        "1 /dev/mmcblk0p3 /dev/mmcblk0p3 4096 4096 %zu %zu sha256 %s %s",
                    part_size_4k_blocks, part_size_4k_blocks,
                    verity_root_hash_str, verity_salt_str);
    dmi->data_size = 1024*16;
    dmi->data_start = sizeof(struct dm_ioctl);

    ks_log(KS_LOG_DEBUG, "Table: %s\n", tbl);

    rc = ioctl(fd, DM_TABLE_LOAD, buf);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "DM_TABLE_LOAD ioctl failed %i\n", rc);
        return rc;
    }

    /* Resume device */

    memset(buf, 0, 1024*16);

    dmi->version[0] = 4;
    dmi->version[1] = 36;
    dmi->version[2] = 0;

    dmi->target_count = 1;

    snprintf(dmi->uuid, sizeof(dmi->uuid), "87258a48-64f2-42d0-b972-4db4aa86f2a6");

    dmi->data_size = 1024*16;
    dmi->data_start = sizeof(struct dm_ioctl);


    rc = ioctl(fd, DM_DEV_SUSPEND, buf);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "DM_DEV_SUSPEND ioctl failed %i\n", rc);
        return rc;
    }

    close(fd);
    free(buf);

    return rc;
}
