/*
 * ks_mount_verity(<UUID>, "/newroot", keystore*)
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
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <linux/netlink.h>

#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/io.h>
#include <bpak/file.h>
#include <bpak/keystore.h>

#include "kcapi/kcapi.h"
#include "gpt.h"
#include "dm.h"

#define NL_MAX_PAYLOAD 8192

#define ks_log(...) \
    do { FILE *fp = fopen("/dev/kmsg","w"); \
    fprintf(fp, "ks: " __VA_ARGS__); \
    fclose(fp); } while(0)

#define ks_log2(...) \
    do { \
    printf( "ks: " __VA_ARGS__); \
    } while(0)

static void ks_panic(const char *msg)
{
    printf ("Panic: %s, rebooting in 1s...\n", msg);
    ks_log ("Panic: %s, rebooting in 1s...\n", msg);
    sleep(5);
    reboot(0x1234567);
    while (1);
}

static int ks_readfile(const char *fn, char *buf, size_t sz)
{
    FILE *fp = fopen(fn,"r");

    if (fp == NULL)
        return -1;
    memset(buf, 0, sz);
    int result = fread (buf,1,sz,fp);

    fclose(fp);

    return (result > 0)?0:-1;
}


static int ks_get_root_device(char **root_device_str, char active_system)
{
    int rc;
#ifdef _NOPE
    rc = blkid_get_cache(&bc, "/dev/null");

    if (rc != 0)
        return -1;


    if (active_system == 'A')
    {
        *root_device_str =
            blkid_get_devname(bc,"PARTUUID","c284387a-3377-4c0f-b5db-1bcbcff1ba1a");
    }
    else if (active_system == 'B')
    {
        *root_device_str =
            blkid_get_devname(bc,"PARTUUID","ac6a1b62-7bd0-460b-9e6a-9a7831ccbfbb");
    }
    else
    {
        ks_log ("No active system\n");
        return -1;
    }
#endif
    return 0;
}

static void ks_early_init(void)
{
    int rc;

    rc = mount("none", "/proc", "proc", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount /proc\n");

    rc = mount("none", "/sys", "sysfs", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount /sys\n");

    rc = mount("none", "/dev", "devtmpfs", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount /dev\n");

    rc = mount("none", "/tmp", "tmpfs", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount /tmp\n");

    rc = mount("none", "/data/tee", "tmpfs", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount /data/tee\n");

    rc = mount("none", "/sys/kernel/config", "configfs", 0, "");

    if (rc == -1)
        ks_panic ("Could not mount configfs\n");
}

static int ks_verity_init(char *root_device_str, uint8_t *root_hash,
                          uint64_t hash_offset)
{
#ifdef _NOPE
    struct crypt_device *cd = NULL;
    struct crypt_params_verity params = {};
    uint32_t activate_flags = CRYPT_ACTIVATE_READONLY;
    int rc;

    if (crypt_init_data_device(&cd, root_device_str,root_device_str) != 0)
        return -1;

    params.flags = 0;
    params.hash_area_offset = hash_offset;
    params.fec_area_offset = 0;
    params.fec_device = NULL;
    params.fec_roots = 0;

    if (crypt_load(cd, CRYPT_VERITY, &params) != 0)
        return -1;

    ssize_t hash_size = crypt_get_volume_key_size(cd);

    rc = crypt_activate_by_volume_key(cd, "vroot",
                     (const char *) root_hash,
                     hash_size,
                     activate_flags);

    if (rc != 0)
        return -1;
#endif
    return 0;
}

static int ks_switchroot(const char *root_device, const char *fs_type)
{
    int rc;

    rc = mount("/dev/mapper/87258a48-64f2-42d0-b972-4db4aa86f2a6", "/newroot", fs_type, MS_RDONLY, "");

    if (rc == -1)
    {
      perror("mount:");
      ks_panic ("Could not mount /newroot");
    }
    mount("/dev",  "/newroot/dev", NULL, MS_MOVE, NULL);
    mount("/proc", "/newroot/proc", NULL, MS_MOVE, NULL);
    mount("/sys",  "/newroot/sys", NULL, MS_MOVE, NULL);
    mount("/tmp",  "/newroot/tmp", NULL, MS_MOVE, NULL);
    mount("/data/tee",  "/newroot/data/tee", NULL, MS_MOVE, NULL);
    mount("/sys/kernel/config",  "/newroot/sys/kernel/config", NULL, MS_MOVE, NULL);
    rc = chdir("/newroot");

    if (rc != 0)
    {
        ks_log("Could not change to /newroot");
        return -1;
    }

    if (mount("/newroot", "/", NULL, MS_MOVE, NULL) < 0)
    {
        ks_log ("Could not remount newroot\n");
        perror("Mount new root");
        return -1;
    }

    rc = chroot(".");

    if (rc != 0)
    {
        ks_log("Could not chroot\n");
        return -1;
    }

    pid_t pid = fork();

    if (pid <= 0)
    {
        /* Remove files from initrd */
        unlink("/init");

        if (pid == 0)
            exit(0);
    }

    return 0;
}

#define KS_KEY_BUFFER_SZ 256
#define KICKSTART_BLOCK_SIG_MAX_SIZE 1024

static int ks_init_device(const char *device_fn,
                          uint8_t  *ksb,
                          uint64_t *hash_tree_offset,
                          uint8_t *root_hash)
{
#ifdef _NOPE
    //struct squashfs_super_block sb;
    uint8_t signature[KICKSTART_BLOCK_SIG_MAX_SIZE];
    uint8_t key_buffer_asn1[KS_KEY_BUFFER_SZ];
    uint16_t sign_length = 0;
    char key_fn[16];
    uint64_t offset;
    uint8_t key_buf[160];
    uint8_t calc_hash[64];
    uint8_t hash_length = 0;
    /*
    br_sha256_context sha256_ctx;
    br_sha384_context sha384_ctx;
    br_sha512_context sha512_ctx;*/
    FILE *fp = fopen (device_fn, "r");

    if (fp == NULL)
    {
        ks_log ("Could not open device '%s'\n",device_fn);
        return KS_ERR;
    }
/*
    if (!fread(&sb, sizeof(struct squashfs_super_block), 1, fp))
    {
        ks_log ("Could not read squashfs superblock\n");
        return KS_ERR;
    }

    if (sb.s_magic != 0x73717368)
    {
        ks_log("Incorrect squashfs magic\n");
        return KS_ERR;
    }

    offset = (sb.bytes_used + (4096 - (sb.bytes_used % 4096)));
    *hash_tree_offset = offset+512;

    if (fseek (fp, offset, SEEK_SET) != 0)
    {
        ks_log ("Seek failed\n");
        return KS_ERR;
    }
*/

/*
    if (!fread(ksb, sizeof(struct kickstart_block), 1, fp))
    {
        ks_log ("Could not read kickstart block\n");
        return KS_ERR;
    }

    if (ksb->magic != KICKSTART_BLOCK_MAGIC)
    {
        ks_log("Incorrect kickstart magic\n");
        return KS_ERR;
    }

    fclose(fp);

    ks_log ("ksb offset: %lu bytes\n",offset);
    ks_log ("ksb magic: %x\n", ksb->magic);
    ks_log ("ksb version: %u\n",ksb->version);
    ks_log ("key_index = %u\n",ksb->key_index);

    memcpy(signature,ksb->signature, KICKSTART_BLOCK_SIG_MAX_SIZE);
    sign_length = ksb->sign_length;

    memset(ksb->signature,0, KICKSTART_BLOCK_SIG_MAX_SIZE);
    ksb->sign_length = 0;

    snprintf (key_fn,16,"/%u.der",ksb->key_index);

    br_ec_public_key pk;
    fp = fopen(key_fn, "r");

    if (fp == NULL)
    {
        ks_panic("Could not load key");
    }

    //size_t asn1_key_read_sz = fread(key_buf, 1, KS_KEY_BUFFER_SZ, fp);
    fclose(fp);

    const uint8_t k[] =
    {
        0x04, 0x39, 0x3D, 0xA9, 0x66, 0xF2, 0x08, 0x89, 0x6A, 0xC3, 0xAE, 0x37, 0x88, 0xF4, 0x09, 0xC8,
        0xB8, 0x1D, 0xCB, 0xD0, 0x6C, 0xA1, 0xCF, 0xB6, 0xAF, 0xE0, 0x3C, 0x65, 0x95, 0x19, 0x13, 0xAB,
        0xA7, 0x6C, 0x91, 0x0F, 0x55, 0xB6, 0xD4, 0xBC, 0x29, 0x07, 0xC8, 0x80, 0xD7, 0x91, 0x63, 0x15,
        0x06, 0xD3, 0x36, 0x6A, 0xDE, 0x2D, 0x30, 0x3D, 0xF1, 0x52, 0x96, 0xE3, 0x57, 0x35, 0x3F, 0xCF,
        0x0C, 0x25, 0x15, 0x56, 0x0F, 0xC6, 0x46, 0x5B, 0xBE, 0x88, 0x87, 0x32, 0x98, 0xDF, 0xE3, 0x47,
        0xFC, 0xB1, 0x6F, 0xBA, 0x06, 0x10, 0x4D, 0x2A, 0x08, 0xFC, 0xE8, 0xA3, 0x5E, 0xF2, 0xF2, 0x02,
        0xD9,
    };

    pk.q = k;
    pk.qlen = 97;

    ks_log("pk.qlen = %lu\n",pk.qlen);


    switch (ksb->sign_kind)
    {
        case KS_SIGN_NIST256p:
            br_sha256_init(&sha256_ctx);
            br_sha256_update(&sha256_ctx, ksb, sizeof(struct kickstart_block));
            br_sha256_out(&sha256_ctx, calc_hash);
            hash_length = 32;
            pk.curve = BR_EC_secp256r1;
        break;
        case KS_SIGN_NIST384p:
            br_sha384_init(&sha384_ctx);
            br_sha384_update(&sha384_ctx, ksb, sizeof(struct kickstart_block));
            br_sha384_out(&sha384_ctx, calc_hash);
            hash_length = 48;
            pk.curve = BR_EC_secp384r1;
        break;
        case KS_SIGN_NIST521p:
            br_sha512_init(&sha512_ctx);
            br_sha512_update(&sha512_ctx, ksb, sizeof(struct kickstart_block));
            br_sha512_out(&sha512_ctx, calc_hash);
            hash_length = 64;
            pk.curve = BR_EC_secp521r1;
        break;
        default:
        break;
    }

    struct timeval t,t2;

    gettimeofday(&t, NULL);
    if (br_ecdsa_i31_vrfy_asn1(&br_ec_prime_i31,
                                calc_hash,
                                hash_length,
                                &pk,
                                signature,
                                sign_length) != 1)
    {
        ks_log("Signature failed\n");
        return KS_ERR;
    }

    memcpy(root_hash, ksb->hash, 32);

    gettimeofday(&t2,NULL);

    ks_log ("Verification took %f us\n", (t2.tv_sec*1E6+t2.tv_usec)-
                                         (t.tv_sec*1E6+t.tv_usec));
    return KS_OK;
*/
#endif
}

/**
 *
 * /kstab
 *      <uuid>:<mount_point>
 *
 *
 */

#define ACTIVE_SYSTEM_BUF_SZ 16
#define KS_ROOTDEVICE "/dev/mmcblk0p3"

int main(int argc, char **argv)
{
    int rc;
    char active_system[ACTIVE_SYSTEM_BUF_SZ];
    char *root_device_str = NULL;
    struct timeval tv;
    unsigned long time_us;
    unsigned long time_us_start;

    gettimeofday(&tv, NULL);
    time_us_start = 1E6 * tv.tv_sec + tv.tv_usec;

    /* Initialize really early stuff, like mounting /proc, /sys etc */
    ks_early_init();

    ks_log("Kickstart " PACKAGE_VERSION " starting...\n");

    /* Read information about which root system we are going to
     * try to mount. ks-initrd currently only supports the punchboot
     * boot loader */
    if (ks_readfile("/proc/device-tree/chosen/pb,active-system",
                    active_system, ACTIVE_SYSTEM_BUF_SZ) != 0)
    {
        ks_panic("Could not read active-system\n");
    }

    ks_log("Active System: %s\n",active_system);
    ks_log("Waiting for %s\n", KS_ROOTDEVICE);

    gettimeofday(&tv, NULL);
    time_us = (1E6 * tv.tv_sec + tv.tv_usec) - time_us_start;
    printf("dev ts1: %lu us\n", time_us);
    struct stat statbuf;
    while (stat(KS_ROOTDEVICE, &statbuf) != 0) {}

    gettimeofday(&tv, NULL);
    time_us = (1E6 * tv.tv_sec + tv.tv_usec) - time_us_start;
    printf("dev ts2: %lu us\n", time_us);
    extern const struct bpak_keystore keystore_ks_internal;

    printf("Internal keystore: %8.8x\n", keystore_ks_internal.id);

    struct gpt_table *gpt;
    char part_name_buf[64];

    rc = gpt_init("/dev/mmcblk0", &gpt);

    if (rc != GPT_OK)
        printf("Error: gpt_init failed!\n");

    for (int p = 0; p < gpt->hdr.no_of_parts; p++)
    {
        if (gpt->part[p].first_lba == 0)
            break;

        int i = 0;
        printf("Name: ");
        while (i < GPT_PART_NAME_MAX_SIZE*2)
        {
            printf("%c", gpt->part[p].name[i]);
            i += 2;
        }

        gpt_part_name(gpt, p, part_name_buf, sizeof(part_name_buf));

        printf(", 0x%llx -> 0x%llx %s\n", gpt->part[p].first_lba,
                                          gpt->part[p].last_lba,
                                          part_name_buf);
    }

    gpt_part_name(gpt, 2, part_name_buf, sizeof(part_name_buf));
    printf("Reading %s\n", part_name_buf);


    struct bpak_header h;

    int fd = open(part_name_buf, O_RDONLY);

    if (fd == -1)
        printf("Error: could not open device\n");

    printf("  --> %llx\n", lseek(fd, -4096, SEEK_END));

    if (read(fd, &h, sizeof(h)) != sizeof(h))
        printf("Error: could not read header\n");

    /* load_header(*gpt, uuid<...>, *h) */

    rc = bpak_valid_header(&h);

    if (rc != BPAK_OK)
    {
        printf("Error: invalid bpak header, %s\n", bpak_error_string(rc));
        while(1)
            sleep(1);
    }
    close(fd);

    char str_buf[65];
    bpak_foreach_meta((&h), m)
    {
        if (!m->id)
            break;

        bpak_meta_to_string(&h, m, str_buf, sizeof(str_buf));
        printf("Found meta id: %8.8x '%s'\n", m->id, str_buf);

    }

    printf("verity mount:\n");
    dm_mount(&h);


    DIR *d;
    struct dirent *dir;
    d = opendir("/dev/mapper");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            printf("%s\n", dir->d_name);
        }
        closedir(d);
    }
    gettimeofday(&tv, NULL);
    time_us = (1E6 * tv.tv_sec + tv.tv_usec) - time_us_start;
    printf("final ts: %lu us\n", time_us);
    printf("id('bpak-package') = %8.8x\n", bpak_id("bpak-package"));
    ks_switchroot("", "squashfs");
    printf("Main loop...\n");

    d = opendir("/");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            printf("%s\n", dir->d_name);
        }
        closedir(d);
    }
    ks_log("Starting real init...\n");

    const char *test_msg = "Hello World!";
    char test_hash[32];

    struct kcapi_handle *kh;
    kcapi_md_init(&kh, "sha256", 0);

    kcapi_md_update(kh, test_msg, strlen(test_msg));
    kcapi_md_final(kh, test_hash, sizeof(test_hash));

    char test_hash_str[65];
    bpak_bin2hex(test_hash, 32, test_hash_str, 65);
    printf("Hash: %s\n", test_hash_str);

    execv("/sbin/init", argv);
    while(1)
    {
        char c = getchar();

        if (c == 'r')
            reboot(0x1234567);
    }
}
