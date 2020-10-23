/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <byteswap.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <bpak/bpak.h>
#include <bpak/utils.h>

#include "keys.h"
#include "log.h"
#include "utils.h"
#include "crypto.h"
#include "bpak_helpers.h"

static uint32_t available_key_ids[KS_MAX_KEYS];
static struct ks_keystore *keystore;
extern const struct bpak_keystore keystore_ks_internal;

int ks_keys_init(void)
{
    int rc = 0;
    int fd;

    keystore = malloc(sizeof(*keystore));

    if (keystore == NULL)
        return -1;

    memset(keystore, 0, sizeof(*keystore));

    /* Read available keys from bootloader */

    fd = open("/proc/device-tree/chosen/pb,slc-available-keys", O_RDONLY);

    if (fd == -1) {
        ks_log(KS_LOG_ERROR, "%s: Could not open pb,slc-available-keys\n", __func__);
        rc = -1;
        goto err_free_out;
    }

    ssize_t read_bytes = read(fd, available_key_ids,
                                sizeof(uint32_t) * KS_MAX_KEYS);

    ks_log(KS_LOG_DEBUG, "%s: Read %zu bytes\n", __func__, read_bytes);
    close(fd);

    /* Fix endianess */
    for (int i = 0; i < KS_MAX_KEYS; i++) {
        if (available_key_ids[i] == 0)
            break;

        uint32_t tmp = bswap_32(available_key_ids[i]);

        available_key_ids[i] = tmp;

        ks_log(KS_LOG_DEBUG, "%s: Available key: 0x%08x\n", __func__, tmp);
    }

    ks_log(KS_LOG_DEBUG, "%s: Internal keystore: %8.8x\n",
                        __func__, keystore_ks_internal.id);

    /* Copy the bpak keystore into our own structure*/
    keystore->id = keystore_ks_internal.id;
    struct ks_key *key = NULL;

    for (int i = 0; i < keystore_ks_internal.no_of_keys; i++) {
        struct bpak_key *bpak_key = keystore_ks_internal.keys[i];

        if (ks_keys_ok(bpak_key->id) != 0) {
            ks_log(KS_LOG_DEBUG, "%s: Key 0x%08x is not accepted, discarding\n",
                                __func__, bpak_key->id);
            continue;
        }

        ks_log(KS_LOG_DEBUG, "%s: Adding key 0x%08x\n", __func__, bpak_key->id);

        if (keystore->keys == NULL) {
            keystore->keys = malloc(sizeof(struct ks_key));
            key = keystore->keys;
        } else {
            key->next = malloc(sizeof(struct ks_key));
            key = key->next;
        }

        memset(key, 0, sizeof(*key));

        key->id = bpak_key->id;
        key->size = bpak_key->size;

        switch (bpak_key->kind) {
            case BPAK_KEY_PUB_PRIME256v1:
                key->kind = KS_KEY_PUB_PRIME256v1;
            break;
            case BPAK_KEY_PUB_SECP384r1:
                key->kind = KS_KEY_PUB_SECP384r1;
            break;
            case BPAK_KEY_PUB_SECP521r1:
                key->kind = KS_KEY_PUB_SECP521r1;
            break;
            case BPAK_KEY_PUB_RSA4096:
                key->kind = KS_KEY_PUB_RSA4096;
            break;
            default:
                ks_log(KS_LOG_ERROR, "unknown keytype %i\n", bpak_key->kind);
                rc = -1;
                goto err_free_out;
        };

        key->data = malloc(bpak_key->size);
        memset(key->data, 0, bpak_key->size);
        memcpy(key->data, bpak_key->data, bpak_key->size);
    }

    return rc;

err_free_out:
    ks_keys_free();
    return rc;
}

void ks_keys_free(void)
{
    ks_log(KS_LOG_DEBUG, "%s\n", __func__);
    /* Free keystore list */

    struct ks_keystore *ks = keystore;
    struct ks_keystore *ks_tmp = NULL;
    struct ks_key *key = NULL;
    struct ks_key *key_tmp = NULL;;

    do {
        ks_tmp = ks;
        ks = ks->next;
        key = ks_tmp->keys;

        while (key) {
            key_tmp = key;
            key = key->next;
            free(key_tmp->data);
            free(key_tmp);
        }

        free(ks_tmp);

    } while(ks);

    ks_log(KS_LOG_DEBUG, "%s done\n", __func__);
}

int ks_keys_ok(uint32_t key_id)
{
    for (int i = 0; i < KS_MAX_KEYS; i++) {
        if (available_key_ids[i] == 0)
            break;
        if (available_key_ids[i] == key_id)
            return 0;
    }

    return -1;
}

int ks_keys_get(uint32_t keystore_id, uint32_t key_id, struct ks_key **key_out)
{
    int rc = 0;

    (*key_out) = NULL;

    rc = ks_keys_ok(key_id);

    if (rc != 0)
        return rc;

    /* Locate keystore */
    struct ks_keystore *ks = NULL;
    bool found_keystore = false;

    for (ks = keystore; ks; ks = ks->next) {
        if (ks->id == keystore_id) {
            found_keystore = true;
            break;
        }
    }

    if (!found_keystore) {
        ks_log(KS_LOG_ERROR, "%s: Invalid keystore: %08x\n", __func__, keystore_id);
        return -1;
    }

    /* Locate key */
    struct ks_key *key = NULL;
    bool found_key = false;

    for (key = ks->keys; key; key = key->next) {
        if (key->id == key_id) {
            found_key = true;
            break;
        }
    }

    if (!found_key) {
        ks_log(KS_LOG_ERROR, "%s: Could not find key 0x%08x in keystore 0x%08x\n",
                                __func__, key_id, keystore_id);
        return -1;
    }

    (*key_out) = key;

    return rc;
}

int ks_keys_add_from_device(const char *device_filename)
{
    int rc;
    struct bpak_header h;
    struct ks_keystore *ks;
    struct ks_key *key;

    ks_log(KS_LOG_DEBUG, "%s: Open '%s'\n", __func__, device_filename);

    int fd = open(device_filename, O_RDONLY);

    if (fd == -1) {
        ks_log(KS_LOG_ERROR, "%s: Could not open device '%s'\n", __func__,
                             device_filename);
        return -1;
    }

    /* Verify and load header */

    rc = bpak_helper_load_and_verify_header(fd, &h);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Signature verification failed\n", __func__);
        goto err_out_close;
    }

    ks_log(KS_LOG_DEBUG, "%s: Signature OK\n", __func__);

    /* Verify payload hash */

    rc = bpak_helper_verify_payload(fd, &h);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Payload verification failed\n", __func__);
        goto err_out_close;
    }

    ks_log(KS_LOG_DEBUG, "%s: Payload OK\n", __func__);

    uint32_t *keystore_id;

    rc = bpak_get_meta(&h, bpak_id("bpak-keystore-id"), (void **) &keystore_id);

    if (rc != BPAK_OK) {
        ks_log(KS_LOG_ERROR, "%s: Could not read 'bpak-keystore-id' property\n",
                             __func__);
        goto err_out_close;
    }

    ks_log(KS_LOG_INFO, "%s: Adding keystore 0x%08x\n", __func__, *keystore_id);

    for (ks = keystore; ks; ks = ks->next) {
        if (ks->next == NULL) {
            ks->next = malloc(sizeof(*ks->next));

            if (ks->next == NULL) {
                ks_log(KS_LOG_ERROR, "%s: malloc failed\n", __func__);
                ks_do_panic(5);
            }

            memset(ks->next, 0, sizeof(*ks->next));
            ks = ks->next;
            break;
        }
    }

    ks->id = (*keystore_id);
    struct ks_key *key_next = NULL;

    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    bpak_foreach_part(&h, part) {
        if (part->id == 0)
            break;

        if (ks_keys_ok(part->id) != 0) {
            ks_log(KS_LOG_DEBUG, "Key 0x%08x is not accepted, discarding\n",
                                part->id);
            continue;
        }

        ks_log(KS_LOG_DEBUG, "%s: Adding key 0x%08x\n", __func__, part->id);

        lseek(fd, bpak_part_offset(&h, part) - 4096, SEEK_SET);

        uint64_t key_size = part->size;

        key = malloc(sizeof(*key));
        if (key == NULL) {
            ks_log(KS_LOG_ERROR, "%s: malloc failed\n", __func__);
            ks_do_panic(5);
        }
        memset(key, 0, sizeof(*key));

        key->data = malloc(key_size+1);
        key->size = key_size;
        key->id = part->id;

        if (key->data == NULL) {
            ks_log(KS_LOG_ERROR, "%s: malloc failed\n", __func__);
            ks_do_panic(5);
        }

        memset(key->data, 0, key_size+1);

        size_t read_bytes = read(fd, key->data, key_size);
        ks_log(KS_LOG_DEBUG, "%s: read %zu bytes\n", __func__, read_bytes);

        /* Decode key type */
        mbedtls_pk_free(&ctx);
        rc = mbedtls_pk_parse_public_key(&ctx, key->data, key_size);

        if (rc != 0)
        {
            char error_str[128];
            mbedtls_strerror(rc, error_str, 128);
            ks_log(KS_LOG_ERROR, "%s: Could not parse key %s\n", __func__, error_str);
            ks_do_panic(5);
        }

        if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0)
        {
            switch (mbedtls_pk_get_bitlen(&ctx))
            {
                case 256:
                    key->kind = KS_KEY_PUB_PRIME256v1;
                break;
                case 384:
                    key->kind = KS_KEY_PUB_SECP384r1;
                break;
                case 521:
                    key->kind = KS_KEY_PUB_SECP521r1;
                break;
                default:
                    ks_log(KS_LOG_ERROR, "Unknown bit-length (%li)\n",
                            mbedtls_pk_get_bitlen(&ctx));
                    ks_do_panic(5);
            };
        }
        else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0)
        {
            if (mbedtls_pk_get_bitlen(&ctx) == 4096)
            {
                key->kind = KS_KEY_PUB_RSA4096;
            }
            else
            {
                ks_log(KS_LOG_ERROR, "Unknown bit-length (%li)\n",
                                mbedtls_pk_get_bitlen(&ctx));
                ks_do_panic(5);
            }
        }
        else
        {
            ks_log(KS_LOG_ERROR, "Error: Unknown key type (%s)\n",
                            mbedtls_pk_get_name(&ctx));
            ks_do_panic(5);
        }

        if (ks->keys == NULL) {
            ks->keys = key;
            key_next = key;
        } else {
            key_next->next = key;
            key_next = key;
        }
    }

err_out_close:
    close(fd);
    return rc;
}
