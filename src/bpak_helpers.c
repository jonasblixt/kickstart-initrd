/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpak/bpak.h>

#include "bpak_helpers.h"
#include "crypto.h"
#include "utils.h"
#include "keys.h"
#include "log.h"

#define KS_HASH_CHUNK_BUF_SZ (1024*1024)

int bpak_helper_load_and_verify_header(int fd, struct bpak_header *h)
{
    int rc;
    struct ks_key *ver_key = NULL;
    struct ks_hash_context hash_ctx;
    char signature_tmp[BPAK_SIGNATURE_MAX_BYTES];
    size_t signature_sz = sizeof(signature_tmp);

    lseek(fd, -4096, SEEK_END);

    if (read(fd, h, sizeof(*h)) != sizeof(*h)) {
        ks_log(KS_LOG_ERROR, "%s: could not read header\n", __func__);
        return -1;
    }

    rc = bpak_valid_header(h);

    if (rc != BPAK_OK)
    {
        ks_log(KS_LOG_ERROR, "%s: Invalid bpak header, %s\n", __func__,
                                    bpak_error_string(rc));
        return rc;
    }

    lseek(fd, 0, SEEK_SET);

    /* Verify header signature */

    rc = ks_keys_get(h->keystore_id, h->key_id, &ver_key);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Key not found %08x [%08x]\n", __func__,
                                h->key_id, h->keystore_id);
        return rc;
    }

    ks_log(KS_LOG_DEBUG, "%s: Using key %08x [%08x]\n", __func__,
                                    h->key_id, h->keystore_id);

    rc = bpak_copyz_signature(h, signature_tmp, &signature_sz);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Could not extract signature\n", __func__);
        return rc;
    }

    rc = ks_hash_init(&hash_ctx, ks_bpak_hash_to_ks(h->hash_kind));

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: hash ctx init failed\n", __func__);
        return rc;
    }

    rc = ks_hash_update(&hash_ctx, h, sizeof(*h));

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Header hashing failed\n", __func__);
        return rc;
    }

    rc = ks_hash_finalize(&hash_ctx, NULL, 0);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Header hashing failed\n", __func__);
        return rc;
    }

    rc = ks_pk_verify(signature_tmp, signature_sz, &hash_ctx, ver_key);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Signature verification failed\n", __func__);
        return rc;
    }

    ks_log(KS_LOG_DEBUG, "%s: Signature OK\n", __func__);
    return rc;
}

int bpak_helper_verify_payload(int fd, struct bpak_header *h)
{
    int rc;
    struct ks_hash_context hash_ctx;
    char *hash_chunk_buf;

    hash_chunk_buf = malloc(KS_HASH_CHUNK_BUF_SZ);

    if (hash_chunk_buf == NULL) {
        ks_log(KS_LOG_ERROR, "%s: Malloc failed\n", __func__);
        return -1;
    }

    rc = ks_hash_init(&hash_ctx, ks_bpak_hash_to_ks(h->hash_kind));

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: hash ctx init failed\n", __func__);
        goto err_free_buf_out;
    }

    lseek(fd, 0, SEEK_SET);

    bpak_foreach_part(h, p)
    {
        size_t bytes_to_read = bpak_part_size(p);
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
        {
            lseek(fd, bpak_part_offset(h, p) - 4096, SEEK_SET);
            continue;
        }

        do
        {
            chunk = (bytes_to_read > KS_HASH_CHUNK_BUF_SZ)?
                                    KS_HASH_CHUNK_BUF_SZ:bytes_to_read;

            size_t read_bytes = read(fd, hash_chunk_buf, chunk);

            if (read_bytes != chunk) {
                ks_log(KS_LOG_ERROR, "%s: read error\n", __func__);
                rc = -1;
                goto err_free_buf_out;
            }

            rc = ks_hash_update(&hash_ctx, hash_chunk_buf, chunk);

            if (rc != 0) {
                ks_log(KS_LOG_ERROR, "%s: Hashing failed\n", __func__);
                goto err_free_buf_out;
            }

            bytes_to_read -= chunk;
        } while (bytes_to_read);
    }

    rc = ks_hash_finalize(&hash_ctx, NULL, 0);

    if (rc != 0) {
        ks_log(KS_LOG_ERROR, "%s: Hashing failed\n", __func__);
        goto err_free_buf_out;
    }

    if (memcmp(hash_ctx.buf, h->payload_hash, hash_ctx.size) != 0) {
        ks_log(KS_LOG_ERROR, "%s: Payload hash mismatch\n", __func__);
        rc = -1;
        goto err_free_buf_out;
    }

    ks_log(KS_LOG_DEBUG, "%s: Payload hash OK\n", __func__);

err_free_buf_out:
    free(hash_chunk_buf);
    return rc;
}
