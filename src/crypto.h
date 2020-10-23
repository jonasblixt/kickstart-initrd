/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef KS_CRYPTO_H_
#define KS_CRYPTO_H_

#include <stdint.h>

#include "keys.h"
#include "crypto_common.h"

struct ks_hash_context
{
    uint8_t buf[128];
    enum ks_hash_algs alg;
    size_t size;
    void *private;
};

int ks_crypto_init(void);
void ks_crypto_free(void);
int ks_hash_init(struct ks_hash_context *ctx, enum ks_hash_algs alg);
int ks_hash_update(struct ks_hash_context *ctx, void *buf, size_t size);
int ks_hash_finalize(struct ks_hash_context *ctx, void *buf, size_t size);
int ks_pk_verify(void *signature, size_t size, struct ks_hash_context *hash,
                        struct ks_key *key);

#endif  // KS_CRYPTO_H_
