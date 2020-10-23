/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef KS_CRYPTO_COMMON_H_
#define KS_CRYPTO_COMMON_H_

#include <stdint.h>

enum ks_hash_algs
{
    KS_HASH_INVALID,
    KS_HASH_MD5,
    KS_HASH_SHA256,
    KS_HASH_SHA384,
    KS_HASH_SHA512,
};

enum ks_key_kind {
    KS_KEY_INVALID,
    KS_KEY_PUB_PRIME256v1,
    KS_KEY_PUB_SECP384r1,
    KS_KEY_PUB_SECP521r1,
    KS_KEY_PUB_RSA4096,
};

struct ks_key {
    uint32_t id;
    size_t size;
    enum ks_key_kind kind;
    uint8_t *data;
    struct ks_key *next;
};

struct ks_keystore {
    uint32_t id;
    struct ks_key *keys;
    struct ks_keystore *next;
};


#endif  // KS_CRYPTO_COMMON_H_
