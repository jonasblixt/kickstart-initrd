/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef KS_KEYSTORE_H_
#define KS_KEYSTORE_H_

#include <stdint.h>
#include <bpak/bpak.h>
#include <bpak/keystore.h>

#include "crypto_common.h"

#define KS_MAX_KEYS 16

int ks_keys_init(void);
void ks_keys_free(void);
int ks_keys_ok(uint32_t key_id);
int ks_keys_get(uint32_t keystore_id, uint32_t key_id, struct ks_key **key);
int ks_keys_add_from_device(const char *device_filename);

#endif  // KS_KEYSTORE_H_
