/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef KS_UTILS_H_
#define KS_UTILS_H_

#include <stdint.h>
#include <bpak/bpak.h>
#include "crypto_common.h"

void ks_do_panic(int delay_s);
int ks_readfile(const char *fn, char *buf, size_t sz);
int ks_bpak_hash_to_ks(enum bpak_hash_kind kind);
enum ks_system ks_active_system(void);

#endif  // KS_UTILS_H_
