#ifndef KS_UTILS_H_
#define KS_UTILS_H_

#include <stdint.h>
#include <bpak/bpak.h>
#include "crypto_common.h"

void ks_do_panic(int delay_s);
int ks_readfile(const char *fn, char *buf, size_t sz);
int ks_bpak_hash_to_ks(enum bpak_hash_kind kind);

#endif  // KS_UTILS_H_
