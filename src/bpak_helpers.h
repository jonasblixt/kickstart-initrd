/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BPAK_HELPERS_H_
#define BPAK_HELPERS_H_

#include <bpak/bpak.h>

int bpak_helper_load_and_verify_header(int fd, struct bpak_header *h);
int bpak_helper_verify_payload(int fd, struct bpak_header *h);

#endif  // BPAK_HELPERS_H_
