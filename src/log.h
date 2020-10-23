/**
 * Kickstart
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef KS_LOG_H_
#define KS_LOG_H_

#include <stdint.h>

enum ks_log_level
{
    KS_LOG_SHUTUP = 0,
    KS_LOG_ERROR,
    KS_LOG_INFO,
    KS_LOG_DEBUG,
    KS_LOG_END,
};

int ks_log_init(enum ks_log_level initial_log_level);
int ks_log_set_loglevel(enum ks_log_level log_level);
int ks_log_free(void);
void ks_log(enum ks_log_level log_level, const char *fmt, ...);

#endif  // KS_LOG_H_
