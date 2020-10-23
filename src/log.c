#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "log.h"

static enum ks_log_level ll;

int ks_log_init(enum ks_log_level initial_log_level)
{
    ll = initial_log_level;
    return 0;
}

int ks_log_set_loglevel(enum ks_log_level log_level)
{
    ll = log_level;
    return 0;
}

int ks_log_free(void)
{
    return 0;
}

void ks_log(enum ks_log_level log_level, const char *fmt, ...)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    if (log_level > ll)
        return;

    if (log_level >= KS_LOG_END)
        return;

    printf("[%5lld.%06lld] ks: ", ts.tv_sec, ts.tv_nsec / (int64_t) 1E3);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
