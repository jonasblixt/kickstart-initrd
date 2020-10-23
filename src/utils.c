#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/reboot.h>
#include <bpak/bpak.h>

#include "log.h"
#include "crypto_common.h"

void ks_do_panic(int delay_s)
{
    ks_log(KS_LOG_ERROR, "Panic, rebooting in %is...\n", delay_s);
    sleep(delay_s);
    reboot(0x1234567);
    while (true) {}
}

int ks_readfile(const char *fn, char *buf, size_t sz)
{
    FILE *fp = fopen(fn,"r");

    if (fp == NULL)
        return -1;

    memset(buf, 0, sz);
    int result = fread (buf, 1, sz, fp);

    fclose(fp);

    return (result > 0)?0:-1;
}

int ks_bpak_hash_to_ks(enum bpak_hash_kind kind)
{
    switch (kind) {
        case BPAK_HASH_SHA256:
            return KS_HASH_SHA256;
        case BPAK_HASH_SHA384:
            return KS_HASH_SHA384;
        case BPAK_HASH_SHA512:
            return KS_HASH_SHA512;
        default:
            return KS_HASH_INVALID;
    }
}
