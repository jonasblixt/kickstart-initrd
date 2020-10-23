#ifndef KS_CONFIG_H_
#define KS_CONFIG_H_

#include <stdbool.h>

struct ks_config_mount_target
{
    const char *name;
    const char *device;
    const char *device_type;
    const char *fs_type;
    const char *mount_target;
    bool move;
    bool early;
    struct ks_config_mount_target *next;
};

struct ks_config_keystore
{
    const char *name;
    const char *device;
    const char *device_type;
    char set;
    struct ks_config_keystore *next;
};

int ks_config_init(const char *config_filename);
struct ks_config_mount_target * ks_config_mount_targets(void);
struct ks_config_keystore * ks_config_keystore(void);
void ks_config_free(void);

#endif  // KS_CONFIG_H_
