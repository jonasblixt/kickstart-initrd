#ifndef KS_CONFIG_H_
#define KS_CONFIG_H_

#include <stdbool.h>

#include "kickstart.h"

struct ks_config_mount_target
{
    const char *name;
    const char *device;
    const char *device_type;
    const char *fs_type;
    const char *mount_target;
    const char *options;
    bool move;
    bool early;
    struct ks_config_mount_target *next;
};

struct ks_config_verity_target
{
    const char *name;
    const char *device;
    const char *device_type;
    enum ks_system system;
    struct ks_config_verity_target *next;
};

struct ks_config_keystore
{
    const char *name;
    const char *device;
    const char *device_type;
    enum ks_system system;
    struct ks_config_keystore *next;
};

struct ks_config
{
    int log_level;
    const char *init_handover;
    const char *root_device;
    struct ks_config *next;
};

int ks_config_init(const char *config_filename);
struct ks_config_mount_target * ks_config_mount_targets(void);
struct ks_config_keystore * ks_config_keystore(void);
struct ks_config * ks_config(void);
struct ks_config_verity_target *ks_config_verity_targets(void);
void ks_config_free(void);

#endif  // KS_CONFIG_H_
