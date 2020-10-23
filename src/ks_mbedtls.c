#include <stdio.h>
#include <string.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "crypto.h"
#include "log.h"

struct ks_mbedtls_hash_ctx {
    mbedtls_sha256_context sha256;
    mbedtls_sha512_context sha512;
};

static int hash_kind(struct ks_hash_context *hash)
{
    switch (hash->alg)
    {
        case KS_HASH_SHA256:
            return MBEDTLS_MD_SHA256;
        case KS_HASH_SHA384:
            return MBEDTLS_MD_SHA384;
        case KS_HASH_SHA512:
            return MBEDTLS_MD_SHA512;
        default:
            return -1;
    }
}

int ks_crypto_init(void)
{
    ks_log(KS_LOG_DEBUG, "%s\n", __func__);
    return 0;
}

void ks_crypto_free(void)
{
    ks_log(KS_LOG_DEBUG, "%s\n", __func__);
}

int ks_hash_init(struct ks_hash_context *ctx, enum ks_hash_algs alg)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->alg = alg;
    ctx->private = malloc(sizeof(struct ks_mbedtls_hash_ctx));

    if (ctx->private == NULL)
        return -1;

    memset(ctx->private, 0, sizeof(struct ks_mbedtls_hash_ctx));

    struct ks_mbedtls_hash_ctx *priv = \
                        (struct ks_mbedtls_hash_ctx *) ctx->private;

    switch (hash_kind(ctx))
    {
        case MBEDTLS_MD_SHA256:
            ks_log(KS_LOG_DEBUG, "%s %i MBEDTLS_MD_SHA256\n", __func__, alg);
            ctx->size = 32;
            mbedtls_sha256_init(&priv->sha256);
            mbedtls_sha256_starts_ret(&priv->sha256, 0);
        break;
        case MBEDTLS_MD_SHA384:
            ks_log(KS_LOG_DEBUG, "%s %i MBEDTLS_MD_SHA384\n", __func__, alg);
            ctx->size = 48;
            mbedtls_sha512_init(&priv->sha512);
            mbedtls_sha512_starts_ret(&priv->sha512, 1);
        break;
        case MBEDTLS_MD_SHA512:
            ks_log(KS_LOG_DEBUG, "%s %i MBEDTLS_MD_SHA512\n", __func__, alg);
            ctx->size = 64;
            mbedtls_sha512_init(&priv->sha512);
            mbedtls_sha512_starts_ret(&priv->sha512, 0);
        break;
        default:
            ks_log(KS_LOG_ERROR, "%s: Unknown alg\n", __func__);
            goto err_free_out;
    }

    return 0;
err_free_out:
    free(ctx->private);
    return -1;
}

int ks_hash_update(struct ks_hash_context *ctx, void *buf, size_t size)
{
    int rc = 0;
    ks_log(KS_LOG_DEBUG, "%s %p, %zu\n", __func__, buf, size);

    struct ks_mbedtls_hash_ctx *priv = \
                        (struct ks_mbedtls_hash_ctx *) ctx->private;

    if (hash_kind(ctx) == MBEDTLS_MD_SHA256)
        rc = mbedtls_sha256_update_ret(&priv->sha256, (char *) buf, size);
    else
        rc = mbedtls_sha512_update_ret(&priv->sha512, (char *) buf, size);

    return rc;
}

int ks_hash_finalize(struct ks_hash_context *ctx, void *buf, size_t size)
{
    int rc = 0;
    ks_log(KS_LOG_DEBUG, "%s %p %zu\n", __func__, buf, size);

    struct ks_mbedtls_hash_ctx *priv = \
                        (struct ks_mbedtls_hash_ctx *) ctx->private;

    if (size) {
        if (hash_kind(ctx) == MBEDTLS_MD_SHA256)
            rc = mbedtls_sha256_update_ret(&priv->sha256, (char *) buf, size);
        else
            rc = mbedtls_sha512_update_ret(&priv->sha512, (char *) buf, size);

        if (rc != 0)
            goto err_out;
    }

    if (hash_kind(ctx) == MBEDTLS_MD_SHA256)
        rc = mbedtls_sha256_finish_ret(&priv->sha256, ctx->buf);
    else
        rc = mbedtls_sha512_finish_ret(&priv->sha512, ctx->buf);

err_out:
    free(priv);
    return rc;
}

int ks_pk_verify(void *signature, size_t size, struct ks_hash_context *hash,
                        struct ks_key *key)
{
    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    int rc = 0;

    ks_log(KS_LOG_DEBUG, "%s %p %zu %p %p\n", __func__, signature, size, hash,
            key);

    mbedtls_pk_init(&ctx);

    rc = mbedtls_pk_parse_public_key(&ctx, key->data, key->size);

    if (rc != 0)
    {
        ks_log(KS_LOG_ERROR, "%s: Uknown key type\n", __func__);
        return rc;
    }

    rc = mbedtls_pk_verify(&ctx, hash_kind(hash),
                                 hash->buf, sizeof(hash->buf),
                                 signature, size);

    if (rc != BPAK_OK)
    {
        char error_str[128];
        mbedtls_strerror(rc, error_str, 128);
        ks_log(KS_LOG_ERROR, "%s: %s\n", __func__, error_str);
        return rc;
    }

    return rc;
}
