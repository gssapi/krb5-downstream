/*
 * OpenSSL 3.0 Legacy Provider Support
 *
 * OpenSSL 3.0 moved older cryptographic algorithms (MD4, MD5, RC4) to a
 * separate "legacy provider" that must be explicitly loaded. These algorithms
 * are considered deprecated but are still needed for backward compatibility:
 *
 *   - MD4/MD5: Used by older Kerberos encryption types and RADIUS
 *   - RC4: Used by RC4-HMAC encryption type
 *   - HMAC-MD5: Required for RADIUS Message-Authenticator attribute
 *
 * In FIPS mode, these algorithms are normally blocked. However, when the
 * "radius_md5_fips_override" configuration option is enabled, we need to
 * allow HMAC-MD5 for RADIUS compatibility. This module provides a shared
 * OpenSSL library context with the legacy provider loaded, enabling access
 * to these algorithms when explicitly required.
 *
 * The context is stored in thread-local storage to avoid concurrency issues.
 */

#include "crypto_int.h"

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <threads.h>
#include <stdbool.h>

/* Thread-local context holding the OpenSSL legacy provider state. */
typedef struct ossl_legacy_context {
    bool initialized;
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *default_provider;
    OSSL_PROVIDER *legacy_provider;
} ossl_legacy_context_t;

static thread_local ossl_legacy_context_t g_ossl_legacy_ctx;

/* Initialize an OpenSSL library context with both default and legacy providers. */
static krb5_error_code
init_ossl_legacy_ctx(ossl_legacy_context_t *ctx)
{
    ctx->libctx = OSSL_LIB_CTX_new();
    if (!ctx->libctx)
        return KRB5_CRYPTO_INTERNAL;

    /* Load both legacy and default provider as both may be needed. */
    ctx->default_provider = OSSL_PROVIDER_load(ctx->libctx, "default");
    ctx->legacy_provider = OSSL_PROVIDER_load(ctx->libctx, "legacy");

    if (!(ctx->default_provider && ctx->legacy_provider))
        return KRB5_CRYPTO_INTERNAL;

    ctx->initialized = true;
    return 0;
}

static void
deinit_ossl_legacy_ctx(ossl_legacy_context_t *ctx)
{
    if (ctx->legacy_provider)
        OSSL_PROVIDER_unload(ctx->legacy_provider);

    if (ctx->default_provider)
        OSSL_PROVIDER_unload(ctx->default_provider);

    if (ctx->libctx)
        OSSL_LIB_CTX_free(ctx->libctx);

    ctx->initialized = false;
}

/*
 * Get an OpenSSL library context with the legacy provider loaded.
 *
 * In non-FIPS mode, returns NULL (use the default context).
 * In FIPS mode, returns a dedicated context with the legacy provider,
 * allowing access to deprecated algorithms like MD4/MD5 when explicitly needed.
 */
krb5_error_code
k5_get_ossl_legacy_libctx(OSSL_LIB_CTX **libctx)
{
    krb5_error_code err;

    if (!EVP_default_properties_is_fips_enabled(NULL)) {
        if (libctx)
            *libctx = NULL;
        err = 0;
        goto end;
    }

    if (!g_ossl_legacy_ctx.initialized) {
        err = init_ossl_legacy_ctx(&g_ossl_legacy_ctx);
        if (err) {
            deinit_ossl_legacy_ctx(&g_ossl_legacy_ctx);
            goto end;
        }
    }

    if (libctx)
        *libctx = g_ossl_legacy_ctx.libctx;
    err = 0;

end:
    return err;
}
