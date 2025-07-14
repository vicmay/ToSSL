#include "tossl_pgp_crypto.h"
#include <string.h>
#include <openssl/err.h>

pgp_error_t pgp_crypto_init(pgp_crypto_ctx_t *ctx) {
    if (!ctx) return PGP_ERR_INTERNAL;
    
    memset(ctx, 0, sizeof(pgp_crypto_ctx_t));
    
    ctx->md_ctx = EVP_MD_CTX_new();
    if (!ctx->md_ctx) return PGP_ERR_MEMORY;
    
    return PGP_OK;
}

void pgp_crypto_cleanup(pgp_crypto_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->pkey_ctx) EVP_PKEY_CTX_free(ctx->pkey_ctx);
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    if (ctx->md_ctx) EVP_MD_CTX_free(ctx->md_ctx);
    if (ctx->sig_buf) {
        secure_memzero(ctx->sig_buf, ctx->sig_len);
        OPENSSL_free(ctx->sig_buf);
    }
    
    memset(ctx, 0, sizeof(pgp_crypto_ctx_t));
}

pgp_error_t pgp_crypto_set_hash(pgp_crypto_ctx_t *ctx, pgp_hash_algo_t algo) {
    if (!ctx || !ctx->md_ctx) return PGP_ERR_INTERNAL;
    
    ctx->md = pgp_hash_to_evp_md(algo);
    if (!ctx->md) return PGP_ERR_UNSUPPORTED_ALGORITHM;
    
    if (!EVP_DigestInit_ex(ctx->md_ctx, ctx->md, NULL))
        return PGP_ERR_CRYPTO_FAILED;
    
    return PGP_OK;
}

pgp_error_t pgp_crypto_set_key(pgp_crypto_ctx_t *ctx, EVP_PKEY *pkey, int padding) {
    if (!ctx || !pkey) return PGP_ERR_INTERNAL;
    
    // Free any existing key context
    if (ctx->pkey_ctx) {
        EVP_PKEY_CTX_free(ctx->pkey_ctx);
        ctx->pkey_ctx = NULL;
    }
    
    // Create new key context
    ctx->pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx->pkey_ctx) return PGP_ERR_MEMORY;
    
    ctx->pkey = pkey;
    ctx->padding = padding;
    
    return PGP_OK;
}

pgp_error_t pgp_crypto_hash_update(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len) {
    if (!ctx || !ctx->md_ctx) return PGP_ERR_INTERNAL;
    
    if (!EVP_DigestUpdate(ctx->md_ctx, data, len))
        return PGP_ERR_CRYPTO_FAILED;
    
    return PGP_OK;
}

pgp_error_t pgp_crypto_hash_final(pgp_crypto_ctx_t *ctx, unsigned char *md, unsigned int *md_len) {
    if (!ctx || !ctx->md_ctx || !md || !md_len) return PGP_ERR_INTERNAL;
    
    if (!EVP_DigestFinal_ex(ctx->md_ctx, md, md_len))
        return PGP_ERR_CRYPTO_FAILED;
    
    return PGP_OK;
}

pgp_error_t pgp_crypto_sign(pgp_crypto_ctx_t *ctx, const unsigned char *tbs, size_t tbs_len,
                           unsigned char *sig, size_t *sig_len) {
    if (!ctx || !ctx->pkey_ctx || !tbs || !sig || !sig_len)
        return PGP_ERR_INTERNAL;
    
    if (EVP_PKEY_sign_init(ctx->pkey_ctx) <= 0)
        return PGP_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx->pkey_ctx, ctx->padding) <= 0)
        return PGP_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_sign(ctx->pkey_ctx, sig, sig_len, tbs, tbs_len) <= 0)
        return PGP_ERR_CRYPTO_FAILED;
    
    return PGP_OK;
}

pgp_error_t pgp_crypto_verify(pgp_crypto_ctx_t *ctx, const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len) {
    if (!ctx || !ctx->pkey_ctx || !msg || !sig)
        return PGP_ERR_INTERNAL;
    
    if (EVP_PKEY_verify_init(ctx->pkey_ctx) <= 0)
        return PGP_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx->pkey_ctx, ctx->padding) <= 0)
        return PGP_ERR_CRYPTO_FAILED;
    
    int ret = EVP_PKEY_verify(ctx->pkey_ctx, sig, sig_len, msg, msg_len);
    if (ret < 0) return PGP_ERR_CRYPTO_FAILED;
    if (ret == 0) return PGP_ERR_VERIFY_FAILED;
    
    return PGP_OK;
}

const EVP_MD *pgp_hash_to_evp_md(pgp_hash_algo_t algo) {
    switch (algo) {
        case PGP_HASH_MD5: return EVP_md5();
        case PGP_HASH_SHA1: return EVP_sha1();
        case PGP_HASH_RIPEMD160: return EVP_ripemd160();
        case PGP_HASH_SHA256: return EVP_sha256();
        case PGP_HASH_SHA384: return EVP_sha384();
        case PGP_HASH_SHA512: return EVP_sha512();
        case PGP_HASH_SHA224: return EVP_sha224();
        default: return NULL;
    }
}
