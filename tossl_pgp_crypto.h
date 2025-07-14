#ifndef TOSSL_PGP_CRYPTO_H
#define TOSSL_PGP_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "tossl_pgp_error.h"

// Supported algorithms as per RFC 4880
typedef enum {
    PGP_HASH_MD5 = 1,
    PGP_HASH_SHA1 = 2,
    PGP_HASH_RIPEMD160 = 3,
    PGP_HASH_SHA256 = 8,
    PGP_HASH_SHA384 = 9,
    PGP_HASH_SHA512 = 10,
    PGP_HASH_SHA224 = 11
} pgp_hash_algo_t;

typedef enum {
    PGP_PUBKEY_RSA = 1,
    PGP_PUBKEY_RSA_E = 2,
    PGP_PUBKEY_RSA_S = 3,
    PGP_PUBKEY_ELGAMAL = 16,
    PGP_PUBKEY_DSA = 17,
    PGP_PUBKEY_ECDH = 18,
    PGP_PUBKEY_ECDSA = 19,
    PGP_PUBKEY_EDDSA = 22
} pgp_pubkey_algo_t;

// Modern crypto context
typedef struct {
    EVP_PKEY_CTX *pkey_ctx;    // Key context for operations
    EVP_PKEY *pkey;            // Public or private key
    EVP_MD_CTX *md_ctx;        // Message digest context
    const EVP_MD *md;          // Message digest algorithm
    unsigned char *sig_buf;     // Signature buffer
    size_t sig_len;            // Signature length
    int padding;               // RSA padding mode
} pgp_crypto_ctx_t;

// Initialize crypto context
pgp_error_t pgp_crypto_init(pgp_crypto_ctx_t *ctx);

// Clean up crypto context
void pgp_crypto_cleanup(pgp_crypto_ctx_t *ctx);

// Set up hash algorithm
pgp_error_t pgp_crypto_set_hash(pgp_crypto_ctx_t *ctx, pgp_hash_algo_t algo);

// Set up public key algorithm
pgp_error_t pgp_crypto_set_key(pgp_crypto_ctx_t *ctx, EVP_PKEY *pkey, int padding);

// Hash data
pgp_error_t pgp_crypto_hash_update(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len);

// Finalize hash
pgp_error_t pgp_crypto_hash_final(pgp_crypto_ctx_t *ctx, unsigned char *md, unsigned int *md_len);

// Sign data
pgp_error_t pgp_crypto_sign(pgp_crypto_ctx_t *ctx, const unsigned char *tbs, size_t tbs_len,
                           unsigned char *sig, size_t *sig_len);

// Verify signature
pgp_error_t pgp_crypto_verify(pgp_crypto_ctx_t *ctx, const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len);

// Convert OpenPGP algorithm ID to OpenSSL EVP_MD
const EVP_MD *pgp_hash_to_evp_md(pgp_hash_algo_t algo);

#endif /* TOSSL_PGP_CRYPTO_H */
