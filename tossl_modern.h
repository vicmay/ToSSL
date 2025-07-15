/*
 * TOSSL Modern OpenSSL 3.x API Wrappers
 * 
 * This file provides modern OpenSSL 3.x API wrappers to replace
 * deprecated functions and ensure compatibility with the latest OpenSSL.
 */

#ifndef TOSSL_MODERN_H
#define TOSSL_MODERN_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <tcl.h>

// Modern OpenSSL 3.x API wrappers

// Key management functions
EVP_PKEY *modern_key_new(int type);
int modern_key_set_rsa_params(EVP_PKEY *pkey, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int modern_key_get_rsa_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d);
int modern_key_check(EVP_PKEY *pkey);

// RSA-specific modern functions
int modern_rsa_get_key_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d);
int modern_rsa_get_factors(EVP_PKEY *pkey, BIGNUM **p, BIGNUM **q);
int modern_rsa_get_crt_params(EVP_PKEY *pkey, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp);
int modern_rsa_validate_key(EVP_PKEY *pkey);

// DSA-specific modern functions
int modern_dsa_get_key_params(EVP_PKEY *pkey, BIGNUM **p, BIGNUM **q, BIGNUM **g, BIGNUM **pub_key, BIGNUM **priv_key);
int modern_dsa_validate_key(EVP_PKEY *pkey);

// EC-specific modern functions
int modern_ec_get_key_params(EVP_PKEY *pkey, BIGNUM **x, BIGNUM **y, BIGNUM **d);
int modern_ec_validate_key(EVP_PKEY *pkey);

// Provider management functions
OSSL_PROVIDER *modern_load_provider(const char *name);
void modern_unload_provider(OSSL_PROVIDER *provider);
int modern_list_providers(char **provider_names);

// Algorithm discovery functions
int modern_list_algorithms(const char *type, char **algorithm_names);
int modern_get_algorithm_properties(const char *algorithm, const char *type, char **properties);

// CRL modern functions
const ASN1_TIME *modern_crl_get_last_update(const X509_CRL *crl);
const ASN1_TIME *modern_crl_get_next_update(const X509_CRL *crl);

// Cipher and digest modern functions
EVP_CIPHER *modern_cipher_fetch(const char *name);
EVP_MD *modern_digest_fetch(const char *name);
void modern_cipher_free(EVP_CIPHER *cipher);
void modern_digest_free(EVP_MD *md);

// Key generation modern functions
EVP_PKEY_CTX *modern_keygen_ctx_new(const char *algorithm);
int modern_keygen_set_params(EVP_PKEY_CTX *ctx, const char *param_name, int value);
int modern_keygen_set_bits(EVP_PKEY_CTX *ctx, int bits);

// Sign/Verify modern functions
EVP_PKEY_CTX *modern_sign_ctx_new(EVP_PKEY *pkey);
EVP_PKEY_CTX *modern_verify_ctx_new(EVP_PKEY *pkey);
int modern_sign_init(EVP_PKEY_CTX *ctx);
int modern_verify_init(EVP_PKEY_CTX *ctx);
int modern_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int modern_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);

// Encryption/Decryption modern functions
EVP_PKEY_CTX *modern_encrypt_ctx_new(EVP_PKEY *pkey);
EVP_PKEY_CTX *modern_decrypt_ctx_new(EVP_PKEY *pkey);
int modern_encrypt_init(EVP_PKEY_CTX *ctx);
int modern_decrypt_init(EVP_PKEY_CTX *ctx);
int modern_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
int modern_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

// Utility functions
int modern_get_key_type(EVP_PKEY *pkey);
const char *modern_get_key_type_name(EVP_PKEY *pkey);
int modern_key_size(EVP_PKEY *pkey);

// FIPS support functions
int modern_enable_fips(void);
int modern_check_fips_status(char **status_info);

#ifdef __cplusplus
extern "C" {
#endif
// Tcl command handler prototypes for provider and FIPS management
int ProviderLoadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int ProviderUnloadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int ProviderListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int FipsEnableCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int FipsStatusCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int AlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int AlgorithmInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
#ifdef __cplusplus
}
#endif

#endif // TOSSL_MODERN_H 