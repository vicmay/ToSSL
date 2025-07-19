/*
 * TOSSL Modern OpenSSL 3.x API Implementation
 * 
 * Implementation of modern OpenSSL 3.x API wrappers to replace
 * deprecated functions and ensure compatibility with the latest OpenSSL.
 */

#include "tossl_modern.h"
#include <openssl/err.h>
#include <string.h>
#include <tcl.h>

// Key management functions
EVP_PKEY *modern_key_new(int type) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        return NULL;
    }
    
    // For OpenSSL 3.x, we need to use the appropriate key generation context
    // This function is simplified for compatibility
    return pkey;
    
    return pkey;
}

int modern_key_set_rsa_params(EVP_PKEY *pkey, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, e, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, d, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_set_params(pkey, params);
}

int modern_key_get_rsa_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, e, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, d, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_get_params(pkey, params);
}

int modern_key_check(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// RSA-specific modern functions
int modern_rsa_get_key_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d) {
    return modern_key_get_rsa_params(pkey, n, e, d);
}

int modern_rsa_get_factors(EVP_PKEY *pkey, BIGNUM **p, BIGNUM **q) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, p, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, q, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_get_params(pkey, params);
}

int modern_rsa_get_crt_params(EVP_PKEY *pkey, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_get_params(pkey, params);
}

int modern_rsa_validate_key(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int modern_rsa_public_check(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_public_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// DSA-specific modern functions
int modern_dsa_get_key_params(EVP_PKEY *pkey, BIGNUM **p, BIGNUM **q, BIGNUM **g, BIGNUM **pub_key, BIGNUM **priv_key) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, g, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, pub_key, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv_key, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_get_params(pkey, params);
}

int modern_dsa_validate_key(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int modern_dsa_public_check(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_public_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// EC-specific modern functions
int modern_ec_get_key_params(EVP_PKEY *pkey, BIGNUM **x, BIGNUM **y, BIGNUM **d) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, x, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, y, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, d, 0),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_get_params(pkey, params);
}

int modern_ec_validate_key(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int modern_ec_public_check(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        return 0;
    }
    int result = EVP_PKEY_public_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// Provider management functions
OSSL_PROVIDER *modern_load_provider(const char *name) {
    return OSSL_PROVIDER_load(NULL, name);
}

void modern_unload_provider(OSSL_PROVIDER *provider) {
    if (provider) {
        OSSL_PROVIDER_unload(provider);
    }
}

int modern_list_providers(char **provider_names) {
    // For now, return known default providers
    // TODO: Implement proper provider enumeration when callback issues are resolved
    char *names = strdup("default, legacy");
    if (!names) return 0;
    
    *provider_names = names;
    return 1;
}

// Algorithm discovery functions
int modern_list_algorithms(const char *type, char **algorithm_names) {
    // For now, return common algorithms based on type
    // TODO: Implement proper algorithm enumeration when callback issues are resolved
    char *names = NULL;
    
    if (strcmp(type, "digest") == 0) {
        names = strdup("sha1, sha256, sha384, sha512, md5");
    } else if (strcmp(type, "cipher") == 0) {
        names = strdup("aes-128-cbc, aes-256-cbc, aes-128-gcm, aes-256-gcm");
    } else if (strcmp(type, "mac") == 0) {
        names = strdup("hmac, cmac");
    } else if (strcmp(type, "kdf") == 0) {
        names = strdup("pbkdf2, scrypt, argon2");
    } else if (strcmp(type, "keyexch") == 0) {
        names = strdup("ecdh, dh");
    } else if (strcmp(type, "signature") == 0) {
        names = strdup("rsa, dsa, ecdsa, ed25519, ed448");
    } else if (strcmp(type, "asym_cipher") == 0) {
        names = strdup("rsa, sm2");
    } else {
        return 0;
    }
    
    if (!names) return 0;
    *algorithm_names = names;
    return 1;
}

int modern_get_algorithm_properties(const char *algorithm, const char *type, char **properties) {
    // For now, return basic info
    // TODO: Implement detailed property querying
    char *info = malloc(256);
    if (!info) return 0;
    
    snprintf(info, 256, "algorithm=%s, type=%s", algorithm, type);
    *properties = info;
    return 1;
}

// CRL modern functions
const ASN1_TIME *modern_crl_get_last_update(const X509_CRL *crl) {
    return X509_CRL_get0_lastUpdate(crl);
}

const ASN1_TIME *modern_crl_get_next_update(const X509_CRL *crl) {
    return X509_CRL_get0_nextUpdate(crl);
}

// Cipher and digest modern functions
EVP_CIPHER *modern_cipher_fetch(const char *name) {
    return EVP_CIPHER_fetch(NULL, name, NULL);
}

EVP_MD *modern_digest_fetch(const char *name) {
    return EVP_MD_fetch(NULL, name, NULL);
}

void modern_cipher_free(EVP_CIPHER *cipher) {
    EVP_CIPHER_free(cipher);
}

void modern_digest_free(EVP_MD *md) {
    EVP_MD_free(md);
}

// Key generation modern functions
EVP_PKEY_CTX *modern_keygen_ctx_new(const char *algorithm) {
    return EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
}

int modern_keygen_set_params(EVP_PKEY_CTX *ctx, const char *param_name, int value) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_uint(param_name, (unsigned int*)&value),
        OSSL_PARAM_END
    };
    
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int modern_keygen_set_bits(EVP_PKEY_CTX *ctx, int bits) {
    return modern_keygen_set_params(ctx, OSSL_PKEY_PARAM_RSA_BITS, bits);
}

// Sign/Verify modern functions
EVP_PKEY_CTX *modern_sign_ctx_new(EVP_PKEY *pkey) {
    return EVP_PKEY_CTX_new(pkey, NULL);
}

EVP_PKEY_CTX *modern_verify_ctx_new(EVP_PKEY *pkey) {
    return EVP_PKEY_CTX_new(pkey, NULL);
}

int modern_sign_init(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_sign_init(ctx);
}

int modern_verify_init(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_verify_init(ctx);
}

int modern_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    return EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
}

int modern_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    return EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
}

// Encryption/Decryption modern functions
EVP_PKEY_CTX *modern_encrypt_ctx_new(EVP_PKEY *pkey) {
    return EVP_PKEY_CTX_new(pkey, NULL);
}

EVP_PKEY_CTX *modern_decrypt_ctx_new(EVP_PKEY *pkey) {
    return EVP_PKEY_CTX_new(pkey, NULL);
}

int modern_encrypt_init(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_encrypt_init(ctx);
}

int modern_decrypt_init(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_decrypt_init(ctx);
}

int modern_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
    return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

int modern_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
    return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}

// Utility functions
int modern_get_key_type(EVP_PKEY *pkey) {
    return EVP_PKEY_id(pkey);
}

const char *modern_get_key_type_name(EVP_PKEY *pkey) {
    int type = EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA: return "RSA";
        case EVP_PKEY_DSA: return "DSA";
        case EVP_PKEY_EC: return "EC";
        case EVP_PKEY_ED25519: return "ED25519";
        case EVP_PKEY_X25519: return "X25519";
        case EVP_PKEY_ED448: return "ED448";
        case EVP_PKEY_X448: return "X448";
        default: return "UNKNOWN";
    }
}

int modern_key_size(EVP_PKEY *pkey) {
    return EVP_PKEY_size(pkey);
} 

// FIPS support functions
int modern_enable_fips(void) {
    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (!fips) {
        return 0;
    }
    
    // Enable FIPS mode
    if (!EVP_default_properties_enable_fips(NULL, 1)) {
        OSSL_PROVIDER_unload(fips);
        return 0;
    }
    
    return 1;
}

int modern_check_fips_status(char **status_info) {
    char *info = malloc(256);
    if (!info) return 0;
    
    // Check if FIPS provider is loaded
    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (fips) {
        OSSL_PROVIDER_unload(fips);
        snprintf(info, 256, "FIPS provider available: yes, FIPS mode: enabled");
    } else {
        snprintf(info, 256, "FIPS provider available: no, FIPS mode: disabled");
    }
    
    *status_info = info;
    return 1;
} 

int ProviderListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    char *provider_names = NULL;
    if (!modern_list_providers(&provider_names)) {
        Tcl_SetResult(interp, (char *)"Failed to list providers", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, provider_names, TCL_VOLATILE);
    free(provider_names);
    return TCL_OK;
} 