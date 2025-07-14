#include "tossl.h"
#include <stdio.h>
#include <openssl/err.h>

// Common utility function
void bin2hex(const unsigned char *in, int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        out[i*2] = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0x0f];
    }
    out[len*2] = '\0';
}

// tossl::hmac -alg <name> -key <key> <data>
int HmacCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -key key data");
        return TCL_ERROR;
    }
    const char *alg = NULL;
    unsigned char *key = NULL, *data = NULL;
    int keylen = 0, datalen = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &keylen);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);

    int rc = TCL_ERROR;
    unsigned char mac[EVP_MAX_MD_SIZE];
    char hex[2*EVP_MAX_MD_SIZE+1];
    EVP_MAC *mac_algo = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    size_t outlen = sizeof(mac);

    mac_algo = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac_algo) {
        Tcl_SetResult(interp, "OpenSSL: HMAC fetch failed", TCL_STATIC);
        goto cleanup;
    }
    ctx = EVP_MAC_CTX_new(mac_algo);
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: HMAC ctx alloc failed", TCL_STATIC);
        goto cleanup;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)alg, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx, key, keylen, params)) {
        Tcl_SetResult(interp, "OpenSSL: HMAC init failed", TCL_STATIC);
        goto cleanup;
    }
    if (!EVP_MAC_update(ctx, data, datalen)) {
        Tcl_SetResult(interp, "OpenSSL: HMAC update failed", TCL_STATIC);
        goto cleanup;
    }
    if (!EVP_MAC_final(ctx, mac, &outlen, sizeof(mac))) {
        Tcl_SetResult(interp, "OpenSSL: HMAC final failed", TCL_STATIC);
        goto cleanup;
    }
    bin2hex(mac, (int)outlen, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    rc = TCL_OK;
cleanup:
    if (ctx) EVP_MAC_CTX_free(ctx);
    if (mac_algo) EVP_MAC_free(mac_algo);
    return rc;
}

// tossl::base64::encode <data>
int Base64EncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &data_len);
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, data_len);
    BIO_flush(bio);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    BIO_free_all(bio);
    return TCL_OK;
}

// tossl::base64::decode <data>
int Base64DecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    const char *data = Tcl_GetString(objv[1]);
    BIO *bio = BIO_new_mem_buf(data, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    unsigned char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len > 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buffer, len));
    } else {
        Tcl_SetResult(interp, "", TCL_STATIC);
    }
    BIO_free_all(bio);
    return TCL_OK;
}

// tossl::base64url::encode <data>
int Base64UrlEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &data_len);
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, data_len);
    BIO_flush(bio);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    char *result = Tcl_Alloc(bptr->length + 1);
    strcpy(result, bptr->data);
    for (int i = 0; result[i]; i++) {
        if (result[i] == '+') result[i] = '-';
        else if (result[i] == '/') result[i] = '_';
    }
    Tcl_SetResult(interp, result, TCL_DYNAMIC);
    BIO_free_all(bio);
    return TCL_OK;
}

// tossl::base64url::decode <data>
int Base64UrlDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    const char *data = Tcl_GetString(objv[1]);
    char *modified = Tcl_Alloc(strlen(data) + 1);
    strcpy(modified, data);
    for (int i = 0; modified[i]; i++) {
        if (modified[i] == '-') modified[i] = '+';
        else if (modified[i] == '_') modified[i] = '/';
    }
    BIO *bio = BIO_new_mem_buf(modified, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    unsigned char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len > 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buffer, len));
    } else {
        Tcl_SetResult(interp, "", TCL_STATIC);
    }
    BIO_free_all(bio);
    Tcl_Free(modified);
    return TCL_OK;
}

// tossl::hex::encode <data>
int HexEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &data_len);
    char *hex = Tcl_Alloc(data_len * 2 + 1);
    bin2hex(data, data_len, hex);
    Tcl_SetResult(interp, hex, TCL_DYNAMIC);
    return TCL_OK;
}

// tossl::hex::decode <data>
int HexDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    const char *hex = Tcl_GetString(objv[1]);
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        Tcl_SetResult(interp, "Invalid hex string length", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char *data = malloc(hex_len / 2);
    for (int i = 0; i < hex_len; i += 2) {
        char byte_str[3] = {hex[i], hex[i+1], '\0'};
        char *endptr;
        data[i/2] = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0') {
            free(data);
            Tcl_SetResult(interp, "Invalid hex string", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(data, hex_len / 2));
    free(data);
    return TCL_OK;
}

// tossl::digest -alg <name> <data>
int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name data");
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[2]);
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &data_len);
    
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, data, data_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hash_len, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    EVP_MD_CTX_free(mdctx);
    return TCL_OK;
}

// tossl::digest::stream -alg <name> <data>
int DigestStreamCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name data");
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[2]);
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &data_len);
    
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const int chunk_size = 1024;
    for (int offset = 0; offset < data_len; offset += chunk_size) {
        int chunk_len = (offset + chunk_size < data_len) ? chunk_size : (data_len - offset);
        if (!EVP_DigestUpdate(mdctx, data + offset, chunk_len)) {
            EVP_MD_CTX_free(mdctx);
            Tcl_SetResult(interp, "OpenSSL: digest update failed", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest final failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hash_len, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    EVP_MD_CTX_free(mdctx);
    return TCL_OK;
}

// tossl::digest::compare <hash1> <hash2>
int DigestCompareCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "hash1 hash2");
        return TCL_ERROR;
    }
    const char *hash1 = Tcl_GetString(objv[1]);
    const char *hash2 = Tcl_GetString(objv[2]);
    
    if (strlen(hash1) != strlen(hash2)) {
        Tcl_SetResult(interp, "0", TCL_STATIC);
        return TCL_OK;
    }
    
    int result = (strcmp(hash1, hash2) == 0) ? 1 : 0;
    Tcl_SetResult(interp, result ? "1" : "0", TCL_STATIC);
    return TCL_OK;
}

// tossl::rand::bytes <count>
int RandBytesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "count");
        return TCL_ERROR;
    }
    int count;
    if (Tcl_GetIntFromObj(interp, objv[1], &count) != TCL_OK) {
        return TCL_ERROR;
    }
    if (count <= 0) {
        Tcl_SetResult(interp, "Count must be positive", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *bytes = malloc(count);
    if (RAND_bytes(bytes, count) != 1) {
        free(bytes);
        Tcl_SetResult(interp, "OpenSSL: random generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(bytes, count));
    free(bytes);
    return TCL_OK;
}

// tossl::rand::key -alg <cipher> ?-len <length>?
int RandKeyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3 && objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher ?-len length?");
        return TCL_ERROR;
    }
    
    const char *cipher = NULL;
    int key_len = 32;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            cipher = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-len") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &key_len) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!cipher) {
        Tcl_SetResult(interp, "Cipher algorithm is required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER *cipher_obj = EVP_CIPHER_fetch(NULL, cipher, NULL);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int actual_key_len = EVP_CIPHER_get_key_length(cipher_obj);
    EVP_CIPHER_free(cipher_obj);
    
    unsigned char *key = malloc(actual_key_len);
    if (RAND_bytes(key, actual_key_len) != 1) {
        free(key);
        Tcl_SetResult(interp, "OpenSSL: random generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, actual_key_len));
    free(key);
    return TCL_OK;
}

// tossl::digest::list
int DigestListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default");
    if (!provider) {
        Tcl_SetResult(interp, "Failed to load default provider", TCL_STATIC);
        return TCL_ERROR;
    }
    
    OSSL_ALGORITHM *algorithms = NULL;
    algorithms = OSSL_PROVIDER_query_operation(provider, OSSL_OP_DIGEST, NULL);
    if (algorithms) {
        for (int i = 0; algorithms[i].algorithm_names != NULL; i++) {
            const char *name = algorithms[i].algorithm_names;
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(name, -1));
        }
        OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_DIGEST, algorithms);
    }
    
    OSSL_PROVIDER_unload(provider);
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

// tossl::rand::iv -alg <cipher>
int RandIvCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher");
        return TCL_ERROR;
    }
    
    const char *cipher = Tcl_GetString(objv[2]);
    EVP_CIPHER *cipher_obj = EVP_CIPHER_fetch(NULL, cipher, NULL);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int iv_len = EVP_CIPHER_get_iv_length(cipher_obj);
    EVP_CIPHER_free(cipher_obj);
    
    if (iv_len <= 0) {
        Tcl_SetResult(interp, "Cipher does not require IV", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *iv = malloc(iv_len);
    if (RAND_bytes(iv, iv_len) != 1) {
        free(iv);
        Tcl_SetResult(interp, "OpenSSL: random generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(iv, iv_len));
    free(iv);
    return TCL_OK;
}

// tossl::pbkdf2 -pass <password> -salt <salt> -iter <iterations> -len <length> ?-alg <digest>?
int Pbkdf2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 9 || (objc % 2) == 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "-password/-pass password -salt salt -iterations/-iter iterations -keylen/-len length -digest/-alg digest");
        return TCL_ERROR;
    }
    
    const char *password = NULL, *salt = NULL, *alg = "sha256";
    int iterations = 0, length = 0;
    int pass_len = 0, salt_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcasecmp(opt, "-pass") == 0 || strcasecmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &pass_len);
        } else if (strcasecmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcasecmp(opt, "-iter") == 0 || strcasecmp(opt, "-iterations") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &iterations) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-len") == 0 || strcasecmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &length) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-alg") == 0 || strcasecmp(opt, "-digest") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || iterations <= 0 || length <= 0) {
        Tcl_SetResult(interp, "All parameters are required and must be positive", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = malloc(length);
    if (PKCS5_PBKDF2_HMAC(password, pass_len, (const unsigned char *)salt, salt_len, 
                          iterations, md, length, key) != 1) {
        free(key);
        Tcl_SetResult(interp, "OpenSSL: PBKDF2 failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, length));
    free(key);
    return TCL_OK;
}

// tossl::scrypt -pass <password> -salt <salt> -n <N> -r <r> -p <p> -len <length>
int ScryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pass password -salt salt -n N -r r -p p -len length");
        return TCL_ERROR;
    }
    
    const char *password = NULL, *salt = NULL;
    int pass_len = 0, salt_len = 0;
    uint64_t N = 0, r = 0, p = 0;
    int length = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcasecmp(opt, "-pass") == 0 || strcasecmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &pass_len);
        } else if (strcasecmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcasecmp(opt, "-n") == 0) {
            if (Tcl_GetWideIntFromObj(interp, objv[i+1], (Tcl_WideInt*)&N) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-r") == 0) {
            if (Tcl_GetWideIntFromObj(interp, objv[i+1], (Tcl_WideInt*)&r) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-p") == 0) {
            if (Tcl_GetWideIntFromObj(interp, objv[i+1], (Tcl_WideInt*)&p) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-len") == 0 || strcasecmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &length) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || N == 0 || r == 0 || p == 0 || length <= 0) {
        Tcl_SetResult(interp, "All parameters are required and must be positive", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = malloc(length);
    if (EVP_PBE_scrypt(password, pass_len, (const unsigned char *)salt, salt_len, 
                       N, r, p, 0, key, length) != 1) {
        free(key);
        Tcl_SetResult(interp, "OpenSSL: scrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, length));
    free(key);
    return TCL_OK;
}

// tossl::argon2 -pass <password> -salt <salt> -t <time> -m <memory> -p <parallel> -len <length>
int Argon2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pass password -salt salt -t time -m memory -p parallel -len length");
        return TCL_ERROR;
    }
    
    const char *password = NULL, *salt = NULL;
    int pass_len = 0, salt_len = 0;
    uint32_t time_cost = 0, memory_cost = 0, parallelism = 0;
    int length = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcasecmp(opt, "-pass") == 0 || strcasecmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &pass_len);
        } else if (strcasecmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcasecmp(opt, "-t") == 0 || strcasecmp(opt, "-time") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], (int*)&time_cost) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-m") == 0 || strcasecmp(opt, "-memory") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], (int*)&memory_cost) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-p") == 0 || strcasecmp(opt, "-parallel") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], (int*)&parallelism) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcasecmp(opt, "-len") == 0 || strcasecmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &length) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || time_cost == 0 || memory_cost == 0 || parallelism == 0 || length <= 0) {
        Tcl_SetResult(interp, "All parameters are required and must be positive", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = malloc(length);
    if (EVP_PBE_scrypt(password, pass_len, (const unsigned char *)salt, salt_len, 
                       time_cost, memory_cost, parallelism, 0, key, length) != 1) {
        free(key);
        Tcl_SetResult(interp, "OpenSSL: Argon2 not supported in this build", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, length));
    free(key);
    return TCL_OK;
}

// tossl::cipher::info -alg <cipher>
int CipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher");
        return TCL_ERROR;
    }
    
    const char *cipher = Tcl_GetString(objv[2]);
    EVP_CIPHER *cipher_obj = EVP_CIPHER_fetch(NULL, cipher, NULL);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("name", -1), Tcl_NewStringObj(cipher, -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("block_size", -1), Tcl_NewIntObj(EVP_CIPHER_get_block_size(cipher_obj)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_length", -1), Tcl_NewIntObj(EVP_CIPHER_get_key_length(cipher_obj)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iv_length", -1), Tcl_NewIntObj(EVP_CIPHER_get_iv_length(cipher_obj)));
    
    EVP_CIPHER_free(cipher_obj);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// Helper: case-insensitive substring search
static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    size_t hlen = strlen(haystack), nlen = strlen(needle);
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        if (strncasecmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

// Helper for EVP_CIPHER_do_all_provided
struct CipherListCtx {
    Tcl_Interp *interp;
    Tcl_Obj *list;
    const char *type_filter;
};

static void cipher_list_cb(const EVP_CIPHER *cipher, void *arg) {
    struct CipherListCtx *ctx = (struct CipherListCtx *)arg;
    const char *name = EVP_CIPHER_get0_name(cipher);
    if (name && (!ctx->type_filter || contains_case_insensitive(name, ctx->type_filter))) {
        Tcl_ListObjAppendElement(ctx->interp, ctx->list, Tcl_NewStringObj(name, -1));
    }
}

int CipherListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *type_filter = NULL;
    if (objc == 3 && strcmp(Tcl_GetString(objv[1]), "-type") == 0) {
        type_filter = Tcl_GetString(objv[2]);
    } else if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-type type?");
        return TCL_ERROR;
    }
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    struct CipherListCtx ctx = { interp, list, type_filter };
    EVP_CIPHER_do_all_provided(NULL, cipher_list_cb, &ctx);
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

// tossl::encrypt -alg <cipher> -key <key> -iv <iv> <data>
int EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    fprintf(stderr, "[DEBUG] EncryptCmd called: objc=%d\n", objc);
    for (int i = 0; i < objc; ++i) {
        int arglen = 0;
        const unsigned char *argstr = (const unsigned char *)Tcl_GetStringFromObj(objv[i], &arglen);
        fprintf(stderr, "[DEBUG] arg %d: len=%d, str=\"%.*s\"\n", i, arglen, arglen, argstr);
        // Print hex dump for binary args
        fprintf(stderr, "[DEBUG] arg %d hex: ", i);
        for (int j = 0; j < arglen; ++j) {
            fprintf(stderr, "%02x", argstr[j]);
        }
        fprintf(stderr, "\n");
    }
    if (objc != 8) {
        fprintf(stderr, "[DEBUG] ERROR: wrong # args, expected 8 (including command name), got %d\n", objc);
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher -key key -iv iv data");
        return TCL_ERROR;
    }
    
    const char *cipher = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    int key_len = 0, iv_len = 0, data_len = 0;
    
    for (int i = 1; i < 6; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        fprintf(stderr, "[DEBUG] parsing arg %d: option '%s'\n", i, opt);
        if (strcmp(opt, "-alg") == 0) {
            cipher = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &key_len);
            fprintf(stderr, "[DEBUG] key arg %d: len=%d, hex=", i+1, key_len);
            for (int j = 0; j < key_len; ++j) fprintf(stderr, "%02x", key[j]);
            fprintf(stderr, "\n");
        } else if (strcmp(opt, "-iv") == 0) {
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &iv_len);
            fprintf(stderr, "[DEBUG] iv arg %d: len=%d, hex=", i+1, iv_len);
            for (int j = 0; j < iv_len; ++j) fprintf(stderr, "%02x", iv[j]);
            fprintf(stderr, "\n");
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[7], &data_len);
    
    const EVP_CIPHER *cipher_obj = EVP_get_cipherbyname(cipher);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "[DEBUG] EncryptCmd cipher: %s, block_size=%d, key_len=%d, iv_len=%d\n", 
            EVP_CIPHER_get0_name(cipher_obj), EVP_CIPHER_get_block_size(cipher_obj),
            EVP_CIPHER_get_key_length(cipher_obj), EVP_CIPHER_get_iv_length(cipher_obj));
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!EVP_EncryptInit_ex2(ctx, cipher_obj, key, iv, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: encryption init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *out = malloc(data_len + EVP_CIPHER_get_block_size(cipher_obj));
    int out_len = 0;
    fprintf(stderr, "[DEBUG] EncryptCmd data hex: ");
    for (int i = 0; i < data_len; ++i) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
    if (!EVP_EncryptUpdate(ctx, out, &out_len, data, data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: encryption update failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len = 0;
    if (!EVP_EncryptFinal_ex(ctx, out + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: encryption final failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, out_len + final_len));
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_obj);
    return TCL_OK;
}

// tossl::decrypt -alg <cipher> -key <key> -iv <iv> <data>
int DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    fprintf(stderr, "[DEBUG] DecryptCmd called: objc=%d\n", objc);
    for (int i = 0; i < objc; ++i) {
        int arglen = 0;
        unsigned char *argbytes = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &arglen);
        fprintf(stderr, "[DEBUG] arg %d: len=%d, hex=", i, arglen);
        for (int j = 0; j < arglen; ++j) {
            fprintf(stderr, "%02x", argbytes[j]);
        }
        fprintf(stderr, "\n");
    }
    if (objc != 8) {
        fprintf(stderr, "[DEBUG] ERROR: wrong # args, expected 8 (including command name), got %d\n", objc);
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher -key key -iv iv data");
        return TCL_ERROR;
    }
    
    const char *cipher = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    int key_len = 0, iv_len = 0, data_len = 0;
    
    for (int i = 1; i < 6; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        fprintf(stderr, "[DEBUG] parsing arg %d: option '%s'\n", i, opt);
        if (strcmp(opt, "-alg") == 0) {
            cipher = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &key_len);
            fprintf(stderr, "[DEBUG] key arg %d: len=%d, hex=", i+1, key_len);
            for (int j = 0; j < key_len; ++j) fprintf(stderr, "%02x", key[j]);
            fprintf(stderr, "\n");
        } else if (strcmp(opt, "-iv") == 0) {
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &iv_len);
            fprintf(stderr, "[DEBUG] iv arg %d: len=%d, hex=", i+1, iv_len);
            for (int j = 0; j < iv_len; ++j) fprintf(stderr, "%02x", iv[j]);
            fprintf(stderr, "\n");
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    // Debug: print key and IV hex
    fprintf(stderr, "[DEBUG] DecryptCmd key hex: ");
    for (int i = 0; i < key_len; ++i) fprintf(stderr, "%02x", key[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[DEBUG] DecryptCmd IV hex: ");
    for (int i = 0; i < iv_len; ++i) fprintf(stderr, "%02x", iv[i]);
    fprintf(stderr, "\n");
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[7], &data_len);
    
    const EVP_CIPHER *cipher_obj = EVP_get_cipherbyname(cipher);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "[DEBUG] DecryptCmd cipher: %s, block_size=%d, key_len=%d, iv_len=%d\n", 
            EVP_CIPHER_get0_name(cipher_obj), EVP_CIPHER_get_block_size(cipher_obj),
            EVP_CIPHER_get_key_length(cipher_obj), EVP_CIPHER_get_iv_length(cipher_obj));
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "[DEBUG] Default OpenSSL padding is used (PKCS#7 for block ciphers)\n");
    if (!EVP_DecryptInit_ex2(ctx, cipher_obj, key, iv, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: decryption init failed", TCL_STATIC);
        fprintf(stderr, "[DEBUG] OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return TCL_ERROR;
    }
    // Allocate output buffer large enough for decrypted data (with padding)
    unsigned char *out = malloc(data_len + EVP_CIPHER_get_block_size(cipher_obj));
    int out_len = 0;
    fprintf(stderr, "[DEBUG] DecryptCmd data hex: ");
    for (int i = 0; i < data_len; ++i) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
    if (!EVP_DecryptUpdate(ctx, out, &out_len, data, data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        free(out);
        Tcl_SetResult(interp, "OpenSSL: decryption update failed", TCL_STATIC);
        fprintf(stderr, "[DEBUG] OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return TCL_ERROR;
    }
    int final_len = 0;
    if (!EVP_DecryptFinal_ex(ctx, out + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher_obj);
        free(out);
        Tcl_SetResult(interp, "OpenSSL: decryption final failed", TCL_STATIC);
        fprintf(stderr, "[DEBUG] OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return TCL_ERROR;
    }
    fprintf(stderr, "[DEBUG] Decrypt output: out_len=%d, final_len=%d\n", out_len, final_len);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, out_len + final_len));
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_obj);
    return TCL_OK;
} 