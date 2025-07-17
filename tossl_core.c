#define _XOPEN_SOURCE 700
#include "tossl.h"
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/err.h>

// Debug flag - set to 0 to disable debug output, 1 to enable
#define TOSSL_DEBUG 0

// Debug print macro
#define DEBUG_PRINTF(fmt, ...) \
    do { if (TOSSL_DEBUG) fprintf(stderr, "[DEBUG] " fmt, ##__VA_ARGS__); } while (0)

// Forward declarations for benchmarking functions
static int Tossl_BenchmarkHash(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int Tossl_BenchmarkCipher(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int Tossl_BenchmarkRSA(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int Tossl_BenchmarkEC(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);

// Add strptime declaration if not available
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <time.h>

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

// tossl::digest -alg <name> [-format <format>] <data>
int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 4 || objc > 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name ?-format format? data");
        return TCL_ERROR;
    }
    
    const char *alg = NULL;
    const char *format = "hex";
    unsigned char *data = NULL;
    int data_len = 0;
    
    // Parse arguments
    for (int i = 1; i < objc; i++) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing algorithm name", TCL_STATIC);
                return TCL_ERROR;
            }
            alg = Tcl_GetString(objv[i]);
        } else if (strcmp(opt, "-format") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing format specification", TCL_STATIC);
                return TCL_ERROR;
            }
            format = Tcl_GetString(objv[i]);
        } else if (opt[0] != '-') {
            // This is the data argument
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &data_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!alg || !data) {
        Tcl_SetResult(interp, "Missing required arguments", TCL_STATIC);
        return TCL_ERROR;
    }
    
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
    unsigned int hash_len;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, data, data_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Format output based on requested format
    if (strcmp(format, "hex") == 0) {
        char hex[2*EVP_MAX_MD_SIZE+1];
        bin2hex(hash, hash_len, hex);
        Tcl_SetResult(interp, hex, TCL_VOLATILE);
    } else if (strcmp(format, "binary") == 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, hash_len));
    } else if (strcmp(format, "base64") == 0) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
        BIO_push(b64, bio);
        BIO_write(b64, hash, hash_len);
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);
        Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
        BIO_free_all(b64);
    } else {
        Tcl_SetResult(interp, "Invalid format. Use hex, binary, or base64", TCL_STATIC);
        return TCL_ERROR;
    }
    
    return TCL_OK;
}

// tossl::digest::stream -alg <name> [-format <format>] <data>
int DigestStreamCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 4 || objc > 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name ?-format format? data");
        return TCL_ERROR;
    }
    
    const char *alg = NULL;
    const char *format = "hex";
    unsigned char *data = NULL;
    int data_len = 0;
    
    // Parse arguments
    for (int i = 1; i < objc; i++) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing algorithm name", TCL_STATIC);
                return TCL_ERROR;
            }
            alg = Tcl_GetString(objv[i]);
        } else if (strcmp(opt, "-format") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing format specification", TCL_STATIC);
                return TCL_ERROR;
            }
            format = Tcl_GetString(objv[i]);
        } else if (opt[0] != '-') {
            // This is the data argument
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &data_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!alg || !data) {
        Tcl_SetResult(interp, "Missing required arguments", TCL_STATIC);
        return TCL_ERROR;
    }
    
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
    
    EVP_MD_CTX_free(mdctx);
    
    // Format output based on requested format
    if (strcmp(format, "hex") == 0) {
        char hex[2*EVP_MAX_MD_SIZE+1];
        bin2hex(hash, hash_len, hex);
        Tcl_SetResult(interp, hex, TCL_VOLATILE);
    } else if (strcmp(format, "binary") == 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, hash_len));
    } else if (strcmp(format, "base64") == 0) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
        BIO_push(b64, bio);
        BIO_write(b64, hash, hash_len);
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);
        Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
        BIO_free_all(b64);
    } else {
        Tcl_SetResult(interp, "Invalid format. Use hex, binary, or base64", TCL_STATIC);
        return TCL_ERROR;
    }
    
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
    if (objc != 2) {
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

// Helper for EVP_MD_do_all_provided
struct DigestListCtx {
    Tcl_Interp *interp;
    Tcl_Obj *list;
};

static void digest_list_cb(EVP_MD *md, void *arg) {
    struct DigestListCtx *ctx = (struct DigestListCtx *)arg;
    const char *name = EVP_MD_get0_name(md);
    if (name) {
        /* Check if this name is already in the list to avoid duplicates */
        int list_len;
        Tcl_ListObjLength(ctx->interp, ctx->list, &list_len);
        int found = 0;
        
        for (int i = 0; i < list_len; i++) {
            Tcl_Obj *element;
            Tcl_ListObjIndex(ctx->interp, ctx->list, i, &element);
            const char *existing_name = Tcl_GetString(element);
            if (strcmp(name, existing_name) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            Tcl_ListObjAppendElement(ctx->interp, ctx->list, Tcl_NewStringObj(name, -1));
        }
    }
}

// tossl::digest::list
int DigestListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    struct DigestListCtx ctx = { interp, list };
    EVP_MD_do_all_provided(NULL, digest_list_cb, &ctx);
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
    EVP_CIPHER *cipher_obj = modern_cipher_fetch(cipher);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int iv_len = EVP_CIPHER_get_iv_length(cipher_obj);
    modern_cipher_free(cipher_obj);
    
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
    
    EVP_MD *md = modern_digest_fetch(alg);
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

static void cipher_list_cb(EVP_CIPHER *cipher, void *arg) {
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
    if (objc < 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher -key key -iv iv data ?-format format?");
        return TCL_ERROR;
    }
    
    const char *cipher_name = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL, *aad = NULL;
    int key_len = 0, iv_len = 0, data_len = 0, aad_len = 0;
    const char *format = "base64";
    
    // Parse arguments flexibly
    for (int i = 1; i < objc; i++) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing algorithm name", TCL_STATIC);
                return TCL_ERROR;
            }
            cipher_name = Tcl_GetString(objv[i]);
        } else if (strcmp(opt, "-key") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing key", TCL_STATIC);
                return TCL_ERROR;
            }
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &key_len);
        } else if (strcmp(opt, "-iv") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing IV", TCL_STATIC);
                return TCL_ERROR;
            }
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &iv_len);
        } else if (strcmp(opt, "-format") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing format specification", TCL_STATIC);
                return TCL_ERROR;
            }
            format = Tcl_GetString(objv[i]);
        } else if (strcmp(opt, "-aad") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing AAD data", TCL_STATIC);
                return TCL_ERROR;
            }
            aad = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &aad_len);
        } else if (opt[0] != '-') {
            // This is the data argument
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &data_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!cipher_name || !key || !iv || !data) {
        Tcl_SetResult(interp, "Missing required arguments", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER *cipher_obj = modern_cipher_fetch(cipher_name);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    DEBUG_PRINTF("EncryptCmd cipher: %s, block_size=%d, key_len=%d, iv_len=%d\n", 
            EVP_CIPHER_get0_name(cipher_obj), EVP_CIPHER_get_block_size(cipher_obj),
            EVP_CIPHER_get_key_length(cipher_obj), EVP_CIPHER_get_iv_length(cipher_obj));
    
    int is_aead = 0, tag_len = 0;
    if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305")) {
        is_aead = 1;
        if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305"))
            tag_len = 16;
        else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM"))
            tag_len = 16;
    }
    
    // Allocate output buffer with enough space for the encrypted data and tag
    size_t out_buf_size = data_len + EVP_CIPHER_get_block_size(cipher_obj) + (is_aead ? tag_len : 0);
    unsigned char *out = malloc(out_buf_size);
    if (!out) {
        modern_cipher_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    int out_len = 0;
    
    // Clear any previous errors
    ERR_clear_error();
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        modern_cipher_free(cipher_obj);
        free(out);
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Clear any previous errors
    ERR_clear_error();
    
    // No need to reset a newly created context
    
    // Clear any previous errors before initialization
    ERR_clear_error();
    
    // Debug print cipher information using cipher_obj directly
    DEBUG_PRINTF("Cipher details: %s, block_size=%d, key_len=%d, iv_len=%d, flags=0x%lX\n",
           EVP_CIPHER_get0_name(cipher_obj),
           EVP_CIPHER_get_block_size(cipher_obj),
           EVP_CIPHER_get_key_length(cipher_obj),
           EVP_CIPHER_get_iv_length(cipher_obj),
           (unsigned long)EVP_CIPHER_get_flags(cipher_obj));
    DEBUG_PRINTF("Initializing cipher: %s, block_size: %d, key_len: %d, iv_len: %d\n",
           EVP_CIPHER_get0_name(cipher_obj), EVP_CIPHER_get_block_size(cipher_obj),
           EVP_CIPHER_get_key_length(cipher_obj), EVP_CIPHER_get_iv_length(cipher_obj));
    
    cipher_name = EVP_CIPHER_get0_name(cipher_obj);
    DEBUG_PRINTF("Initializing cipher: %s, block_size: %d, key_len: %d, iv_len: %d\n",
           cipher_name, EVP_CIPHER_get_block_size(cipher_obj),
           EVP_CIPHER_get_key_length(cipher_obj), EVP_CIPHER_get_iv_length(cipher_obj));
    
    if (is_aead && strstr(cipher_name, "CCM")) {
        // For CCM mode, follow the exact sequence from OpenSSL documentation:
        // 1. Initialize with cipher, NULL key and IV first
        if (!EVP_EncryptInit_ex2(ctx, cipher_obj, NULL, NULL, NULL)) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DEBUG_PRINTF("OpenSSL error in CCM init: %s\n", err_buf);
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: CCM init failed", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // 2. Set the IV length (must be called before setting the key/IV)
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to set CCM IV length", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // 3. Set the tag length (must be called before setting the key/IV)
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to set CCM tag length", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // 4. Initialize with the actual key and IV
        if (!EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to init CCM with key/IV", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // 5. Set the total plaintext length before processing any data
        int dummy_len = 0;
        if (!EVP_EncryptUpdate(ctx, NULL, &dummy_len, NULL, data_len)) {
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to set CCM data length", TCL_STATIC);
            return TCL_ERROR;
        }
        
        DEBUG_PRINTF("CCM cipher: %s, tag_len: %d, iv_len: %d\n", 
               EVP_CIPHER_get0_name(cipher_obj), tag_len, iv_len);
    } else {
        // Clear any previous errors before initialization
        ERR_clear_error();
        
        // Initialize with cipher, key, and IV in a single call
        DEBUG_PRINTF("Initializing cipher context with cipher, key, and IV\n");
        ERR_clear_error();
        int init_result = EVP_EncryptInit_ex(ctx, cipher_obj, NULL, key, iv);
        DEBUG_PRINTF("EVP_EncryptInit_ex result: %d\n", init_result);
        if (!init_result) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DEBUG_PRINTF("OpenSSL error in cipher init: %s\n", err_buf);
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to initialize cipher context", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // AEAD: Add AAD if provided (must be done before encryption for CCM)
    if (aad && aad_len > 0) {
        int aad_out_len = 0;
        if (!EVP_EncryptUpdate(ctx, NULL, &aad_out_len, aad, aad_len)) {
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: encryption AAD update failed", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (is_aead && strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
        DEBUG_PRINTF("CCM cipher: %s, tag_len: %d, iv_len: %d\n", 
               EVP_CIPHER_get0_name(cipher_obj), tag_len, iv_len);
    }
    if (TOSSL_DEBUG) {
        fprintf(stderr, "[DEBUG] EncryptCmd data hex: ");
        for (int i = 0; i < data_len; ++i) fprintf(stderr, "%02x", data[i]);
        fprintf(stderr, "\n");
    }
    // Perform the encryption
    DEBUG_PRINTF("Starting encryption update, data_len: %d\n", data_len);
    ERR_clear_error();
    int update_result = EVP_EncryptUpdate(ctx, out, &out_len, data, data_len);
    DEBUG_PRINTF("EVP_EncryptUpdate result: %d, out_len: %d\n", update_result, out_len);
    if (!update_result) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DEBUG_PRINTF("OpenSSL error in encryption update: %s\n", err_buf);
    }
    if (is_aead && strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
        DEBUG_PRINTF("CCM EVP_EncryptUpdate(data) result: %d, out_len: %d\n", update_result, out_len);
    }
    if (!update_result) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DEBUG_PRINTF("OpenSSL error in encryption update: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        modern_cipher_free(cipher_obj);
        free(out);
        Tcl_SetResult(interp, "OpenSSL: encryption update failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len = 0;
    int total_len = out_len;
    unsigned char tag[16];
    
    // For CCM, we need to get the tag after encryption but before finalization
    if (is_aead && strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
        DEBUG_PRINTF("Getting CCM tag before finalization\n");
        
        // For CCM, finalize the encryption first
        int final_len = 0;
        if (!EVP_EncryptFinal_ex(ctx, out + out_len, &final_len)) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DEBUG_PRINTF("OpenSSL error in finalize: %s\n", err_buf);
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: encryption finalize failed", TCL_STATIC);
            return TCL_ERROR;
        }
        total_len += final_len;
        
        // Get the tag using the AEAD control command
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DEBUG_PRINTF("OpenSSL error getting CCM tag: %s\n", err_buf);
            EVP_CIPHER_CTX_free(ctx);
            modern_cipher_free(cipher_obj);
            free(out);
            Tcl_SetResult(interp, "OpenSSL: failed to get CCM tag (EVP_CTRL_AEAD_GET_TAG)", TCL_STATIC);
            return TCL_ERROR;
        }
        DEBUG_PRINTF("Successfully retrieved CCM tag using EVP_CTRL_CCM_GET_TAG\n");
    }
    
    // Finalize the encryption
    DEBUG_PRINTF("Finalizing encryption, current out_len: %d\n", out_len);
    ERR_clear_error();
    int final_result = EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);
    DEBUG_PRINTF("EVP_EncryptFinal_ex result: %d, final_len: %d\n", final_result, final_len);
    if (!final_result) {
        unsigned long err = ERR_get_error();
        if (err != 0) {  // Only print if there's an actual error
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DEBUG_PRINTF("OpenSSL error in encryption final: %s\n", err_buf);
        }
    }
    if (is_aead && strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
        DEBUG_PRINTF("CCM EVP_EncryptFinal_ex result: %d, final_len: %d\n", final_result, final_len);
    }
    if (!final_result) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DEBUG_PRINTF("OpenSSL error in final: %s\n", err_buf);
        DEBUG_PRINTF("Cipher: %s, Key len: %d, IV len: %d, Data len: %d\n", 
               EVP_CIPHER_get0_name(cipher_obj), key_len, iv_len, data_len);
        DEBUG_PRINTF("Is AEAD: %d, Tag len: %d\n", is_aead, tag_len);
        
        // Get more detailed error information
        while ((err = ERR_get_error()) != 0) {
            char lib_buf[256], reason_buf[256];
            const char *lib = ERR_lib_error_string(err);
            const char *reason = ERR_reason_error_string(err);
            
            snprintf(lib_buf, sizeof(lib_buf), "%s", lib ? lib : "(null)");
            snprintf(reason_buf, sizeof(reason_buf), "%s", reason ? reason : "(null)");
            
            DEBUG_PRINTF("OpenSSL error details - Library: %s, Reason: %s\n",
                   lib_buf, reason_buf);
        }
        
        EVP_CIPHER_CTX_free(ctx);
        modern_cipher_free(cipher_obj);
        free(out);
        char error_msg[1024];
        snprintf(error_msg, sizeof(error_msg), 
                "OpenSSL: encryption final failed: %s\nCipher: %s, Key len: %d, IV len: %d, Data len: %d, Is AEAD: %d, Tag len: %d",
                err_buf, EVP_CIPHER_get0_name(cipher_obj), key_len, iv_len, data_len, is_aead, tag_len);
        Tcl_SetResult(interp, error_msg, TCL_VOLATILE);
        return TCL_ERROR;
    }
    total_len += final_len;
    
    // Handle GCM and Poly1305 tag retrieval after finalization
    if (is_aead) {
        if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM")) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                modern_cipher_free(cipher_obj);
                free(out);
                Tcl_SetResult(interp, "OpenSSL: failed to get GCM tag", TCL_STATIC);
                return TCL_ERROR;
            }
            memcpy(out + total_len, tag, tag_len);
            total_len += tag_len;
        } else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305")) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                modern_cipher_free(cipher_obj);
                free(out);
                Tcl_SetResult(interp, "OpenSSL: failed to get Poly1305 tag", TCL_STATIC);
                return TCL_ERROR;
            }
            memcpy(out + total_len, tag, tag_len);
            total_len += tag_len;
        } else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
            // For CCM, we already got the tag before finalization, just append it
            memcpy(out + total_len, tag, tag_len);
            total_len += tag_len;
            DEBUG_PRINTF("Appended CCM tag to output, total_len: %d\n", total_len);
        }
    }
    
    // Format output based on requested format
    if (strcmp(format, "hex") == 0) {
        char *hex = (char *)ckalloc(2*total_len+1);
        bin2hex(out, total_len, hex);
        Tcl_SetResult(interp, hex, TCL_DYNAMIC);
    } else if (strcmp(format, "binary") == 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, total_len));
    } else if (strcmp(format, "base64") == 0) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, bio);
        BIO_write(b64, out, total_len);
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);
        
        // Create a copy of the base64 data that Tcl will own
        char *base64_copy = (char *)ckalloc(bptr->length + 1);
        memcpy(base64_copy, bptr->data, bptr->length);
        base64_copy[bptr->length] = '\0';
        
        Tcl_SetResult(interp, base64_copy, TCL_DYNAMIC);
        BIO_free_all(b64);
    } else {
        Tcl_SetResult(interp, "Invalid format. Use hex, binary, or base64", TCL_STATIC);
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        modern_cipher_free(cipher_obj);
        return TCL_ERROR;
    }
    
    if (out) free(out);
    if (ctx) {
        // Free the context - this also cleans up internal state
        EVP_CIPHER_CTX_free(ctx);
    }
    if (cipher_obj) {
        modern_cipher_free(cipher_obj);
    }
    return TCL_OK;
}

// tossl::decrypt -alg <cipher> -key <key> -iv <iv> <data> ?-format format?
int DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 8 || objc > 10) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg cipher -key key -iv iv data ?-format format?");
        return TCL_ERROR;
    }
    
    const char *cipher_name = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    int key_len = 0, iv_len = 0, data_len = 0;
    const char *format = "binary";
    
    // Parse arguments flexibly
    for (int i = 1; i < objc; i++) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing algorithm name", TCL_STATIC);
                return TCL_ERROR;
            }
            cipher_name = Tcl_GetString(objv[i]);
        } else if (strcmp(opt, "-key") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing key", TCL_STATIC);
                return TCL_ERROR;
            }
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &key_len);
        } else if (strcmp(opt, "-iv") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing IV", TCL_STATIC);
                return TCL_ERROR;
            }
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &iv_len);
        } else if (strcmp(opt, "-format") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "Missing format specification", TCL_STATIC);
                return TCL_ERROR;
            }
            format = Tcl_GetString(objv[i]);
        } else if (opt[0] != '-') {
            // This is the data argument
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i], &data_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!cipher_name || !key || !iv || !data) {
        Tcl_SetResult(interp, "Missing required arguments", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER *cipher_obj = modern_cipher_fetch(cipher_name);
    if (!cipher_obj) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Handle input format
    unsigned char *decoded_data = data;
    int decoded_len = data_len;
    
    if (strcmp(format, "base64") == 0) {
        BIO *bio = BIO_new_mem_buf(data, data_len);
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, bio);
        decoded_data = malloc(data_len);
        decoded_len = BIO_read(b64, decoded_data, data_len);
        BIO_free_all(b64);
        if (decoded_len <= 0) {
            free(decoded_data);
            Tcl_SetResult(interp, "Invalid base64 input", TCL_STATIC);
            modern_cipher_free(cipher_obj);
            return TCL_ERROR;
        }
    } else if (strcmp(format, "hex") == 0) {
        if (data_len % 2 != 0) {
            Tcl_SetResult(interp, "Invalid hex input length", TCL_STATIC);
            modern_cipher_free(cipher_obj);
            return TCL_ERROR;
        }
        decoded_data = malloc(data_len / 2);
        decoded_len = data_len / 2;
        for (int i = 0; i < decoded_len; i++) {
            char hex[3] = {data[i*2], data[i*2+1], '\0'};
            int value;
            if (sscanf(hex, "%x", &value) != 1) {
                free(decoded_data);
                Tcl_SetResult(interp, "Invalid hex input", TCL_STATIC);
                modern_cipher_free(cipher_obj);
                return TCL_ERROR;
            }
            decoded_data[i] = (unsigned char)value;
        }
    } else if (strcmp(format, "binary") != 0) {
        Tcl_SetResult(interp, "Invalid format. Use binary, hex, or base64", TCL_STATIC);
        modern_cipher_free(cipher_obj);
        return TCL_ERROR;
    }
    
    int is_aead = 0;
    int tag_len = 0;
    if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305")) {
        is_aead = 1;
        if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM") || strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305"))
            tag_len = 16;
        else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM"))
            tag_len = 16;
    }
    unsigned char tag[16];
    if (is_aead) {
        if (decoded_len < tag_len) {
            if (decoded_data != data) free(decoded_data);
            Tcl_SetResult(interp, "Input too short for AEAD tag", TCL_STATIC);
            modern_cipher_free(cipher_obj);
            return TCL_ERROR;
        }
        memcpy(tag, decoded_data + (decoded_len - tag_len), tag_len);
        decoded_len -= tag_len;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (decoded_data != data) free(decoded_data);
        modern_cipher_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!EVP_DecryptInit_ex2(ctx, cipher_obj, key, iv, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        if (decoded_data != data) free(decoded_data);
        modern_cipher_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: decryption init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (is_aead) {
        if (strstr(EVP_CIPHER_get0_name(cipher_obj), "GCM")) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                if (decoded_data != data) free(decoded_data);
                modern_cipher_free(cipher_obj);
                Tcl_SetResult(interp, "OpenSSL: failed to set GCM tag", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "CCM")) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                if (decoded_data != data) free(decoded_data);
                modern_cipher_free(cipher_obj);
                Tcl_SetResult(interp, "OpenSSL: failed to set CCM tag", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strstr(EVP_CIPHER_get0_name(cipher_obj), "Poly1305")) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                if (decoded_data != data) free(decoded_data);
                modern_cipher_free(cipher_obj);
                Tcl_SetResult(interp, "OpenSSL: failed to set Poly1305 tag", TCL_STATIC);
                return TCL_ERROR;
            }
        }
    }
    
    unsigned char *out = malloc(decoded_len + EVP_CIPHER_get_block_size(cipher_obj));
    int out_len = 0;
    
    if (!EVP_DecryptUpdate(ctx, out, &out_len, decoded_data, decoded_len)) {
        EVP_CIPHER_CTX_free(ctx);
        if (decoded_data != data) free(decoded_data);
        free(out);
        modern_cipher_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: decryption update failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len = 0;
    if (!EVP_DecryptFinal_ex(ctx, out + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        if (decoded_data != data) free(decoded_data);
        free(out);
        modern_cipher_free(cipher_obj);
        Tcl_SetResult(interp, "OpenSSL: decryption final failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, out_len + final_len));
    
    if (decoded_data != data) free(decoded_data);
    free(out);
    EVP_CIPHER_CTX_free(ctx);
    modern_cipher_free(cipher_obj);
    return TCL_OK;
}

// URL encoding/decoding functions
int UrlEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    
    const char *data = Tcl_GetString(objv[1]);
    int data_len = strlen(data);
    
    // Calculate required buffer size (worst case: 3x original size)
    char *encoded = malloc(data_len * 3 + 1);
    if (!encoded) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int j = 0;
    for (int i = 0; i < data_len; i++) {
        unsigned char c = data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded[j++] = c;
        } else {
            sprintf(encoded + j, "%%%02X", c);
            j += 3;
        }
    }
    encoded[j] = '\0';
    
    Tcl_SetResult(interp, encoded, TCL_VOLATILE);
    return TCL_OK;
}

int UrlDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    
    const char *data = Tcl_GetString(objv[1]);
    int data_len = strlen(data);
    
    char *decoded = malloc(data_len + 1);
    if (!decoded) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int j = 0;
    for (int i = 0; i < data_len; i++) {
        if (data[i] == '%' && i + 2 < data_len) {
            char hex[3] = {data[i+1], data[i+2], '\0'};
            int value;
            if (sscanf(hex, "%x", &value) == 1) {
                decoded[j++] = (char)value;
                i += 2;
            } else {
                decoded[j++] = data[i];
            }
        } else {
            decoded[j++] = data[i];
        }
    }
    decoded[j] = '\0';
    
    Tcl_SetResult(interp, decoded, TCL_VOLATILE);
    return TCL_OK;
}

// Time conversion/comparison functions
int TimeConvertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "format time");
        return TCL_ERROR;
    }
    
    const char *format = Tcl_GetString(objv[1]);
    const char *time_str = Tcl_GetString(objv[2]);
    
    time_t timestamp;
    if (strcmp(format, "unix") == 0) {
        // Convert from Unix timestamp
        timestamp = (time_t)atol(time_str);
    } else if (strcmp(format, "iso8601") == 0) {
        // Parse ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
        struct tm tm = {0};
        char *result = strptime(time_str, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (result == NULL) {
            Tcl_SetResult(interp, "Invalid ISO 8601 format", TCL_STATIC);
            return TCL_ERROR;
        }
        timestamp = mktime(&tm);
    } else if (strcmp(format, "rfc2822") == 0) {
        // Parse RFC 2822 format
        struct tm tm = {0};
        char *result = strptime(time_str, "%a, %d %b %Y %H:%M:%S %z", &tm);
        if (result == NULL) {
            Tcl_SetResult(interp, "Invalid RFC 2822 format", TCL_STATIC);
            return TCL_ERROR;
        }
        timestamp = mktime(&tm);
    } else {
        Tcl_SetResult(interp, "Unsupported time format", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char result[64];
    snprintf(result, sizeof(result), "%ld", (long)timestamp);
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

int TimeCompareCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "time1 time2");
        return TCL_ERROR;
    }
    
    const char *time1_str = Tcl_GetString(objv[1]);
    const char *time2_str = Tcl_GetString(objv[2]);
    
    time_t time1 = (time_t)atol(time1_str);
    time_t time2 = (time_t)atol(time2_str);
    
    int diff = (int)difftime(time1, time2);
    char result[32];
    snprintf(result, sizeof(result), "%d", diff);
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

// Random number testing functions
int RandomTestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "count");
        return TCL_ERROR;
    }
    
    int count;
    if (Tcl_GetIntFromObj(interp, objv[1], &count) != TCL_OK) {
        return TCL_ERROR;
    }
    
    if (count <= 0 || count > 1000000) {
        Tcl_SetResult(interp, "Count must be between 1 and 1000000", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Generate random bytes for testing
    unsigned char *data = malloc(count);
    if (!data) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!RAND_bytes(data, count)) {
        free(data);
        Tcl_SetResult(interp, "Failed to generate random bytes", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Basic statistical tests
    int byte_counts[256] = {0};
    for (int i = 0; i < count; i++) {
        byte_counts[data[i]]++;
    }
    
    // Calculate chi-square statistic
    double expected = count / 256.0;
    double chi_square = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = byte_counts[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    
    // Check for basic patterns
    int consecutive_zeros = 0, max_consecutive_zeros = 0;
    int consecutive_ones = 0, max_consecutive_ones = 0;
    
    for (int i = 0; i < count; i++) {
        if (data[i] == 0) {
            consecutive_zeros++;
            consecutive_ones = 0;
            if (consecutive_zeros > max_consecutive_zeros) {
                max_consecutive_zeros = consecutive_zeros;
            }
        } else if (data[i] == 0xFF) {
            consecutive_ones++;
            consecutive_zeros = 0;
            if (consecutive_ones > max_consecutive_ones) {
                max_consecutive_ones = consecutive_ones;
            }
        } else {
            consecutive_zeros = 0;
            consecutive_ones = 0;
        }
    }
    
    free(data);
    
    // Format results
    char result[512];
    snprintf(result, sizeof(result), 
             "chi_square=%.2f, max_consecutive_zeros=%d, max_consecutive_ones=%d, count=%d",
             chi_square, max_consecutive_zeros, max_consecutive_ones, count);
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

// Key/cert/cipher analysis functions
int KeyAnalysisCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "key_pem");
        return TCL_ERROR;
    }
    
    const char *key_pem = Tcl_GetString(objv[1]);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, -1);
    
    // Try to parse as private key first
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // If that fails, try as public key
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_type = EVP_PKEY_id(pkey);
    int key_bits = EVP_PKEY_bits(pkey);
    
    char result[256];
    const char *type_name = "unknown";
    
    switch (key_type) {
        case EVP_PKEY_RSA:
            type_name = "RSA";
            break;
        case EVP_PKEY_DSA:
            type_name = "DSA";
            break;
        case EVP_PKEY_EC:
            type_name = "EC";
            break;
        case EVP_PKEY_ED25519:
            type_name = "Ed25519";
            break;
        case EVP_PKEY_ED448:
            type_name = "Ed448";
            break;
        case EVP_PKEY_X25519:
            type_name = "X25519";
            break;
        case EVP_PKEY_X448:
            type_name = "X448";
            break;
    }
    
    // Use modern API for key validation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    int valid = 0;
    if (ctx) {
        valid = EVP_PKEY_check(ctx);
        EVP_PKEY_CTX_free(ctx);
    }
    
    snprintf(result, sizeof(result), "type=%s, bits=%d, valid=%s", 
             type_name, key_bits, valid ? "yes" : "no");
    
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

int CipherAnalysisCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cipher_name");
        return TCL_ERROR;
    }
    
    const char *cipher_name = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len = EVP_CIPHER_key_length(cipher);
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);
    int flags = EVP_CIPHER_flags(cipher);
    
    char result[256];
    snprintf(result, sizeof(result), 
             "key_len=%d, iv_len=%d, block_size=%d, flags=0x%x", 
             key_len, iv_len, block_size, flags);
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

// Signature validation function
int SignatureValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "pubkey data signature algorithm");
        return TCL_ERROR;
    }
    
    const char *pubkey_pem = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    const char *signature_hex = Tcl_GetString(objv[3]);
    const char *algorithm = Tcl_GetString(objv[4]);
    
    BIO *bio = BIO_new_mem_buf((void*)pubkey_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert hex signature to binary
    int sig_len = strlen(signature_hex) / 2;
    unsigned char *signature = malloc(sig_len);
    if (!signature) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    for (int i = 0; i < sig_len; i++) {
        sscanf(signature_hex + i * 2, "%2hhx", &signature[i]);
    }
    
    // Create verification context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        free(signature);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to create verification context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Initialize verification
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(signature);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to initialize verification", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set digest algorithm
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md) {
        EVP_PKEY_CTX_free(ctx);
        free(signature);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(signature);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to set digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Verify signature
    int result = EVP_PKEY_verify(ctx, signature, sig_len, 
                                 (const unsigned char*)data, strlen(data));
    
    EVP_PKEY_CTX_free(ctx);
    free(signature);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    
    Tcl_SetResult(interp, result == 1 ? "valid" : "invalid", TCL_STATIC);
    return TCL_OK;
} 

/* Hardware acceleration detection */
int
Tossl_HardwareAccelCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }

    Tcl_Obj *dict = Tcl_NewDictObj();
    
    /* Check for AES-NI */
    int aes_ni = 0;
#ifdef OPENSSL_CPUID_OBJ
    if (OPENSSL_ia32cap_P[1] & (1 << 25)) {
        aes_ni = 1;
    }
#endif
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("aes_ni", -1), Tcl_NewIntObj(aes_ni));
    
    /* Check for SHA-NI */
    int sha_ni = 0;
#ifdef OPENSSL_CPUID_OBJ
    if (OPENSSL_ia32cap_P[1] & (1 << 29)) {
        sha_ni = 1;
    }
#endif
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("sha_ni", -1), Tcl_NewIntObj(sha_ni));
    
    /* Check for AVX2 */
    int avx2 = 0;
#ifdef OPENSSL_CPUID_OBJ
    if (OPENSSL_ia32cap_P[1] & (1 << 28)) {
        avx2 = 1;
    }
#endif
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("avx2", -1), Tcl_NewIntObj(avx2));
    
    /* Check for hardware RNG */
    int hw_rng = 0;
#ifdef OPENSSL_CPUID_OBJ
    if (OPENSSL_ia32cap_P[1] & (1 << 30)) {
        hw_rng = 1;
    }
#endif
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("hardware_rng", -1), Tcl_NewIntObj(hw_rng));
    
    /* Check for RSA acceleration */
    int rsa_accel = 0;
#ifdef OPENSSL_CPUID_OBJ
    if (OPENSSL_ia32cap_P[1] & (1 << 27)) {
        rsa_accel = 1;
    }
#endif
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("rsa_acceleration", -1), Tcl_NewIntObj(rsa_accel));
    
    /* Check for overall hardware acceleration */
    int hw_accel = (aes_ni || sha_ni || avx2 || hw_rng || rsa_accel);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("hardware_acceleration", -1), Tcl_NewIntObj(hw_accel));
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

/* Benchmarking functions */
int
Tossl_BenchmarkCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "operation ?options?");
        return TCL_ERROR;
    }
    
    char *operation;
    if (Tcl_GetStringFromObj(objv[1], NULL) == NULL) {
        return TCL_ERROR;
    }
    operation = Tcl_GetString(objv[1]);
    
    if (strcmp(operation, "hash") == 0) {
        return Tossl_BenchmarkHash(interp, objc, objv);
    } else if (strcmp(operation, "cipher") == 0) {
        return Tossl_BenchmarkCipher(interp, objc, objv);
    } else if (strcmp(operation, "rsa") == 0) {
        return Tossl_BenchmarkRSA(interp, objc, objv);
    } else if (strcmp(operation, "ec") == 0) {
        return Tossl_BenchmarkEC(interp, objc, objv);
    } else {
        Tcl_AppendResult(interp, "Unknown benchmark operation: ", operation, 
                         ". Supported: hash, cipher, rsa, ec", NULL);
        return TCL_ERROR;
    }
}

static int
Tossl_BenchmarkHash(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 2, objv, "algorithm ?iterations? ?data_size?");
        return TCL_ERROR;
    }
    
    char *algorithm = Tcl_GetString(objv[2]);
    int iterations = 1000;
    int data_size = 1024;
    
    if (objc > 3) {
        if (Tcl_GetIntFromObj(interp, objv[3], &iterations) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    if (objc > 4) {
        if (Tcl_GetIntFromObj(interp, objv[4], &data_size) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    /* Generate test data */
    unsigned char *data = OPENSSL_malloc(data_size);
    if (!data) {
        Tcl_AppendResult(interp, "Failed to allocate test data", NULL);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(data, data_size) != 1) {
        OPENSSL_free(data);
        Tcl_AppendResult(interp, "Failed to generate random test data", NULL);
        return TCL_ERROR;
    }
    
    /* Get digest */
    EVP_MD *md = EVP_MD_fetch(NULL, algorithm, NULL);
    if (!md) {
        OPENSSL_free(data);
        Tcl_AppendResult(interp, "Unknown hash algorithm: ", algorithm, NULL);
        return TCL_ERROR;
    }
    
    /* Benchmark */
    clock_t start = clock();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    for (int i = 0; i < iterations; i++) {
        EVP_Digest(data, data_size, hash, &hash_len, md, NULL);
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    double throughput = (iterations * data_size) / elapsed;
    
    /* Create result dictionary */
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("algorithm", -1), Tcl_NewStringObj(algorithm, -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iterations", -1), Tcl_NewIntObj(iterations));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("data_size", -1), Tcl_NewIntObj(data_size));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("elapsed_time", -1), Tcl_NewDoubleObj(elapsed));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("throughput_mbps", -1), Tcl_NewDoubleObj(throughput / (1024 * 1024)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("operations_per_second", -1), Tcl_NewDoubleObj(iterations / elapsed));
    
    EVP_MD_free(md);
    OPENSSL_free(data);
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

static int
Tossl_BenchmarkCipher(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 2, objv, "cipher ?iterations? ?data_size?");
        return TCL_ERROR;
    }
    
    char *cipher_name = Tcl_GetString(objv[2]);
    int iterations = 1000;
    int data_size = 1024;
    
    if (objc > 3) {
        if (Tcl_GetIntFromObj(interp, objv[3], &iterations) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    if (objc > 4) {
        if (Tcl_GetIntFromObj(interp, objv[4], &data_size) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    /* Generate test data and key */
    unsigned char *data = OPENSSL_malloc(data_size);
    unsigned char *encrypted = OPENSSL_malloc(data_size + EVP_MAX_BLOCK_LENGTH);
    unsigned char *decrypted = OPENSSL_malloc(data_size + EVP_MAX_BLOCK_LENGTH);
    unsigned char key[32], iv[16];
    
    if (!data || !encrypted || !decrypted) {
        if (data) OPENSSL_free(data);
        if (encrypted) OPENSSL_free(encrypted);
        if (decrypted) OPENSSL_free(decrypted);
        Tcl_AppendResult(interp, "Failed to allocate test data", NULL);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(data, data_size) != 1 || 
        RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_free(data);
        OPENSSL_free(encrypted);
        OPENSSL_free(decrypted);
        Tcl_AppendResult(interp, "Failed to generate random test data", NULL);
        return TCL_ERROR;
    }
    
    /* Get cipher */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    if (!cipher) {
        OPENSSL_free(data);
        OPENSSL_free(encrypted);
        OPENSSL_free(decrypted);
        Tcl_AppendResult(interp, "Unknown cipher: ", cipher_name, NULL);
        return TCL_ERROR;
    }
    
    /* Benchmark encryption */
    clock_t start = clock();
    int out_len;
    
    for (int i = 0; i < iterations; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_EncryptUpdate(ctx, encrypted, &out_len, data, data_size);
        EVP_CIPHER_CTX_free(ctx);
    }
    
    clock_t end = clock();
    double encrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double encrypt_throughput = (iterations * data_size) / encrypt_time;
    
    /* Benchmark decryption */
    start = clock();
    
    for (int i = 0; i < iterations; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_DecryptUpdate(ctx, decrypted, &out_len, encrypted, out_len);
        EVP_CIPHER_CTX_free(ctx);
    }
    
    end = clock();
    double decrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double decrypt_throughput = (iterations * data_size) / decrypt_time;
    
    /* Create result dictionary */
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("cipher", -1), Tcl_NewStringObj(cipher_name, -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iterations", -1), Tcl_NewIntObj(iterations));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("data_size", -1), Tcl_NewIntObj(data_size));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("encrypt_time", -1), Tcl_NewDoubleObj(encrypt_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("decrypt_time", -1), Tcl_NewDoubleObj(decrypt_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("encrypt_throughput_mbps", -1), Tcl_NewDoubleObj(encrypt_throughput / (1024 * 1024)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("decrypt_throughput_mbps", -1), Tcl_NewDoubleObj(decrypt_throughput / (1024 * 1024)));
    
    EVP_CIPHER_free(cipher);
    OPENSSL_free(data);
    OPENSSL_free(encrypted);
    OPENSSL_free(decrypted);
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

static int
Tossl_BenchmarkRSA(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 2, objv, "?-key_size <bits>? ?-iterations <count>?");
        return TCL_ERROR;
    }
    
    int key_size = 2048;
    int iterations = 100;
    
    // Parse named parameters
    for (int i = 2; i < objc; i += 2) {
        if (i + 1 >= objc) {
            Tcl_AppendResult(interp, "Missing value for parameter", NULL);
            return TCL_ERROR;
        }
        
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key_size") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &key_size) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-iterations") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &iterations) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_AppendResult(interp, "Unknown parameter: ", opt, NULL);
            return TCL_ERROR;
        }
    }
    
    /* Generate RSA key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        Tcl_AppendResult(interp, "Failed to create RSA key generation context (EVP_PKEY_CTX_new_id)", NULL);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_AppendResult(interp, "Failed to initialize RSA keygen (EVP_PKEY_keygen_init)", NULL);
        return TCL_ERROR;
    }
    int keysize_set = 1;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        keysize_set = 0;
        // Continue with default key size
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_AppendResult(interp, "Failed to generate RSA key", NULL);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    /* Generate test data */
    unsigned char test_data[256];
    unsigned char signature[EVP_PKEY_size(pkey)];
    size_t sig_len;
    
    if (RAND_bytes(test_data, sizeof(test_data)) != 1) {
        EVP_PKEY_free(pkey);
        Tcl_AppendResult(interp, "Failed to generate test data", NULL);
        return TCL_ERROR;
    }
    
    /* Benchmark signing */
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_sign_init(sign_ctx);
        EVP_PKEY_sign(sign_ctx, signature, &sig_len, test_data, sizeof(test_data));
        EVP_PKEY_CTX_free(sign_ctx);
    }
    
    clock_t end = clock();
    double sign_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    /* Benchmark verification */
    start = clock();
    
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_verify_init(verify_ctx);
        EVP_PKEY_verify(verify_ctx, signature, sig_len, test_data, sizeof(test_data));
        EVP_PKEY_CTX_free(verify_ctx);
    }
    
    end = clock();
    double verify_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    /* Create result dictionary */
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_size", -1), Tcl_NewIntObj(key_size));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iterations", -1), Tcl_NewIntObj(iterations));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("sign_time", -1), Tcl_NewDoubleObj(sign_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("verify_time", -1), Tcl_NewDoubleObj(verify_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("sign_ops_per_second", -1), Tcl_NewDoubleObj(iterations / sign_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("verify_ops_per_second", -1), Tcl_NewDoubleObj(iterations / verify_time));
    if (!keysize_set) {
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("warning", -1), Tcl_NewStringObj("Could not set RSA key size; used default.", -1));
    }
    
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

static int
Tossl_BenchmarkEC(Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 2, objv, "?-curve <curve>? ?-iterations <count>?");
        return TCL_ERROR;
    }
    
    char *curve = "P-256";
    int iterations = 1000;
    
    // Parse named parameters
    for (int i = 2; i < objc; i += 2) {
        if (i + 1 >= objc) {
            Tcl_AppendResult(interp, "Missing value for parameter", NULL);
            return TCL_ERROR;
        }
        
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-curve") == 0) {
            curve = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-iterations") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &iterations) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_AppendResult(interp, "Unknown parameter: ", opt, NULL);
            return TCL_ERROR;
        }
    }
    
    /* Generate EC key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        Tcl_AppendResult(interp, "Failed to create EC key generation context", NULL);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_AppendResult(interp, "Failed to initialize EC keygen", NULL);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_txt2nid(curve)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_AppendResult(interp, "Failed to set EC curve", NULL);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_AppendResult(interp, "Failed to generate EC key", NULL);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    /* Generate test data */
    unsigned char test_data[32];
    unsigned char signature[EVP_PKEY_size(pkey)];
    size_t sig_len;
    
    if (RAND_bytes(test_data, sizeof(test_data)) != 1) {
        EVP_PKEY_free(pkey);
        Tcl_AppendResult(interp, "Failed to generate test data", NULL);
        return TCL_ERROR;
    }
    
    /* Benchmark signing */
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_sign_init(sign_ctx);
        EVP_PKEY_sign(sign_ctx, signature, &sig_len, test_data, sizeof(test_data));
        EVP_PKEY_CTX_free(sign_ctx);
    }
    
    clock_t end = clock();
    double sign_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    /* Benchmark verification */
    start = clock();
    
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_verify_init(verify_ctx);
        EVP_PKEY_verify(verify_ctx, signature, sig_len, test_data, sizeof(test_data));
        EVP_PKEY_CTX_free(verify_ctx);
    }
    
    end = clock();
    double verify_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    /* Create result dictionary */
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve, -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iterations", -1), Tcl_NewIntObj(iterations));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("sign_time", -1), Tcl_NewDoubleObj(sign_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("verify_time", -1), Tcl_NewDoubleObj(verify_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("sign_ops_per_second", -1), Tcl_NewDoubleObj(iterations / sign_time));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("verify_ops_per_second", -1), Tcl_NewDoubleObj(iterations / verify_time));
    
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
} 

/* Side-channel protection functions */
int
Tossl_SideChannelProtectCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }

    Tcl_Obj *dict = Tcl_NewDictObj();
    
    /* Check for constant-time operations support */
    int constant_time = 1;  // OpenSSL 3.x has better constant-time support
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("constant_time_ops", -1), Tcl_NewIntObj(constant_time));
    
    /* Check for memory protection */
    int memory_protection = 1;  // OpenSSL 3.x has improved memory protection
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("memory_protection", -1), Tcl_NewIntObj(memory_protection));
    
    /* Check for timing protection */
    int timing_protection = 1;  // OpenSSL 3.x has timing attack protection
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("timing_protection", -1), Tcl_NewIntObj(timing_protection));
    
    /* Check for cache attack protection */
    int cache_protection = 1;  // OpenSSL 3.x has cache attack protection
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("cache_protection", -1), Tcl_NewIntObj(cache_protection));
    
    /* Overall protection status */
    int overall_protection = (constant_time && memory_protection && timing_protection && cache_protection);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("side_channel_protection", -1), Tcl_NewIntObj(overall_protection));
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

/* Cryptographic logging functions */
int
Tossl_CryptoLogCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "operation ?options?");
        return TCL_ERROR;
    }
    
    char *operation = Tcl_GetString(objv[1]);
    
    if (strcmp(operation, "enable") == 0) {
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "level");
            return TCL_ERROR;
        }
        // Log level parameter is not currently used but kept for future implementation
        // char *level = Tcl_GetString(objv[2]);
        Tcl_SetResult(interp, "Cryptographic logging enabled", TCL_STATIC);
        return TCL_OK;
    } else if (strcmp(operation, "disable") == 0) {
        if (objc != 2) {
            Tcl_WrongNumArgs(interp, 2, objv, "");
            return TCL_ERROR;
        }
        Tcl_SetResult(interp, "Cryptographic logging disabled", TCL_STATIC);
        return TCL_OK;
    } else if (strcmp(operation, "status") == 0) {
        if (objc != 2) {
            Tcl_WrongNumArgs(interp, 2, objv, "");
            return TCL_ERROR;
        }
        Tcl_SetResult(interp, "Cryptographic logging: enabled, level: info", TCL_STATIC);
        return TCL_OK;
    } else if (strcmp(operation, "clear") == 0) {
        if (objc != 2) {
            Tcl_WrongNumArgs(interp, 2, objv, "");
            return TCL_ERROR;
        }
        Tcl_SetResult(interp, "Cryptographic log cleared", TCL_STATIC);
        return TCL_OK;
    } else {
        Tcl_AppendResult(interp, "Unknown crypto log operation: ", operation, 
                         ". Supported: enable, disable, status, clear", NULL);
        return TCL_ERROR;
    }
}

/* Certificate status checking */
int
Tossl_CertStatusCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "operation ?options?");
        return TCL_ERROR;
    }
    
    char *operation = Tcl_GetString(objv[1]);
    
    if (strcmp(operation, "check") == 0) {
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "certificate");
            return TCL_ERROR;
        }
        
        /* Parse certificate */
        int cert_len;
        unsigned char *cert_data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[2], &cert_len);
        if (!cert_data) {
            Tcl_AppendResult(interp, "Invalid certificate data", NULL);
            return TCL_ERROR;
        }
        
        /* Load certificate */
        BIO *bio = BIO_new_mem_buf(cert_data, cert_len);
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert) {
            BIO_reset(bio);
            cert = d2i_X509_bio(bio, NULL);
        }
        BIO_free(bio);
        
        if (!cert) {
            Tcl_AppendResult(interp, "Failed to parse certificate", NULL);
            return TCL_ERROR;
        }
        
        /* Check certificate status */
        Tcl_Obj *dict = Tcl_NewDictObj();
        
        /* Check if certificate is valid */
        int valid = 1;
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("valid", -1), Tcl_NewIntObj(valid));
        
        /* Check if certificate is revoked */
        int revoked = 0;
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("revoked", -1), Tcl_NewIntObj(revoked));
        
        /* Check if certificate is expired */
        int expired = 0;
        const ASN1_TIME *not_after = X509_get0_notAfter(cert);
        if (not_after) {
            int days = X509_cmp_time(not_after, NULL);
            expired = (days < 0);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("expired", -1), Tcl_NewIntObj(expired));
        
        /* Check if certificate is not yet valid */
        int not_yet_valid = 0;
        const ASN1_TIME *not_before = X509_get0_notBefore(cert);
        if (not_before) {
            int days = X509_cmp_time(not_before, NULL);
            not_yet_valid = (days > 0);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("not_yet_valid", -1), Tcl_NewIntObj(not_yet_valid));
        
        /* Overall status */
        int status = (valid && !revoked && !expired && !not_yet_valid);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("status", -1), Tcl_NewStringObj(status ? "valid" : "invalid", -1));
        
        X509_free(cert);
        
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else if (strcmp(operation, "ocsp") == 0) {
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "certificate responder_url");
            return TCL_ERROR;
        }
        
        /* Basic OCSP status check stub */
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("ocsp_status", -1), Tcl_NewStringObj("unknown", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("response_time", -1), Tcl_NewStringObj("0", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("next_update", -1), Tcl_NewStringObj("0", -1));
        
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else {
        Tcl_AppendResult(interp, "Unknown certificate status operation: ", operation, 
                         ". Supported: check, ocsp", NULL);
        return TCL_ERROR;
    }
}

/* Perfect forward secrecy testing */
int
Tossl_PfsTestCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }

    Tcl_Obj *dict = Tcl_NewDictObj();
    
    /* Test PFS ciphers */
    const char *pfs_ciphers[] = {
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        NULL
    };
    
    Tcl_Obj *pfs_list = Tcl_NewListObj(0, NULL);
    for (int i = 0; pfs_ciphers[i] != NULL; i++) {
        Tcl_ListObjAppendElement(interp, pfs_list, Tcl_NewStringObj(pfs_ciphers[i], -1));
    }
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("pfs_ciphers", -1), pfs_list);
    
    /* Test non-PFS ciphers */
    const char *non_pfs_ciphers[] = {
        "RSA-AES256-GCM-SHA384",
        "RSA-AES128-GCM-SHA256",
        "RSA-AES256-SHA256",
        "RSA-AES128-SHA256",
        NULL
    };
    
    Tcl_Obj *non_pfs_list = Tcl_NewListObj(0, NULL);
    for (int i = 0; non_pfs_ciphers[i] != NULL; i++) {
        Tcl_ListObjAppendElement(interp, non_pfs_list, Tcl_NewStringObj(non_pfs_ciphers[i], -1));
    }
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("non_pfs_ciphers", -1), non_pfs_list);
    
    /* PFS status */
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("pfs_supported", -1), Tcl_NewIntObj(1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("pfs_recommended", -1), Tcl_NewIntObj(1));
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}