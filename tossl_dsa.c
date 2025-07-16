#include "tossl.h"

// tossl::dsa::sign -key <pem> -data <data> ?-alg <digest>?
int DsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data ?-alg digest?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *alg = "sha256";
    unsigned char *data = NULL;
    int key_len = 0, data_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-data") == 0) {
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem || !data) {
        Tcl_SetResult(interp, "Key and data are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD *md = modern_digest_fetch(alg);
    if (!md) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: digest sign init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, data, data_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: signature size calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSign(mdctx, sig, &sig_len, data, data_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: signature generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, sig_len));
    free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::dsa::verify -key <pem> -data <data> -sig <signature> ?-alg <digest>?
int DsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7 && objc != 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data -sig signature ?-alg digest?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *alg = "sha256";
    unsigned char *data = NULL, *sig = NULL;
    int key_len = 0, data_len = 0, sig_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-data") == 0) {
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-sig") == 0) {
            sig = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &sig_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem || !data || !sig) {
        Tcl_SetResult(interp, "Key, data, and signature are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD *md = modern_digest_fetch(alg);
    if (!md) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: digest verify init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::dsa::generate_params ?-bits <bits>?
int DsaGenerateParamsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 1 && objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-bits bits?");
        return TCL_ERROR;
    }
    
    int bits = 2048;
    if (objc == 3) {
        if (Tcl_GetIntFromObj(interp, objv[2], &bits) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create DSA context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DSA paramgen init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DSA bits setting failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_paramgen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DSA parameter generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_Parameters(bio, pkey)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: failed to write parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return TCL_OK;
}

// tossl::dsa::validate -key <pem>
int DsaValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    
    const char *key_pem = Tcl_GetString(objv[2]);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    int is_private = 1;
    if (!pkey) {
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)key_pem, -1);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        is_private = 0;
    }
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse DSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Not a DSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    int result;
    if (is_private) {
        result = modern_dsa_validate_key(pkey);
    } else {
        result = modern_dsa_public_check(pkey);
    }
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
} 