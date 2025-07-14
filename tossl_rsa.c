#include "tossl.h"

// tossl::rsa::generate ?-bits <bits>?
int RsaGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create RSA context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: RSA keygen init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: RSA bits setting failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: RSA key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create dictionary for result
    Tcl_Obj *result = Tcl_NewDictObj();
    
    // Get private key
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: failed to write private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("private", -1), 
                   Tcl_NewStringObj(bptr->data, bptr->length));
    BIO_free(bio);
    
    // Get public key
    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: failed to write public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO_get_mem_ptr(bio, &bptr);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("public", -1), 
                   Tcl_NewStringObj(bptr->data, bptr->length));
    BIO_free(bio);
    
    Tcl_SetObjResult(interp, result);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return TCL_OK;
}

// tossl::rsa::encrypt -key <pem> -data <data> ?-padding <pkcs1|oaep>?
int RsaEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data ?-padding pkcs1|oaep?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *padding = "pkcs1";
    unsigned char *data = NULL;
    int key_len = 0, data_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-data") == 0) {
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
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
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create encryption context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: encryption init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (strcmp(padding, "oaep") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: OAEP padding setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") != 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Padding must be 'pkcs1' or 'oaep'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: encryption size calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *out = malloc(out_len);
    if (EVP_PKEY_encrypt(ctx, out, &out_len, data, data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: encryption failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, out_len));
    free(out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::rsa::decrypt -key <pem> -data <data> ?-padding <pkcs1|oaep>?
int RsaDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data ?-padding pkcs1|oaep?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *padding = "pkcs1";
    unsigned char *data = NULL;
    int key_len = 0, data_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-data") == 0) {
            data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
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
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create decryption context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: decryption init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (strcmp(padding, "oaep") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: OAEP padding setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") != 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Padding must be 'pkcs1' or 'oaep'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: decryption size calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *out = malloc(out_len);
    if (EVP_PKEY_decrypt(ctx, out, &out_len, data, data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: decryption failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, out_len));
    free(out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::rsa::sign -key <pem> -data <data> ?-alg <digest>? ?-padding <pkcs1|pss>?
int RsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5 && objc != 7 && objc != 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data ?-alg digest? ?-padding pkcs1|pss?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *alg = "sha256", *padding = "pkcs1";
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
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
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
    
    const EVP_MD *md = EVP_get_digestbyname(alg);
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
    
    if (strcmp(padding, "pss") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx), RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: PSS padding setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") != 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Padding must be 'pkcs1' or 'pss'", TCL_STATIC);
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

// tossl::rsa::verify -key <pem> -data <data> -sig <signature> ?-alg <digest>? ?-padding <pkcs1|pss>?
int RsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7 && objc != 9 && objc != 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -data data -sig sig ?-alg digest? ?-padding pkcs1|pss?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *alg = "sha256", *padding = "pkcs1";
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
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
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
    
    const EVP_MD *md = EVP_get_digestbyname(alg);
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
    
    if (strcmp(padding, "pss") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx), RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: PSS padding setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") != 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Padding must be 'pkcs1' or 'pss'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::rsa::validate -key <pem>
int RsaValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    
    const char *key_pem = Tcl_GetString(objv[2]);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Not an RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = RSA_check_key(rsa);
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::rsa::components -key <pem>
int RsaComponentsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    
    const char *key_pem = Tcl_GetString(objv[2]);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Not an RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    
    const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    
    if (n) {
        char *n_hex = BN_bn2hex(n);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("n", -1), Tcl_NewStringObj(n_hex, -1));
        OPENSSL_free(n_hex);
    }
    
    if (e) {
        char *e_hex = BN_bn2hex(e);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("e", -1), Tcl_NewStringObj(e_hex, -1));
        OPENSSL_free(e_hex);
    }
    
    if (d) {
        char *d_hex = BN_bn2hex(d);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("d", -1), Tcl_NewStringObj(d_hex, -1));
        OPENSSL_free(d_hex);
    }
    
    if (p) {
        char *p_hex = BN_bn2hex(p);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("p", -1), Tcl_NewStringObj(p_hex, -1));
        OPENSSL_free(p_hex);
    }
    
    if (q) {
        char *q_hex = BN_bn2hex(q);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("q", -1), Tcl_NewStringObj(q_hex, -1));
        OPENSSL_free(q_hex);
    }
    
    if (dmp1) {
        char *dmp1_hex = BN_bn2hex(dmp1);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("dmp1", -1), Tcl_NewStringObj(dmp1_hex, -1));
        OPENSSL_free(dmp1_hex);
    }
    
    if (dmq1) {
        char *dmq1_hex = BN_bn2hex(dmq1);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("dmq1", -1), Tcl_NewStringObj(dmq1_hex, -1));
        OPENSSL_free(dmq1_hex);
    }
    
    if (iqmp) {
        char *iqmp_hex = BN_bn2hex(iqmp);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iqmp", -1), Tcl_NewStringObj(iqmp_hex, -1));
        OPENSSL_free(iqmp_hex);
    }
    
    Tcl_SetObjResult(interp, dict);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
} 