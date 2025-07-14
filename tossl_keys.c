#include "tossl.h"

// tossl::key::parse <pem|der>
int KeyParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem|der");
        return TCL_ERROR;
    }
    int input_len;
    unsigned char *input = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &input_len);
    // Try as PEM
    BIO *bio = BIO_new_mem_buf((void*)input, input_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as DER
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)input, input_len);
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    if (pkey) {
        int bits = EVP_PKEY_get_bits(pkey);
        int type = EVP_PKEY_base_id(pkey);
        Tcl_Obj *dict = Tcl_NewDictObj();
        if (type == EVP_PKEY_RSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("rsa", -1));
        } else if (type == EVP_PKEY_DSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        } else if (type == EVP_PKEY_EC) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("ec", -1));
            char curve[80] = {0};
            OSSL_PARAM params[2] = { OSSL_PARAM_utf8_string("group", curve, sizeof(curve)), OSSL_PARAM_END };
            EVP_PKEY_get_params(pkey, params);
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve[0] ? curve : "unknown", -1));
        } else {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("unknown", -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kind", -1), Tcl_NewStringObj("private", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
        Tcl_SetObjResult(interp, dict);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return TCL_OK;
    }
    // Try as public key PEM
    BIO_free(bio);
    bio = BIO_new_mem_buf((void*)input, input_len);
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as public key DER
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)input, input_len);
        pkey = d2i_PUBKEY_bio(bio, NULL);
    }
    if (pkey) {
        int bits = EVP_PKEY_get_bits(pkey);
        int type = EVP_PKEY_base_id(pkey);
        Tcl_Obj *dict = Tcl_NewDictObj();
        if (type == EVP_PKEY_RSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("rsa", -1));
        } else if (type == EVP_PKEY_DSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        } else if (type == EVP_PKEY_EC) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("ec", -1));
            char curve[80] = {0};
            OSSL_PARAM params[2] = { OSSL_PARAM_utf8_string("group", curve, sizeof(curve)), OSSL_PARAM_END };
            EVP_PKEY_get_params(pkey, params);
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve[0] ? curve : "unknown", -1));
        } else {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("unknown", -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kind", -1), Tcl_NewStringObj("public", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
        Tcl_SetObjResult(interp, dict);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return TCL_OK;
    }
    BIO_free(bio);
    Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
    return TCL_ERROR;
}

// tossl::key::write -key <pem> -format <pem|der> -type <private|public>
int KeyWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -format pem|der -type private|public");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *format = NULL, *type = NULL;
    int key_len = 0;
    
    for (int i = 1; i < 6; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-format") == 0) {
            format = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem || !format || !type) {
        Tcl_SetResult(interp, "All parameters are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = NULL;
    
    if (strcmp(type, "private") == 0) {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else if (strcmp(type, "public") == 0) {
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    } else {
        BIO_free(bio);
        Tcl_SetResult(interp, "Type must be 'private' or 'public'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    int success = 0;
    
    if (strcmp(format, "pem") == 0) {
        if (strcmp(type, "private") == 0) {
            success = PEM_write_bio_PrivateKey(out_bio, pkey, NULL, NULL, 0, NULL, NULL);
        } else {
            success = PEM_write_bio_PUBKEY(out_bio, pkey);
        }
    } else if (strcmp(format, "der") == 0) {
        if (strcmp(type, "private") == 0) {
            success = i2d_PrivateKey_bio(out_bio, pkey);
        } else {
            success = i2d_PUBKEY_bio(out_bio, pkey);
        }
    } else {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Format must be 'pem' or 'der'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!success) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to write key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::key::generate -type <rsa|dsa|ec> ?-bits <bits>? ?-curve <curve>?
int KeyGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3 && objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-type rsa|dsa|ec ?-bits bits? ?-curve curve?");
        return TCL_ERROR;
    }
    
    const char *type = NULL, *curve = "prime256v1";
    int bits = 2048;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-bits") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &bits) != TCL_OK) {
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-curve") == 0) {
            curve = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!type) {
        Tcl_SetResult(interp, "Key type is required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    
    if (strcmp(type, "rsa") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
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
    } else if (strcmp(type, "dsa") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
        if (!ctx) {
            Tcl_SetResult(interp, "OpenSSL: failed to create DSA context", TCL_STATIC);
            return TCL_ERROR;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: DSA keygen init failed", TCL_STATIC);
            return TCL_ERROR;
        }
        if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: DSA bits setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(type, "ec") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) {
            Tcl_SetResult(interp, "OpenSSL: failed to create EC context", TCL_STATIC);
            return TCL_ERROR;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: EC keygen init failed", TCL_STATIC);
            return TCL_ERROR;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_txt2nid(curve)) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: EC curve setting failed", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        Tcl_SetResult(interp, "Type must be 'rsa', 'dsa', or 'ec'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
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
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return TCL_OK;
}

// tossl::key::getpub -key <pem>
int KeyGetPubCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    
    EVP_PKEY *pubkey = EVP_PKEY_new();
    if (!pubkey) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_copy_parameters(pubkey, pkey) <= 0) {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to copy parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_set1_RSA(pubkey, EVP_PKEY_get0_RSA(pkey)) <= 0 &&
        EVP_PKEY_set1_DSA(pubkey, EVP_PKEY_get0_DSA(pkey)) <= 0 &&
        EVP_PKEY_set1_EC_KEY(pubkey, EVP_PKEY_get0_EC_KEY(pkey)) <= 0) {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to set public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(out_bio, pubkey)) {
        BIO_free(out_bio);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to write public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::key::convert -key <pem> -from <pem|der> -to <pem|der> -type <private|public>
int KeyConvertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key key -from pem|der -to pem|der -type private|public");
        return TCL_ERROR;
    }
    
    const char *key_data = NULL, *from_format = NULL, *to_format = NULL, *type = NULL;
    int key_len = 0;
    
    for (int i = 1; i < 8; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_data = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-from") == 0) {
            from_format = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-to") == 0) {
            to_format = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_data || !from_format || !to_format || !type) {
        Tcl_SetResult(interp, "All parameters are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new_mem_buf((void*)key_data, key_len);
    EVP_PKEY *pkey = NULL;
    
    if (strcmp(from_format, "pem") == 0) {
        if (strcmp(type, "private") == 0) {
            pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        } else {
            pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        }
    } else if (strcmp(from_format, "der") == 0) {
        if (strcmp(type, "private") == 0) {
            pkey = d2i_PrivateKey_bio(bio, NULL);
        } else {
            pkey = d2i_PUBKEY_bio(bio, NULL);
        }
    } else {
        BIO_free(bio);
        Tcl_SetResult(interp, "From format must be 'pem' or 'der'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    int success = 0;
    
    if (strcmp(to_format, "pem") == 0) {
        if (strcmp(type, "private") == 0) {
            success = PEM_write_bio_PrivateKey(out_bio, pkey, NULL, NULL, 0, NULL, NULL);
        } else {
            success = PEM_write_bio_PUBKEY(out_bio, pkey);
        }
    } else if (strcmp(to_format, "der") == 0) {
        if (strcmp(type, "private") == 0) {
            success = i2d_PrivateKey_bio(out_bio, pkey);
        } else {
            success = i2d_PUBKEY_bio(out_bio, pkey);
        }
    } else {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "To format must be 'pem' or 'der'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!success) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to convert key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::key::fingerprint -key <pem> ?-alg <digest>?
int KeyFingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3 && objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem ?-alg digest?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *alg = "sha256";
    int key_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem) {
        Tcl_SetResult(interp, "Key is required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert to DER
    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);
    if (der_len <= 0) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to convert key to DER", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Calculate hash
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, der, der_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hash_len, hex);
    
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    return TCL_OK;
} 