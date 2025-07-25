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
        } else if (type == EVP_PKEY_EC || type == EVP_PKEY_SM2) {
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
        } else if (type == EVP_PKEY_EC || type == EVP_PKEY_SM2) {
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
            /* Use PKCS#8 DER output for private keys */
            success = i2d_PKCS8PrivateKey_bio(out_bio, pkey, NULL, NULL, 0, NULL, NULL);
            BUF_MEM *debug_bptr;
            BIO_get_mem_ptr(out_bio, &debug_bptr);
            fprintf(stderr, "DEBUG: i2d_PKCS8PrivateKey_bio returned %d, DER length = %ld\n", success, debug_bptr ? debug_bptr->length : -1L);
            if (debug_bptr && debug_bptr->length > 0) {
                int dump_len = debug_bptr->length < 32 ? debug_bptr->length : 32;
                fprintf(stderr, "DEBUG: DER head: ");
                for (int i = 0; i < dump_len; ++i) fprintf(stderr, "%02x", (unsigned char)debug_bptr->data[i]);
                fprintf(stderr, "\n");
            }
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
    if (strcmp(format, "der") == 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *)bptr->data, bptr->length));
    } else {
        Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    }
    
    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// tossl::key::generate -type <rsa|dsa|ec> ?-bits <bits>? ?-curve <curve>?
int KeyGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 1 && objc != 3 && objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-type rsa|dsa|ec ?-bits bits? ?-curve curve?");
        return TCL_ERROR;
    }
    const char *type = "rsa", *curve = "prime256v1";
    int bits = 2048;
    int type_explicit = 0;
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
            type_explicit = 1;
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
    if (type_explicit && !type) {
        Tcl_SetResult(interp, "Key type is required", TCL_STATIC);
        return TCL_ERROR;
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;

    int rc = TCL_ERROR;
    BIO *priv_bio = NULL, *pub_bio = NULL;
    do {
        if (strcmp(type, "rsa") == 0) {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!ctx) {
                Tcl_SetResult(interp, "OpenSSL: failed to create RSA context", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                Tcl_SetResult(interp, "OpenSSL: RSA keygen init failed", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
                Tcl_SetResult(interp, "OpenSSL: RSA bits setting failed", TCL_STATIC);
                break;
            }
        } else if (strcmp(type, "dsa") == 0) {
            EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
            if (!param_ctx) {
                Tcl_SetResult(interp, "OpenSSL: failed to create DSA param context", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
                EVP_PKEY_CTX_free(param_ctx);
                Tcl_SetResult(interp, "OpenSSL: DSA paramgen init failed", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_CTX_set_dsa_paramgen_bits(param_ctx, bits) <= 0) {
                EVP_PKEY_CTX_free(param_ctx);
                Tcl_SetResult(interp, "OpenSSL: DSA bits setting failed", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_paramgen(param_ctx, &params) <= 0) {
                EVP_PKEY_CTX_free(param_ctx);
                Tcl_SetResult(interp, "OpenSSL: DSA parameter generation failed", TCL_STATIC);
                break;
            }
            EVP_PKEY_CTX_free(param_ctx);
            param_ctx = NULL;
            ctx = EVP_PKEY_CTX_new(params, NULL);
            if (!ctx) {
                EVP_PKEY_free(params); params = NULL;
                Tcl_SetResult(interp, "OpenSSL: failed to create DSA keygen context", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                EVP_PKEY_free(params); params = NULL;
                Tcl_SetResult(interp, "OpenSSL: DSA keygen init failed", TCL_STATIC);
                break;
            }
            EVP_PKEY_free(params); params = NULL;
        } else if (strcmp(type, "ec") == 0) {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (!ctx) {
                Tcl_SetResult(interp, "OpenSSL: failed to create EC context", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                Tcl_SetResult(interp, "OpenSSL: EC keygen init failed", TCL_STATIC);
                break;
            }
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_txt2nid(curve)) <= 0) {
                Tcl_SetResult(interp, "OpenSSL: EC curve setting failed", TCL_STATIC);
                break;
            }
        } else {
            Tcl_SetResult(interp, "Only RSA, DSA, and EC supported for now", TCL_STATIC);
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            Tcl_SetResult(interp, "OpenSSL: key generation failed", TCL_STATIC);
            break;
        }

        priv_bio = BIO_new(BIO_s_mem());
        pub_bio = BIO_new(BIO_s_mem());
        if (!priv_bio || !pub_bio) {
            Tcl_SetResult(interp, "OpenSSL: BIO allocation failed", TCL_STATIC);
            break;
        }
        PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_PUBKEY(pub_bio, pkey);
        BUF_MEM *priv_bptr, *pub_bptr;
        BIO_get_mem_ptr(priv_bio, &priv_bptr);
        BIO_get_mem_ptr(pub_bio, &pub_bptr);
        Tcl_Obj *priv_pem = Tcl_NewStringObj(priv_bptr->data, priv_bptr->length);
        Tcl_Obj *pub_pem = Tcl_NewStringObj(pub_bptr->data, pub_bptr->length);
        int keybits = EVP_PKEY_get_bits(pkey);
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), priv_pem);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), pub_pem);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj(type, -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(keybits));
        if (strcmp(type, "ec") == 0) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve, -1));
        }
        Tcl_SetObjResult(interp, dict);
        rc = TCL_OK;
    } while (0);

    if (priv_bio) BIO_free(priv_bio);
    if (pub_bio) BIO_free(pub_bio);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (params) EVP_PKEY_free(params);
    return rc;
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
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(out_bio, pkey)) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to write public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    // Patch: For Ed448/Ed25519, verify the PEM is valid and type is correct
    char *pub_pem = bptr->data;
    BIO *pub_bio = BIO_new_mem_buf(pub_pem, bptr->length);
    EVP_PKEY *pubkey_check = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    if (!pubkey_check) {
        BIO_free(pub_bio);
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse extracted public key", TCL_STATIC);
        return TCL_ERROR;
    }
    int type = EVP_PKEY_id(pubkey_check);
    EVP_PKEY_free(pubkey_check);
    BIO_free(pub_bio);
    if (EVP_PKEY_id(pkey) == EVP_PKEY_ED448 && type != EVP_PKEY_ED448) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Extracted public key is not valid Ed448", TCL_STATIC);
        return TCL_ERROR;
    }
    if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 && type != EVP_PKEY_ED25519) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Extracted public key is not valid Ed25519", TCL_STATIC);
        return TCL_ERROR;
    }
    // Note: SM2 keys may be EC keys with SM2 curve, so we don't validate the type here
    // The SM2 commands will handle the validation themselves
    Tcl_SetResult(interp, pub_pem, TCL_VOLATILE);
    BIO_free(out_bio);
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
    
    const char *from_format = NULL, *to_format = NULL, *type = NULL;
    int key_len = 0;
    unsigned char *key_data = NULL;
    for (int i = 1; i < 8; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            // Always get as byte array for binary safety
            key_data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &key_len);
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
        } else if (strcmp(type, "public") == 0) {
            pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        } else {
            BIO_free(bio);
            Tcl_SetResult(interp, "Type must be 'private' or 'public'", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(from_format, "der") == 0) {
        if (strcmp(type, "private") == 0) {
            pkey = d2i_PrivateKey_bio(bio, NULL);
        } else if (strcmp(type, "public") == 0) {
            pkey = d2i_PUBKEY_bio(bio, NULL);
        } else {
            BIO_free(bio);
            Tcl_SetResult(interp, "Type must be 'private' or 'public'", TCL_STATIC);
            return TCL_ERROR;
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
    if (strcmp(to_format, "der") == 0) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *)bptr->data, bptr->length));
    } else {
        Tcl_SetObjResult(interp, Tcl_NewStringObj(bptr->data, bptr->length));
    }
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