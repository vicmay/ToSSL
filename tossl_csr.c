#include "tossl.h"
#include <stdio.h>

// CSR create command
int CsrCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Accept: -key pem -subject subjectDictOrString ?-extensions extList? ?-attributes attrList?
    if (objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -subject subject ?-extensions extList? ?-attributes attrList?");
        return TCL_ERROR;
    }
    const char *key_pem = NULL;
    int key_len = 0;
    Tcl_Obj *subjectObj = NULL;
    Tcl_Obj *extListObj = NULL;
    Tcl_Obj *attrListObj = NULL;
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-subject") == 0) {
            subjectObj = objv[i+1];
        } else if (strcmp(opt, "-extensions") == 0) {
            extListObj = objv[i+1];
        } else if (strcmp(opt, "-attributes") == 0) {
            attrListObj = objv[i+1];
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!key_pem || !subjectObj) {
        Tcl_SetResult(interp, "Key and subject are required", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    fprintf(stderr, "DEBUG: BIO_new_mem_buf done\n");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to parse private key\n");
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "DEBUG: Private key parsed\n");
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to create CSR\n");
        Tcl_SetResult(interp, "Failed to create CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "DEBUG: CSR allocated\n");
    // Set subject (dict or string) BEFORE setting public key
    X509_NAME *name = NULL;
    int dictSize = 0;
    int isDict = 0;
    if (Tcl_DictObjSize(interp, subjectObj, &dictSize) == TCL_OK) {
        isDict = 1;
    }
    fprintf(stderr, "DEBUG: isDict=%d\n", isDict);
    if (isDict) {
        name = X509_NAME_new();
        if (!name) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            fprintf(stderr, "DEBUG: Failed to create subject name\n");
            Tcl_SetResult(interp, "Failed to create subject name", TCL_STATIC);
            return TCL_ERROR;
        }
        // Dict: {CN val O val OU val ...}
        Tcl_DictSearch search;
        Tcl_Obj *key, *val;
        int done;
        int dictFirstResult = Tcl_DictObjFirst(interp, subjectObj, &search, &key, &val, &done);
        fprintf(stderr, "DEBUG: Tcl_DictObjFirst result=%d\n", dictFirstResult);
        if (dictFirstResult == TCL_OK) {
            fprintf(stderr, "DEBUG: Tcl_DictObjFirst OK, entering for loop\n");
            for (; !done; Tcl_DictObjNext(&search, &key, &val, &done)) {
                const char *field = Tcl_GetString(key);
                const char *value = Tcl_GetString(val);
                fprintf(stderr, "DEBUG: Before X509_NAME_add_entry_by_txt %s=%s\n", field, value);
                int add_result = X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
                fprintf(stderr, "DEBUG: After X509_NAME_add_entry_by_txt %s=%s, result=%d\n", field, value, add_result);
                if (add_result <= 0) {
                    X509_NAME_free(name);
                    X509_REQ_free(req);
                    EVP_PKEY_free(pkey);
                    BIO_free(bio);
                    fprintf(stderr, "DEBUG: Failed to set subject field %s\n", field);
                    Tcl_SetResult(interp, "Failed to set subject field", TCL_STATIC);
                    return TCL_ERROR;
                }
            }
            fprintf(stderr, "DEBUG: End of for loop\n");
        }
        fprintf(stderr, "DEBUG: All subject fields set from dict\n");
    } else {
        fprintf(stderr, "DEBUG: Entering string subject branch\n");
        // String: try OpenSSL DN parser
        name = X509_NAME_new();
        if (!name) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to create subject name", TCL_STATIC);
            return TCL_ERROR;
        }
        const char *subject_str = Tcl_GetString(subjectObj);
        fprintf(stderr, "DEBUG: Setting subject from string: %s\n", subject_str);
        int add_result = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)subject_str, -1, -1, 0);
        fprintf(stderr, "DEBUG: After X509_NAME_add_entry_by_txt (string branch), result=%d\n", add_result);
        if (add_result <= 0) {
            X509_NAME_free(name);
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to set subject", TCL_STATIC);
            return TCL_ERROR;
        }
        fprintf(stderr, "DEBUG: Subject set from string\n");
    }
    if (X509_REQ_set_subject_name(req, name) <= 0) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to set subject name", TCL_STATIC);
        return TCL_ERROR;
    }
    // Do NOT free(name) here; OpenSSL manages it after set_subject_name for CSRs
    fprintf(stderr, "DEBUG: Subject name set on req\n");
    // Now set public key (after subject)
    if (X509_REQ_set_pubkey(req, pkey) <= 0) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to set public key\n");
        Tcl_SetResult(interp, "Failed to set public key", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "DEBUG: Public key set\n");
    // Extensions
    fprintf(stderr, "DEBUG: Before extensions block\n");
    if (extListObj) {
        int extCount;
        Tcl_Obj **extElems;
        if (Tcl_ListObjGetElements(interp, extListObj, &extCount, &extElems) == TCL_OK) {
            STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
            for (int i = 0; i < extCount; ++i) {
                Tcl_Obj *extDict = extElems[i];
                Tcl_Obj *oidObj, *valObj, *critObj;
                if (Tcl_DictObjGet(interp, extDict, Tcl_NewStringObj("oid", -1), &oidObj) != TCL_OK || !oidObj) continue;
                if (Tcl_DictObjGet(interp, extDict, Tcl_NewStringObj("value", -1), &valObj) != TCL_OK || !valObj) continue;
                int critical = 0;
                if (Tcl_DictObjGet(interp, extDict, Tcl_NewStringObj("critical", -1), &critObj) == TCL_OK && critObj) {
                    Tcl_GetBooleanFromObj(interp, critObj, &critical);
                }
                const char *oid = Tcl_GetString(oidObj);
                const char *val = Tcl_GetString(valObj);
                int nid = OBJ_txt2nid(oid);
                X509V3_CTX ctx;
                X509V3_set_ctx_nodb(&ctx);
                X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
                X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, val);
                if (!ext) continue;
                X509_EXTENSION_set_critical(ext, critical);
                sk_X509_EXTENSION_push(exts, ext);
            }
            if (sk_X509_EXTENSION_num(exts) > 0) {
                X509_REQ_add_extensions(req, exts);
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }
    fprintf(stderr, "DEBUG: After extensions block\n");
    // Attributes
    fprintf(stderr, "DEBUG: Before attributes block\n");
    if (attrListObj) {
        int attrCount;
        Tcl_Obj **attrElems;
        if (Tcl_ListObjGetElements(interp, attrListObj, &attrCount, &attrElems) == TCL_OK) {
            for (int i = 0; i < attrCount; ++i) {
                Tcl_Obj *attrDict = attrElems[i];
                Tcl_Obj *oidObj, *valObj;
                if (Tcl_DictObjGet(interp, attrDict, Tcl_NewStringObj("oid", -1), &oidObj) != TCL_OK || !oidObj) continue;
                if (Tcl_DictObjGet(interp, attrDict, Tcl_NewStringObj("value", -1), &valObj) != TCL_OK || !valObj) continue;
                const char *oid = Tcl_GetString(oidObj);
                const char *val = Tcl_GetString(valObj);
                int nid = OBJ_txt2nid(oid);
                ASN1_STRING *asn1str = ASN1_UTF8STRING_new();
                ASN1_STRING_set(asn1str, val, strlen(val));
                X509_ATTRIBUTE *attr = X509_ATTRIBUTE_create(nid, V_ASN1_UTF8STRING, asn1str);
                if (attr) X509_REQ_add1_attr(req, attr);
                X509_ATTRIBUTE_free(attr);
                // Do NOT free asn1str; ownership is transferred to the attribute
            }
        }
    }
    fprintf(stderr, "DEBUG: After attributes block\n");
    // Sign
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to sign CSR\n");
        Tcl_SetResult(interp, "Failed to sign CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "DEBUG: CSR signed\n");
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to create output BIO\n");
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    if (PEM_write_bio_X509_REQ(out_bio, req) <= 0) {
        BIO_free(out_bio);
        // X509_NAME_free(name); // Do NOT free here
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        fprintf(stderr, "DEBUG: Failed to write CSR\n");
        Tcl_SetResult(interp, "Failed to write CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    fprintf(stderr, "DEBUG: CSR written to PEM\n");
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    BIO_free(out_bio);
    // X509_NAME_free(name); // Do NOT free here; OpenSSL manages it
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    fprintf(stderr, "DEBUG: CSR creation done\n");
    return TCL_OK;
}

// CSR parse command
int CsrParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "csr_pem");
        return TCL_ERROR;
    }
    
    const char *csr_pem = Tcl_GetString(objv[1]);
    
    BIO *bio = BIO_new_mem_buf((void*)csr_pem, -1);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Get subject
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (name) {
        char *subject = X509_NAME_oneline(name, NULL, 0);
        if (subject) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("subject", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(subject, -1));
            OPENSSL_free(subject);
        }
    }
    
    // Get public key info
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (pkey) {
        int key_type = EVP_PKEY_id(pkey);
        const char *key_type_str = OBJ_nid2sn(key_type);
        if (key_type_str) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("key_type", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(key_type_str, -1));
        }
        EVP_PKEY_free(pkey);
    }
    
    // Get signature info
    const X509_ALGOR *sig_alg;
    const ASN1_BIT_STRING *sig;
    X509_REQ_get0_signature(req, &sig, &sig_alg);
    if (sig_alg) {
        const char *sig_alg_str = OBJ_nid2sn(OBJ_obj2nid(sig_alg->algorithm));
        if (sig_alg_str) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("signature_algorithm", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(sig_alg_str, -1));
        }
    }
    
    BIO_free(bio);
    X509_REQ_free(req);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// CSR validate command
int CsrValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "csr_pem");
        return TCL_ERROR;
    }
    
    const char *csr_pem = Tcl_GetString(objv[1]);
    
    BIO *bio = BIO_new_mem_buf((void*)csr_pem, -1);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (!pkey) {
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to extract public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = X509_REQ_verify(req, pkey);
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    BIO_free(bio);
    return TCL_OK;
}

// CSR fingerprint command
int CsrFingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "csr_pem algorithm");
        return TCL_ERROR;
    }
    
    const char *csr_pem = Tcl_GetString(objv[1]);
    const char *algorithm = Tcl_GetString(objv[2]);
    
    BIO *bio = BIO_new_mem_buf((void*)csr_pem, -1);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md) {
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *der_bio = BIO_new(BIO_s_mem());
    if (!der_bio) {
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to create DER BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (i2d_X509_REQ_bio(der_bio, req) <= 0) {
        BIO_free(der_bio);
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to convert to DER", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(der_bio, &bptr);
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    if (EVP_Digest(bptr->data, bptr->length, hash, &hash_len, md, NULL) <= 0) {
        BIO_free(der_bio);
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to calculate hash", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char hex_hash[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    
    BIO_free(der_bio);
    X509_REQ_free(req);
    BIO_free(bio);
    
    Tcl_SetResult(interp, hex_hash, TCL_STATIC);
    return TCL_OK;
}

// CSR modify command
int CsrModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "csr_pem -subject new_subject ?-extensions extensions?");
        return TCL_ERROR;
    }
    
    const char *csr_pem = Tcl_GetString(objv[1]);
    const char *new_subject = NULL, *extensions = NULL, *key_pem = NULL;
    int key_len = 0;
    for (int i = 2; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-subject") == 0) {
            new_subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-extensions") == 0) {
            extensions = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    BIO *bio = BIO_new_mem_buf((void*)csr_pem, -1);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (new_subject) {
        X509_NAME *name = X509_NAME_new();
        if (!name) {
            X509_REQ_free(req);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to create new subject name", TCL_STATIC);
            return TCL_ERROR;
        }
        // Parse DN string: e.g., "CN=foo,O=bar,C=US"
        char *subject_copy = strdup(new_subject);
        char *token = strtok(subject_copy, ",");
        while (token) {
            char *eq = strchr(token, '=');
            if (eq) {
                *eq = '\0';
                const char *field = token;
                const char *value = eq + 1;
                X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
            }
            token = strtok(NULL, ",");
        }
        free(subject_copy);
        if (X509_REQ_set_subject_name(req, name) <= 0) {
            X509_NAME_free(name);
            X509_REQ_free(req);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to set new subject name on CSR", TCL_STATIC);
            return TCL_ERROR;
        }
        X509_NAME_free(name);
    }
    // Optionally re-sign the CSR if key is provided
    if (key_pem) {
        BIO *keybio = BIO_new_mem_buf((void*)key_pem, key_len);
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
        if (!pkey) {
            BIO_free(keybio);
            X509_REQ_free(req);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to parse private key for re-signing", TCL_STATIC);
            return TCL_ERROR;
        }
        if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
            EVP_PKEY_free(pkey);
            BIO_free(keybio);
            X509_REQ_free(req);
            BIO_free(bio);
            Tcl_SetResult(interp, "Failed to re-sign CSR", TCL_STATIC);
            return TCL_ERROR;
        }
        EVP_PKEY_free(pkey);
        BIO_free(keybio);
    }
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    if (PEM_write_bio_X509_REQ(out_bio, req) <= 0) {
        BIO_free(out_bio);
        X509_REQ_free(req);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to write modified CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    BIO_free(out_bio);
    X509_REQ_free(req);
    BIO_free(bio);
    return TCL_OK;
} 