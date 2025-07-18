#include "tossl.h"

// X.509 certificate parsing command
int X509ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Extract subject
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        char subject_str[256];
        X509_NAME_oneline(subject, subject_str, sizeof(subject_str));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("subject", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(subject_str, -1));
    }
    
    // Extract issuer
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer) {
        char issuer_str[256];
        X509_NAME_oneline(issuer, issuer_str, sizeof(issuer_str));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("issuer", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(issuer_str, -1));
    }
    
    // Extract serial number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char *serial_str = BN_bn2hex(bn);
            if (serial_str) {
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("serial", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(serial_str, -1));
                OPENSSL_free(serial_str);
            }
            BN_free(bn);
        }
    }
    
    // Extract validity dates
    ASN1_TIME *not_before = X509_getm_notBefore(cert);
    ASN1_TIME *not_after = X509_getm_notAfter(cert);
    
    if (not_before) {
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("not_before", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj((char*)not_before->data, not_before->length));
    }
    
    if (not_after) {
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("not_after", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj((char*)not_after->data, not_after->length));
    }
    
    X509_free(cert);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::x509::ct_extensions certificate
int X509CtExtensionsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate");
        return TCL_ERROR;
    }
    const char *cert_data = Tcl_GetString(objv[1]);
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
#ifdef OPENSSL_VERSION_MAJOR
#if OPENSSL_VERSION_MAJOR >= 1
    // Try to extract SCTs (Signed Certificate Timestamps)
    int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count; i++) {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        char extname[128];
        OBJ_obj2txt(extname, sizeof(extname), obj, 1);
        if (strcmp(extname, "1.3.6.1.4.1.11129.2.4.2") == 0) { // SCT extension OID
            // Add SCT extension as hex string
            ASN1_OCTET_STRING *oct = X509_EXTENSION_get_data(ext);
            char *hex = OPENSSL_buf2hexstr(oct->data, oct->length);
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("sct", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(hex, -1));
            OPENSSL_free(hex);
        }
    }
#endif
#endif
    X509_free(cert);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// X.509 certificate modification command
int X509ModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate field value ?field value? ...");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Process field modifications
    for (int i = 2; i < objc; i += 2) {
        if (i + 1 >= objc) {
            X509_free(cert);
            Tcl_SetResult(interp, "Odd number of arguments for field-value pairs", TCL_STATIC);
            return TCL_ERROR;
        }
        
        const char *field = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(field, "subject") == 0) {
            X509_NAME *name = X509_NAME_new();
            if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)value, -1, -1, 0) <= 0) {
                X509_NAME_free(name);
                X509_free(cert);
                Tcl_SetResult(interp, "Failed to set subject", TCL_STATIC);
                return TCL_ERROR;
            }
            X509_set_subject_name(cert, name);
            X509_NAME_free(name);
        } else if (strcmp(field, "issuer") == 0) {
            X509_NAME *name = X509_NAME_new();
            if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)value, -1, -1, 0) <= 0) {
                X509_NAME_free(name);
                X509_free(cert);
                Tcl_SetResult(interp, "Failed to set issuer", TCL_STATIC);
                return TCL_ERROR;
            }
            X509_set_issuer_name(cert, name);
            X509_NAME_free(name);
        }
    }
    
    // Write modified certificate
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509(bio, cert) <= 0) {
        BIO_free(bio);
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to write certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    Tcl_Obj *result = Tcl_NewStringObj(bptr->data, bptr->length);
    
    BIO_free(bio);
    X509_free(cert);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// X.509 certificate creation command
int X509CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 11 || objc % 2 == 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "-subject dn -issuer dn -pubkey pem -privkey pem -days n ?-san {dns1 dns2 ...}? ?-keyusage {usage1 usage2 ...}?");
        return TCL_ERROR;
    }
    const char *subject = NULL, *issuer = NULL, *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0, days = 0;
    Tcl_Obj *sanListObj = NULL;
    Tcl_Obj *keyUsageListObj = NULL;
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-subject") == 0) {
            subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-issuer") == 0) {
            issuer = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-days") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &days) != TCL_OK) return TCL_ERROR;
        } else if (strcmp(opt, "-san") == 0) {
            sanListObj = objv[i+1];
        } else if (strcmp(opt, "-keyusage") == 0) {
            keyUsageListObj = objv[i+1];
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!subject || !issuer || !pubkey || !privkey || days <= 0) {
        Tcl_SetResult(interp, "Missing required option", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *pub_bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    BIO *priv_bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *issuer_pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    if (!pkey || !issuer_pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        if (issuer_pkey) EVP_PKEY_free(issuer_pkey);
        BIO_free(pub_bio); BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key(s)", TCL_STATIC);
        return TCL_ERROR;
    }
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey); EVP_PKEY_free(issuer_pkey);
        BIO_free(pub_bio); BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create X509 object", TCL_STATIC);
        return TCL_ERROR;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), (long)60*60*24*days);
    X509_set_pubkey(cert, pkey);
    X509_NAME *subj = X509_NAME_new();
    X509_NAME *iss = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const unsigned char*)subject, -1, -1, 0);
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char*)issuer, -1, -1, 0);
    X509_set_subject_name(cert, subj);
    X509_set_issuer_name(cert, iss);
    // Add SAN extension if requested
    if (sanListObj) {
        int sanCount;
        Tcl_Obj **sanElems;
        if (Tcl_ListObjGetElements(interp, sanListObj, &sanCount, &sanElems) == TCL_OK && sanCount > 0) {
            char sanStr[1024] = "";
            for (int i = 0; i < sanCount; ++i) {
                if (i > 0) strcat(sanStr, ",");
                const char *val = Tcl_GetString(sanElems[i]);
                if (strchr(val, '.') || strchr(val, ':')) {
                    strcat(sanStr, "DNS:");
                    strcat(sanStr, val);
                } else {
                    strcat(sanStr, val);
                }
            }
            X509V3_CTX ctx;
            X509V3_set_ctx_nodb(&ctx);
            X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
            X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, sanStr);
            if (ext) {
                X509_add_ext(cert, ext, -1);
                X509_EXTENSION_free(ext);
            }
        }
    }
    // Add key usage extension if requested
    if (keyUsageListObj) {
        int kuCount;
        Tcl_Obj **kuElems;
        if (Tcl_ListObjGetElements(interp, keyUsageListObj, &kuCount, &kuElems) == TCL_OK && kuCount > 0) {
            ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
            for (int i = 0; i < kuCount; ++i) {
                const char *usage = Tcl_GetString(kuElems[i]);
                if (strcmp(usage, "digitalSignature") == 0) ASN1_BIT_STRING_set_bit(ku, 0, 1);
                if (strcmp(usage, "nonRepudiation") == 0) ASN1_BIT_STRING_set_bit(ku, 1, 1);
                if (strcmp(usage, "keyEncipherment") == 0) ASN1_BIT_STRING_set_bit(ku, 2, 1);
                if (strcmp(usage, "dataEncipherment") == 0) ASN1_BIT_STRING_set_bit(ku, 3, 1);
                if (strcmp(usage, "keyAgreement") == 0) ASN1_BIT_STRING_set_bit(ku, 4, 1);
                if (strcmp(usage, "keyCertSign") == 0) ASN1_BIT_STRING_set_bit(ku, 5, 1);
                if (strcmp(usage, "cRLSign") == 0) ASN1_BIT_STRING_set_bit(ku, 6, 1);
                if (strcmp(usage, "encipherOnly") == 0) ASN1_BIT_STRING_set_bit(ku, 7, 1);
                if (strcmp(usage, "decipherOnly") == 0) ASN1_BIT_STRING_set_bit(ku, 8, 1);
            }
            X509_EXTENSION *ext = X509V3_EXT_i2d(NID_key_usage, 0, ku);
            if (ext) {
                X509_add_ext(cert, ext, -1);
                X509_EXTENSION_free(ext);
            }
            ASN1_BIT_STRING_free(ku);
        }
    }
    int ok = X509_sign(cert, issuer_pkey, EVP_sha256());
    X509_NAME_free(subj); X509_NAME_free(iss);
    EVP_PKEY_free(pkey); EVP_PKEY_free(issuer_pkey);
    BIO_free(pub_bio); BIO_free(priv_bio);
    if (!ok) {
        X509_free(cert);
        Tcl_SetResult(interp, "OpenSSL: certificate signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    char *pem = NULL;
    long pemlen = BIO_get_mem_data(out, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, pemlen));
    BIO_free(out);
    X509_free(cert);
    return TCL_OK;
}

// X.509 certificate validation command
int X509ValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Check if certificate is expired
    int result = X509_cmp_time(X509_getm_notAfter(cert), NULL);
    if (result < 0) {
        X509_free(cert);
        Tcl_SetResult(interp, "Certificate is expired", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Check if certificate is not yet valid
    result = X509_cmp_time(X509_getm_notBefore(cert), NULL);
    if (result > 0) {
        X509_free(cert);
        Tcl_SetResult(interp, "Certificate is not yet valid", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_free(cert);
    Tcl_SetResult(interp, "Certificate is valid", TCL_STATIC);
    return TCL_OK;
}

// X.509 certificate fingerprint command
int X509FingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate digest");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    const char *digest_name = Tcl_GetString(objv[2]);
    
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_MD *md = EVP_get_digestbyname(digest_name);
    if (!md) {
        X509_free(cert);
        Tcl_SetResult(interp, "Invalid digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int fingerprint_len;
    
    if (X509_digest(cert, md, fingerprint, &fingerprint_len) <= 0) {
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to calculate fingerprint", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *hex_fingerprint = Tcl_Alloc(EVP_MAX_MD_SIZE * 2 + 1);
    bin2hex(fingerprint, fingerprint_len, hex_fingerprint);
    
    X509_free(cert);
    Tcl_SetResult(interp, hex_fingerprint, TCL_DYNAMIC);
    return TCL_OK;
}

// X.509 certificate verification command
int X509VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate ca_certificate");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    const char *ca_cert_data = Tcl_GetString(objv[2]);
    
    X509 *cert = NULL, *ca_cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    bio = BIO_new_mem_buf(ca_cert_data, -1);
    if (!bio) {
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ca_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!ca_cert) {
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to parse CA certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        X509_free(cert);
        X509_free(ca_cert);
        Tcl_SetResult(interp, "Failed to create certificate store", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_STORE_add_cert(store, ca_cert) <= 0) {
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca_cert);
        Tcl_SetResult(interp, "Failed to add CA certificate to store", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca_cert);
        Tcl_SetResult(interp, "Failed to create verification context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) <= 0) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca_cert);
        Tcl_SetResult(interp, "Failed to initialize verification context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = X509_verify_cert(ctx);
    
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(ca_cert);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result == 1));
    return TCL_OK;
}

// X.509 certificate time validation command
int X509TimeValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "certificate");
        return TCL_ERROR;
    }
    
    const char *cert_data = Tcl_GetString(objv[1]);
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Check not before
    int not_before_result = X509_cmp_time(X509_getm_notBefore(cert), NULL);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("not_before_valid", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewBooleanObj(not_before_result <= 0));
    
    // Check not after
    int not_after_result = X509_cmp_time(X509_getm_notAfter(cert), NULL);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("not_after_valid", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewBooleanObj(not_after_result >= 0));
    
    // Overall validity
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("valid", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewBooleanObj(not_before_result <= 0 && not_after_result >= 0));
    
    X509_free(cert);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 