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
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "private_key subject days");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *subject_str = Tcl_GetString(objv[2]);
    int days = atoi(Tcl_GetString(objv[3]));
    
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(key_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set version
    X509_set_version(cert, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    
    // Set subject
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)subject_str, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);
    
    // Set validity
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), days * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(cert, pkey);
    
    // Sign certificate
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to sign certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Write certificate
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509(bio, cert) <= 0) {
        BIO_free(bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to write certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    Tcl_Obj *result = Tcl_NewStringObj(bptr->data, bptr->length);
    
    BIO_free(bio);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, result);
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
    
    char hex_fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
    bin2hex(fingerprint, fingerprint_len, hex_fingerprint);
    
    X509_free(cert);
    Tcl_SetResult(interp, hex_fingerprint, TCL_STATIC);
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