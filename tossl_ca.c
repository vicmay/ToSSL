#include "tossl.h"

// CA generate command
int CaGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key key -subject subject ?-days days? ?-extensions extensions?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *subject = NULL, *extensions = NULL;
    int key_len = 0, days = 365;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-subject") == 0) {
            subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-days") == 0) {
            days = atoi(Tcl_GetString(objv[i+1]));
        } else if (strcmp(opt, "-extensions") == 0) {
            extensions = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem || !subject) {
        Tcl_SetResult(interp, "Key and subject are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *key_bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set version
    if (X509_set_version(cert, 2) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set certificate version", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create serial number", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (ASN1_INTEGER_set(serial, 1) <= 0) {
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set serial number", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_set_serialNumber(cert, serial) <= 0) {
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set certificate serial", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ASN1_INTEGER_free(serial);
    
    // Set subject and issuer (same for self-signed CA)
    X509_NAME *name = X509_get_subject_name(cert);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)subject, -1, -1, 0) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set subject", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_set_issuer_name(cert, name) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set issuer", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set public key
    if (X509_set_pubkey(cert, pkey) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set validity period
    ASN1_TIME *not_before = ASN1_TIME_new();
    ASN1_TIME *not_after = ASN1_TIME_new();
    if (!not_before || !not_after) {
        if (not_before) ASN1_TIME_free(not_before);
        if (not_after) ASN1_TIME_free(not_after);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create time structures", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ASN1_TIME_set(not_before, time(NULL));
    ASN1_TIME_set(not_after, time(NULL) + days * 24 * 60 * 60);
    
    X509_set_notBefore(cert, not_before);
    X509_set_notAfter(cert, not_after);
    
    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);
    
    // Add basic constraints extension for CA
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Add key usage extension
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to sign certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509(out_bio, cert) <= 0) {
        BIO_free(out_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to write certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    return TCL_OK;
}

// CA sign command
int CaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ca_key ca_key -ca_cert ca_cert -csr csr ?-days days?");
        return TCL_ERROR;
    }
    
    const char *ca_key_pem = NULL, *ca_cert_pem = NULL, *csr_pem = NULL;
    int ca_key_len = 0, ca_cert_len = 0, csr_len = 0, days = 365;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-ca_key") == 0) {
            ca_key_pem = Tcl_GetStringFromObj(objv[i+1], &ca_key_len);
        } else if (strcmp(opt, "-ca_cert") == 0) {
            ca_cert_pem = Tcl_GetStringFromObj(objv[i+1], &ca_cert_len);
        } else if (strcmp(opt, "-csr") == 0) {
            csr_pem = Tcl_GetStringFromObj(objv[i+1], &csr_len);
        } else if (strcmp(opt, "-days") == 0) {
            days = atoi(Tcl_GetString(objv[i+1]));
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!ca_key_pem || !ca_cert_pem || !csr_pem) {
        Tcl_SetResult(interp, "CA key, CA certificate, and CSR are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse CA private key
    BIO *ca_key_bio = BIO_new_mem_buf((void*)ca_key_pem, ca_key_len);
    EVP_PKEY *ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    if (!ca_key) {
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to parse CA private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse CA certificate
    BIO *ca_cert_bio = BIO_new_mem_buf((void*)ca_cert_pem, ca_cert_len);
    X509 *ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if (!ca_cert) {
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to parse CA certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse CSR
    BIO *csr_bio = BIO_new_mem_buf((void*)csr_pem, csr_len);
    X509_REQ *req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    if (!req) {
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create certificate from CSR
    X509 *cert = X509_new();
    if (!cert) {
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to create certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set version
    if (X509_set_version(cert, 2) <= 0) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set certificate version", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to create serial number", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (ASN1_INTEGER_set(serial, 2) <= 0) {
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set serial number", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_set_serialNumber(cert, serial) <= 0) {
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set certificate serial", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ASN1_INTEGER_free(serial);
    
    // Set subject from CSR
    X509_NAME *subject = X509_REQ_get_subject_name(req);
    if (X509_set_subject_name(cert, subject) <= 0) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set subject", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set issuer from CA certificate
    X509_NAME *issuer = X509_get_subject_name(ca_cert);
    if (X509_set_issuer_name(cert, issuer) <= 0) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set issuer", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set public key from CSR
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
    if (!pubkey) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to get public key from CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_set_pubkey(cert, pubkey) <= 0) {
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to set public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_free(pubkey);
    
    // Set validity period
    ASN1_TIME *not_before = ASN1_TIME_new();
    ASN1_TIME *not_after = ASN1_TIME_new();
    if (!not_before || !not_after) {
        if (not_before) ASN1_TIME_free(not_before);
        if (not_after) ASN1_TIME_free(not_after);
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to create time structures", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ASN1_TIME_set(not_before, time(NULL));
    ASN1_TIME_set(not_after, time(NULL) + days * 24 * 60 * 60);
    
    X509_set_notBefore(cert, not_before);
    X509_set_notAfter(cert, not_after);
    
    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);
    
    // Sign the certificate with CA key
    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to sign certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509(out_bio, cert) <= 0) {
        BIO_free(out_bio);
        X509_free(cert);
        X509_REQ_free(req);
        BIO_free(csr_bio);
        X509_free(ca_cert);
        BIO_free(ca_cert_bio);
        EVP_PKEY_free(ca_key);
        BIO_free(ca_key_bio);
        Tcl_SetResult(interp, "Failed to write certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    X509_free(cert);
    X509_REQ_free(req);
    BIO_free(csr_bio);
    X509_free(ca_cert);
    BIO_free(ca_cert_bio);
    EVP_PKEY_free(ca_key);
    BIO_free(ca_key_bio);
    return TCL_OK;
} 