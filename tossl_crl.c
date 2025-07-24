#include "tossl.h"
#include <openssl/evp.h>

// CRL create command
int CrlCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key key -cert cert ?-revoked_certs revoked_certs?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *cert_pem = NULL;
    int key_len = 0, cert_len = 0, days = 30;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0 || strcmp(opt, "-ca_key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-cert") == 0 || strcmp(opt, "-ca_cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-days") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &days) != TCL_OK) {
                return TCL_ERROR;
            }
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!key_pem || !cert_pem) {
        Tcl_SetResult(interp, "Key and certificate are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (days <= 0) {
        Tcl_SetResult(interp, "Days must be a positive integer", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *key_bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_CRL *crl = X509_CRL_new();
    if (!crl) {
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create CRL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set version
    if (X509_CRL_set_version(crl, 1) <= 0) {
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set CRL version", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set issuer
    X509_NAME *issuer = X509_get_subject_name(cert);
    if (X509_CRL_set_issuer_name(crl, issuer) <= 0) {
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to set CRL issuer", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set last update and next update
    ASN1_TIME *last_update = ASN1_TIME_new();
    ASN1_TIME *next_update = ASN1_TIME_new();
    if (!last_update || !next_update) {
        if (last_update) ASN1_TIME_free(last_update);
        if (next_update) ASN1_TIME_free(next_update);
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create time structures", TCL_STATIC);
        return TCL_ERROR;
    }
    
    ASN1_TIME_set(last_update, time(NULL));
    ASN1_TIME_set(next_update, time(NULL) + days*24*60*60); // days from now
    
    X509_CRL_set1_lastUpdate(crl, last_update);
    X509_CRL_set1_nextUpdate(crl, next_update);
    
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    
    // Validate that private key matches certificate
    EVP_PKEY *cert_pubkey = X509_get_pubkey(cert);
    if (!cert_pubkey) {
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to extract public key from certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_cmp(cert_pubkey, pkey) != 1) {
        EVP_PKEY_free(cert_pubkey);
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Private key does not match certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_PKEY_free(cert_pubkey);
    
    // Sign the CRL
    if (X509_CRL_sign(crl, pkey, EVP_sha256()) <= 0) {
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to sign CRL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509_CRL(out_bio, crl) <= 0) {
        BIO_free(out_bio);
        X509_CRL_free(crl);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to write CRL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    X509_CRL_free(crl);
    X509_free(cert);
    BIO_free(cert_bio);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    return TCL_OK;
}

// CRL parse command
int CrlParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "crl_pem");
        return TCL_ERROR;
    }
    
    const char *crl_pem = Tcl_GetString(objv[1]);
    
    BIO *crl_bio = BIO_new_mem_buf((void*)crl_pem, -1);
    X509_CRL *crl = PEM_read_bio_X509_CRL(crl_bio, NULL, NULL, NULL);
    if (!crl) {
        BIO_free(crl_bio);
        Tcl_SetResult(interp, "Failed to parse CRL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Get version
    long version = X509_CRL_get_version(crl);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("version", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(version));
    
    // Get issuer
    X509_NAME *issuer = X509_CRL_get_issuer(crl);
    char *issuer_str = NULL;
    if (issuer) {
        issuer_str = X509_NAME_oneline(issuer, NULL, 0);
    }
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("issuer", -1));
    if (issuer_str) {
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(issuer_str, -1));
        OPENSSL_free(issuer_str);
    } else {
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("", -1));
    }
    
    // Get last update
    const ASN1_TIME *last_update = modern_crl_get_last_update(crl);
    if (last_update) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (ASN1_TIME_print(bio, last_update)) {
            BUF_MEM *bptr;
            BIO_get_mem_ptr(bio, &bptr);
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("last_update", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(bptr->data, bptr->length));
        }
        BIO_free(bio);
    }
    
    // Get next update
    const ASN1_TIME *next_update = modern_crl_get_next_update(crl);
    if (next_update) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (ASN1_TIME_print(bio, next_update)) {
            BUF_MEM *bptr;
            BIO_get_mem_ptr(bio, &bptr);
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("next_update", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(bptr->data, bptr->length));
        }
        BIO_free(bio);
    }
    
    // Get number of revoked certificates
    STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
    int num_revoked = 0;
    if (revoked) {
        num_revoked = sk_X509_REVOKED_num(revoked);
    }
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("num_revoked", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(num_revoked));
    
    BIO_free(crl_bio);
    X509_CRL_free(crl);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 