#include "tossl.h"

// CSR create command
int CsrCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem -subject subject ?-extensions extensions?");
        return TCL_ERROR;
    }
    
    const char *key_pem = NULL, *subject = NULL, *extensions = NULL;
    int key_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-subject") == 0) {
            subject = Tcl_GetString(objv[i+1]);
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
    
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to create CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_REQ_set_pubkey(req, pkey) <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to set public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to get subject name", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)subject, -1, -1, 0) <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to set subject", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to sign CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_X509_REQ(out_bio, req) <= 0) {
        BIO_free(out_bio);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Failed to write CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
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
    const char *new_subject = NULL, *extensions = NULL;
    
    for (int i = 2; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-subject") == 0) {
            new_subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-extensions") == 0) {
            extensions = Tcl_GetString(objv[i+1]);
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
        X509_NAME *name = X509_REQ_get_subject_name(req);
        if (name) {
            // Clear existing entries by recreating the name
            X509_NAME_free(name);
            name = X509_NAME_new();
            X509_REQ_set_subject_name(req, name);
            if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)new_subject, -1, -1, 0) <= 0) {
                X509_REQ_free(req);
                BIO_free(bio);
                Tcl_SetResult(interp, "Failed to set new subject", TCL_STATIC);
                return TCL_ERROR;
            }
        }
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