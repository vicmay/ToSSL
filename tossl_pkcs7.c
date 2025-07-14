#include "tossl.h"

// PKCS#7 encrypt command
int Pkcs7EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-data data -cert cert ?-cipher cipher?");
        return TCL_ERROR;
    }
    
    const char *data = NULL, *cert_pem = NULL, *cipher = "aes-256-cbc";
    int data_len = 0, cert_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-data") == 0) {
            data = Tcl_GetStringFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-cipher") == 0) {
            cipher = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!data || !cert_pem) {
        Tcl_SetResult(interp, "Data and certificate are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_CIPHER *cipher_obj = EVP_get_cipherbyname(cipher);
    if (!cipher_obj) {
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Unknown cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *data_bio = BIO_new_mem_buf((void*)data, data_len);
    PKCS7 *p7 = PKCS7_encrypt(NULL, data_bio, cipher_obj, PKCS7_BINARY);
    if (!p7) {
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PKCS7_add_recipient(p7, cert) <= 0) {
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to add recipient", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (i2d_PKCS7_bio(out_bio, p7) <= 0) {
        BIO_free(out_bio);
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to write PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    PKCS7_free(p7);
    X509_free(cert);
    BIO_free(cert_bio);
    return TCL_OK;
}

// PKCS#7 decrypt command
int Pkcs7DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7_data private_key");
        return TCL_ERROR;
    }
    
    const char *pkcs7_data = Tcl_GetString(objv[1]);
    const char *key_pem = Tcl_GetString(objv[2]);
    
    BIO *pkcs7_bio = BIO_new_mem_buf((void*)pkcs7_data, -1);
    PKCS7 *p7 = d2i_PKCS7_bio(pkcs7_bio, NULL);
    if (!p7) {
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *key_bio = BIO_new_mem_buf((void*)key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (!pkey) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        PKCS7_free(p7);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        PKCS7_free(p7);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PKCS7_decrypt(p7, pkey, NULL, out_bio, 0) <= 0) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        PKCS7_free(p7);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to decrypt PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    PKCS7_free(p7);
    BIO_free(pkcs7_bio);
    return TCL_OK;
}

// PKCS#7 sign command
int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-data data -key key -cert cert ?-detached?");
        return TCL_ERROR;
    }
    
    const char *data = NULL, *key_pem = NULL, *cert_pem = NULL;
    int data_len = 0, key_len = 0, cert_len = 0;
    int detached = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-data") == 0) {
            data = Tcl_GetStringFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-detached") == 0) {
            detached = 1;
            i--; // Don't skip next argument
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!data || !key_pem || !cert_pem) {
        Tcl_SetResult(interp, "Data, key, and certificate are required", TCL_STATIC);
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
    
    PKCS7 *p7 = PKCS7_sign(cert, pkey, NULL, NULL, detached ? PKCS7_DETACHED : 0);
    if (!p7) {
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *data_bio = BIO_new_mem_buf((void*)data, data_len);
    if (!data_bio) {
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create data BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PKCS7_final(p7, data_bio, detached ? PKCS7_DETACHED : 0) <= 0) {
        BIO_free(data_bio);
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to finalize PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        BIO_free(data_bio);
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (i2d_PKCS7_bio(out_bio, p7) <= 0) {
        BIO_free(out_bio);
        BIO_free(data_bio);
        PKCS7_free(p7);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        Tcl_SetResult(interp, "Failed to write PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    BIO_free(data_bio);
    PKCS7_free(p7);
    X509_free(cert);
    BIO_free(cert_bio);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    return TCL_OK;
}

// PKCS#7 verify command
int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7_data ?-data data? ?-certs certs?");
        return TCL_ERROR;
    }
    
    const char *pkcs7_data = Tcl_GetString(objv[1]);
    const char *data = NULL, *certs_pem = NULL;
    int data_len = 0, certs_len = 0;
    
    for (int i = 2; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-data") == 0) {
            data = Tcl_GetStringFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-certs") == 0) {
            certs_pem = Tcl_GetStringFromObj(objv[i+1], &certs_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    BIO *pkcs7_bio = BIO_new_mem_buf((void*)pkcs7_data, -1);
    PKCS7 *p7 = d2i_PKCS7_bio(pkcs7_bio, NULL);
    if (!p7) {
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        PKCS7_free(p7);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to create certificate store", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (certs_pem) {
        BIO *certs_bio = BIO_new_mem_buf((void*)certs_pem, certs_len);
        X509 *cert;
        while ((cert = PEM_read_bio_X509(certs_bio, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(store, cert);
            X509_free(cert);
        }
        BIO_free(certs_bio);
    }
    
    BIO *data_bio = NULL;
    if (data) {
        data_bio = BIO_new_mem_buf((void*)data, data_len);
    }
    
    int result = PKCS7_verify(p7, NULL, store, data_bio, NULL, 0);
    Tcl_SetResult(interp, (result == 1) ? "1" : "0", TCL_STATIC);
    
    if (data_bio) BIO_free(data_bio);
    X509_STORE_free(store);
    PKCS7_free(p7);
    BIO_free(pkcs7_bio);
    return TCL_OK;
}

// PKCS#7 info command
int Pkcs7InfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7_data");
        return TCL_ERROR;
    }
    
    const char *pkcs7_data = Tcl_GetString(objv[1]);
    
    BIO *pkcs7_bio = BIO_new_mem_buf((void*)pkcs7_data, -1);
    PKCS7 *p7 = d2i_PKCS7_bio(pkcs7_bio, NULL);
    if (!p7) {
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Get type
    int type = OBJ_obj2nid(p7->type);
    const char *type_str = OBJ_nid2sn(type);
    if (type_str) {
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("type", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(type_str, -1));
    }
    
    // Get signers info
    STACK_OF(PKCS7_SIGNER_INFO) *signers = PKCS7_get_signer_info(p7);
    if (signers) {
        int num_signers = sk_PKCS7_SIGNER_INFO_num(signers);
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("num_signers", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(num_signers));
    }
    
    // Get recipients info
    STACK_OF(PKCS7_RECIP_INFO) *recipients = NULL;
    int type_nid = OBJ_obj2nid(p7->type);
    if (type_nid == NID_pkcs7_enveloped && p7->d.enveloped)
        recipients = p7->d.enveloped->recipientinfo;
    else if (type_nid == NID_pkcs7_signedAndEnveloped && p7->d.signed_and_enveloped)
        recipients = p7->d.signed_and_enveloped->recipientinfo;
    if (recipients) {
        int num_recipients = sk_PKCS7_RECIP_INFO_num(recipients);
        Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("num_recipients", -1));
        Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(num_recipients));
    }
    
    BIO_free(pkcs7_bio);
    PKCS7_free(p7);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 