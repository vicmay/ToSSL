#include "tossl.h"
#include <openssl/cms.h>

// PKCS#7 encrypt command (now uses CMS_encrypt, multi-recipient)
int Pkcs7EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-data data -cert cert ?-cert cert2 ...? ?-cipher cipher?");
        return TCL_ERROR;
    }
    const char *data = NULL, *cipher = "aes-256-cbc";
    int data_len = 0;
    STACK_OF(X509) *recips = sk_X509_new_null();
    if (!recips) {
        Tcl_SetResult(interp, "Failed to create recipient stack", TCL_STATIC);
        return TCL_ERROR;
    }
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-data") == 0) {
            data = Tcl_GetStringFromObj(objv[i+1], &data_len);
        } else if (strcmp(opt, "-cert") == 0) {
            int cert_len = 0;
            const char *cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
            BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
            X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
            BIO_free(certbio);
            if (!cert) {
                sk_X509_pop_free(recips, X509_free);
                Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
                return TCL_ERROR;
            }
            sk_X509_push(recips, cert);
        } else if (strcmp(opt, "-cipher") == 0) {
            cipher = Tcl_GetString(objv[i+1]);
        } else {
            sk_X509_pop_free(recips, X509_free);
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!data || sk_X509_num(recips) == 0) {
        sk_X509_pop_free(recips, X509_free);
        Tcl_SetResult(interp, "Data and at least one certificate are required", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    const EVP_CIPHER *cipher_obj = EVP_get_cipherbyname(cipher);
    if (!cipher_obj) {
        sk_X509_pop_free(recips, X509_free);
        BIO_free(databio);
        Tcl_SetResult(interp, "Unknown cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    CMS_ContentInfo *cms = CMS_encrypt(recips, databio, cipher_obj, CMS_BINARY);
    if (!cms) {
        sk_X509_pop_free(recips, X509_free);
        BIO_free(databio);
        Tcl_SetResult(interp, "CMS_encrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *outbio = BIO_new(BIO_s_mem());
    int ok = i2d_CMS_bio(outbio, cms);
    if (!ok) {
        CMS_ContentInfo_free(cms);
        sk_X509_pop_free(recips, X509_free);
        BIO_free(databio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "Failed to serialize CMS/PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    CMS_ContentInfo_free(cms);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(databio);
    BIO_free(outbio);
    return TCL_OK;
}

// PKCS#7 decrypt command (now uses CMS_decrypt)
int Pkcs7DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7_data private_key");
        return TCL_ERROR;
    }
    int pkcs7_len = 0;
    unsigned char *pkcs7_data = Tcl_GetByteArrayFromObj(objv[1], &pkcs7_len);
    const char *key_pem = Tcl_GetString(objv[2]);
    BIO *pkcs7_bio = BIO_new_mem_buf((void*)pkcs7_data, pkcs7_len);
    CMS_ContentInfo *cms = d2i_CMS_bio(pkcs7_bio, NULL);
    if (!cms) {
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse CMS/PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *key_bio = BIO_new_mem_buf((void*)key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (!pkey) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        CMS_ContentInfo_free(cms);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *out_bio = BIO_new(BIO_s_mem());
    int ok = CMS_decrypt(cms, pkey, NULL, NULL, out_bio, CMS_BINARY);
    if (!ok) {
        BIO_free(out_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        CMS_ContentInfo_free(cms);
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to decrypt CMS/PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(out_bio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    BIO_free(out_bio);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    CMS_ContentInfo_free(cms);
    BIO_free(pkcs7_bio);
    return TCL_OK;
}

// PKCS#7 sign command (now uses CMS_sign)
int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-data data -key key -cert cert ?-detached 0|1?");
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
            if (Tcl_GetIntFromObj(interp, objv[i+1], &detached) != TCL_OK) return TCL_ERROR;
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
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    CMS_ContentInfo *cms = CMS_sign(cert, pkey, NULL, databio, detached ? CMS_DETACHED : 0);
    if (!cms) {
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        BIO_free(databio);
        Tcl_SetResult(interp, "Failed to create CMS/PKCS7 signature", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *outbio = BIO_new(BIO_s_mem());
    int ok = i2d_CMS_bio(outbio, cms);
    if (!ok) {
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        BIO_free(cert_bio);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        BIO_free(databio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "Failed to serialize CMS/PKCS7 signature", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    CMS_ContentInfo_free(cms);
    X509_free(cert);
    BIO_free(cert_bio);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    BIO_free(databio);
    BIO_free(outbio);
    return TCL_OK;
}

// PKCS#7 verify command (now uses CMS_verify)
int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ca ca pkcs7 data");
        return TCL_ERROR;
    }
    const char *ca_pem = NULL;
    int ca_len = 0, sig_len = 0, data_len = 0;
    Tcl_Obj *sigObj = NULL, *dataObj = NULL;
    // Parse options: -ca <ca> <pkcs7> <data>
    int i = 1;
    for (; i + 1 < objc - 2; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-ca") == 0) {
            ca_pem = Tcl_GetStringFromObj(objv[i+1], &ca_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (i + 2 != objc) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ca ca pkcs7 data");
        return TCL_ERROR;
    }
    sigObj = objv[objc-2];
    dataObj = objv[objc-1];
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(sigObj, &sig_len);
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(dataObj, &data_len);
    // Load CA cert
    BIO *cabio = BIO_new_mem_buf((void*)ca_pem, ca_len);
    X509 *ca = PEM_read_bio_X509(cabio, NULL, NULL, NULL);
    if (!ca) {
        BIO_free(cabio);
        Tcl_SetResult(interp, "Failed to parse CA cert", TCL_STATIC);
        return TCL_ERROR;
    }
    // Load CMS/PKCS7 signature
    BIO *sigbio = BIO_new_mem_buf((void*)sig, sig_len);
    CMS_ContentInfo *cms = d2i_CMS_bio(sigbio, NULL);
    if (!cms) {
        BIO_reset(sigbio);
        cms = PEM_read_bio_CMS(sigbio, NULL, NULL, NULL);
    }
    if (!cms) {
        // Instead of error, return 0 for invalid signature
        X509_free(ca);
        BIO_free(cabio);
        BIO_free(sigbio);
        Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));
        return TCL_OK;
    }
    // Prepare data
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    // Build cert store
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    // Create cert stack
    STACK_OF(X509) *certs = sk_X509_new_null();
    sk_X509_push(certs, ca);
    // Verify
    int ok = CMS_verify(cms, certs, store, databio, NULL, CMS_BINARY);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok == 1));
    // Cleanup
    sk_X509_free(certs);
    X509_STORE_free(store);
    CMS_ContentInfo_free(cms);
    X509_free(ca);
    BIO_free(cabio);
    BIO_free(sigbio);
    BIO_free(databio);
    return TCL_OK;
}

// PKCS#7 info command
int Pkcs7InfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7_data");
        return TCL_ERROR;
    }
    int pkcs7_len = 0;
    unsigned char *pkcs7_data = Tcl_GetByteArrayFromObj(objv[1], &pkcs7_len);
    BIO *pkcs7_bio = BIO_new_mem_buf((void*)pkcs7_data, pkcs7_len);
    PKCS7 *p7 = NULL;
    // Try to parse as PEM first, then DER if that fails
    p7 = PEM_read_bio_PKCS7(pkcs7_bio, NULL, NULL, NULL);
    if (!p7) {
        BIO_reset(pkcs7_bio);
        p7 = d2i_PKCS7_bio(pkcs7_bio, NULL);
    }
    if (!p7) {
        BIO_free(pkcs7_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *result = Tcl_NewDictObj();
    int type = OBJ_obj2nid(p7->type);
    const char *type_str = OBJ_nid2sn(type);
    if (type_str) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("type", -1), Tcl_NewStringObj(type_str, -1));
    }
    STACK_OF(PKCS7_SIGNER_INFO) *signers = PKCS7_get_signer_info(p7);
    if (signers) {
        int num_signers = sk_PKCS7_SIGNER_INFO_num(signers);
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("num_signers", -1), Tcl_NewIntObj(num_signers));
    }
    STACK_OF(PKCS7_RECIP_INFO) *recipients = NULL;
    int type_nid = OBJ_obj2nid(p7->type);
    if (type_nid == NID_pkcs7_enveloped && p7->d.enveloped)
        recipients = p7->d.enveloped->recipientinfo;
    else if (type_nid == NID_pkcs7_signedAndEnveloped && p7->d.signed_and_enveloped)
        recipients = p7->d.signed_and_enveloped->recipientinfo;
    if (recipients) {
        int num_recipients = sk_PKCS7_RECIP_INFO_num(recipients);
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("num_recipients", -1), Tcl_NewIntObj(num_recipients));
        if (type_nid == NID_pkcs7_enveloped && p7->d.enveloped && p7->d.enveloped->enc_data && p7->d.enveloped->enc_data->algorithm) {
            int enc_nid = OBJ_obj2nid(p7->d.enveloped->enc_data->algorithm->algorithm);
            const char *cipher_str = OBJ_nid2sn(enc_nid);
            if (cipher_str) {
                Tcl_DictObjPut(interp, result, Tcl_NewStringObj("cipher", -1), Tcl_NewStringObj(cipher_str, -1));
            }
        }
    }
    BIO_free(pkcs7_bio);
    PKCS7_free(p7);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 