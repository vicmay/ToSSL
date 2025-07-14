#include "tossl.h"

// PKCS#12 create command
int Pkcs12CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert cert -key key -password password ?-name friendly_name?");
        return TCL_ERROR;
    }
    
    const char *cert_pem = NULL, *key_pem = NULL, *password = NULL, *friendly_name = "TOSSL PKCS#12";
    int cert_len = 0, key_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-password") == 0) {
            password = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-name") == 0) {
            friendly_name = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!cert_pem || !key_pem || !password) {
        Tcl_SetResult(interp, "Certificate, key, and password are required", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *key_bio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (!pkey) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    PKCS12 *p12 = PKCS12_create(password, friendly_name, pkey, cert, NULL, 0, 0, 0, 0, 0);
    if (!p12) {
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create PKCS12", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        PKCS12_free(p12);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (i2d_PKCS12_bio(out_bio, p12) <= 0) {
        BIO_free(out_bio);
        PKCS12_free(p12);
        EVP_PKEY_free(pkey);
        BIO_free(key_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to write PKCS12", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    X509_free(cert);
    BIO_free(cert_bio);
    return TCL_OK;
}

// PKCS#12 parse command
int Pkcs12ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs12_data password");
        return TCL_ERROR;
    }
    
    const char *pkcs12_data = Tcl_GetString(objv[1]);
    const char *password = Tcl_GetString(objv[2]);
    
    BIO *pkcs12_bio = BIO_new_mem_buf((void*)pkcs12_data, -1);
    PKCS12 *p12 = d2i_PKCS12_bio(pkcs12_bio, NULL);
    if (!p12) {
        BIO_free(pkcs12_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS12", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca_certs = NULL;
    
    if (PKCS12_parse(p12, password, &pkey, &cert, &ca_certs) <= 0) {
        PKCS12_free(p12);
        BIO_free(pkcs12_bio);
        Tcl_SetResult(interp, "Failed to parse PKCS12 contents", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Extract certificate
    if (cert) {
        BIO *cert_bio = BIO_new(BIO_s_mem());
        if (cert_bio) {
            if (PEM_write_bio_X509(cert_bio, cert) > 0) {
                BUF_MEM *cert_bptr;
                BIO_get_mem_ptr(cert_bio, &cert_bptr);
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("certificate", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(cert_bptr->data, cert_bptr->length));
            }
            BIO_free(cert_bio);
        }
    }
    
    // Extract private key
    if (pkey) {
        BIO *key_bio = BIO_new(BIO_s_mem());
        if (key_bio) {
            if (PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL) > 0) {
                BUF_MEM *key_bptr;
                BIO_get_mem_ptr(key_bio, &key_bptr);
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("private_key", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(key_bptr->data, key_bptr->length));
            }
            BIO_free(key_bio);
        }
    }
    
    // Extract CA certificates
    if (ca_certs) {
        int num_ca = sk_X509_num(ca_certs);
        if (num_ca > 0) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("ca_certificates", -1));
            Tcl_Obj *ca_list = Tcl_NewListObj(0, NULL);
            
            for (int i = 0; i < num_ca; i++) {
                X509 *ca_cert = sk_X509_value(ca_certs, i);
                BIO *ca_bio = BIO_new(BIO_s_mem());
                if (ca_bio) {
                    if (PEM_write_bio_X509(ca_bio, ca_cert) > 0) {
                        BUF_MEM *ca_bptr;
                        BIO_get_mem_ptr(ca_bio, &ca_bptr);
                        Tcl_ListObjAppendElement(interp, ca_list, Tcl_NewStringObj(ca_bptr->data, ca_bptr->length));
                    }
                    BIO_free(ca_bio);
                }
            }
            Tcl_ListObjAppendElement(interp, result, ca_list);
        }
    }
    
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (ca_certs) sk_X509_pop_free(ca_certs, X509_free);
    PKCS12_free(p12);
    BIO_free(pkcs12_bio);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 