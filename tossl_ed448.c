#include "tossl.h"

// Ed448 key generation command
int Ed448GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
    
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create Ed448 context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key generation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to generate Ed448 key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Write private key to PEM
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to write private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    Tcl_Obj *result = Tcl_NewStringObj(bptr->data, bptr->length);
    
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Ed448 signing command
int Ed448SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[2], &data_len);
    
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
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED448) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an Ed448 key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to initialize signing", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t sig_len;
    if (EVP_DigestSign(ctx, NULL, &sig_len, data, data_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to calculate signature length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSign(ctx, sig, &sig_len, data, data_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create signature", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(sig, sig_len);
    free(sig);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Ed448 verification command
int Ed448VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data signature");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    int data_len, sig_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[2], &data_len);
    unsigned char *sig_data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &sig_len);
    
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(key_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED448) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an Ed448 key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to initialize verification", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = EVP_DigestVerify(ctx, sig_data, sig_len, data, data_len);
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result == 1));
    return TCL_OK;
} 