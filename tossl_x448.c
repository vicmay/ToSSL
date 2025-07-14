#include "tossl.h"

// X448 key generation command
int X448GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);
    
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create X448 context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key generation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to generate X448 key", TCL_STATIC);
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

// X448 key derivation command
int X448DeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "private_key public_key");
        return TCL_ERROR;
    }
    
    const char *priv_key_data = Tcl_GetString(objv[1]);
    const char *pub_key_data = Tcl_GetString(objv[2]);
    
    EVP_PKEY *priv_key = NULL, *pub_key = NULL;
    BIO *bio = BIO_new_mem_buf(priv_key_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!priv_key) {
        Tcl_SetResult(interp, "Failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_id(priv_key) != EVP_PKEY_X448) {
        EVP_PKEY_free(priv_key);
        Tcl_SetResult(interp, "Not an X448 private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    bio = BIO_new_mem_buf(pub_key_data, -1);
    if (!bio) {
        EVP_PKEY_free(priv_key);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pub_key) {
        EVP_PKEY_free(priv_key);
        Tcl_SetResult(interp, "Failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_id(pub_key) != EVP_PKEY_X448) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Not an X448 public key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Failed to create key derivation context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Failed to initialize key derivation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Failed to set peer key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t shared_len;
    if (EVP_PKEY_derive(ctx, NULL, &shared_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Failed to calculate shared secret length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *shared = malloc(shared_len);
    if (!shared) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_derive(ctx, shared, &shared_len) <= 0) {
        free(shared);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Failed to derive shared secret", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(shared, shared_len);
    free(shared);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 