#include "tossl.h"

// Ed25519 key generation command
int Ed25519GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create Ed25519 context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key generation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to generate Ed25519 key", TCL_STATIC);
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

// Ed25519 signing command
int Ed25519SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    
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
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an Ed25519 key", TCL_STATIC);
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
    if (EVP_DigestSign(ctx, NULL, &sig_len, (const unsigned char*)data, strlen(data)) <= 0) {
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
    
    if (EVP_DigestSign(ctx, sig, &sig_len, (const unsigned char*)data, strlen(data)) <= 0) {
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

// Ed25519 verification command
int Ed25519VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data signature");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    const char *sig_data = Tcl_GetString(objv[3]);
    
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
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an Ed25519 key", TCL_STATIC);
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
    
    int result = EVP_DigestVerify(ctx, (const unsigned char*)sig_data, strlen(sig_data),
                                 (const unsigned char*)data, strlen(data));
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result == 1));
    return TCL_OK;
}

// X25519 key generation command
int X25519GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create X25519 context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key generation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to generate X25519 key", TCL_STATIC);
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

// X25519 key derivation command
int X25519DeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    
    if (EVP_PKEY_id(priv_key) != EVP_PKEY_X25519) {
        EVP_PKEY_free(priv_key);
        Tcl_SetResult(interp, "Not an X25519 private key", TCL_STATIC);
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
    
    if (EVP_PKEY_id(pub_key) != EVP_PKEY_X25519) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        Tcl_SetResult(interp, "Not an X25519 public key", TCL_STATIC);
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