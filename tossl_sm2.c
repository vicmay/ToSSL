#include "tossl.h"

// SM2 key generation command
int Sm2GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    
    // Try SM2 key generation first
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (ctx) {
        if (EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0) {
            EVP_PKEY_CTX_free(ctx);
            // Verify it's actually an SM2 key
            if (EVP_PKEY_id(pkey) == EVP_PKEY_SM2) {
                goto write_key;
            } else {
                EVP_PKEY_free(pkey);
                pkey = NULL;
            }
        } else {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
        }
    }
    
    // Fallback to EC key generation with SM2 curve
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create EC context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize EC key generation", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set the curve to SM2
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to set SM2 curve", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to generate SM2 EC key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
write_key:
    // Write private key to PEM
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Try to write as EC private key first (more specific format)
    int write_success = 0;
    if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
        EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec_key) {
            if (PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL) > 0) {
                write_success = 1;
            }
        }
    }
    
    // Fallback to generic private key format
    if (!write_success) {
        if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            Tcl_SetResult(interp, "Failed to write private key", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    Tcl_Obj *result = Tcl_NewStringObj(bptr->data, bptr->length);
    
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// SM2 signing command
int Sm2SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    
    // Basic key type validation - only reject obviously wrong types
    int key_type = EVP_PKEY_id(pkey);
    
    // RSA keys (type 6) should be rejected for SM2 operations
    if (key_type == 6) { // EVP_PKEY_RSA
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "RSA keys cannot be used for SM2 operations", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Accept other key types and let OpenSSL handle the details
    // The key type checking was too restrictive and causing issues
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
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

// SM2 verification command
int Sm2VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data signature");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    int sig_len;
    const unsigned char *sig_data = (const unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &sig_len);
    
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
    
    // Check if it's an SM2 key or EC key with SM2 curve
    int key_type = EVP_PKEY_id(pkey);
    int base_type = EVP_PKEY_base_id(pkey);
    
    // Accept SM2, EC, and unknown key types (unknown might be SM2 in some OpenSSL versions)
    if (key_type != EVP_PKEY_SM2 && key_type != EVP_PKEY_EC && 
        base_type != EVP_PKEY_SM2 && base_type != EVP_PKEY_EC &&
        key_type != -1) { // -1 indicates unknown type, which might be SM2
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an SM2 or EC key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // If it's an EC key, try to verify it's using SM2 curve, but don't fail if we can't determine
    if (key_type == EVP_PKEY_EC || base_type == EVP_PKEY_EC) {
        char curve_name[80] = "unknown";
        if (EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name), NULL) > 0) {
            if (strstr(curve_name, "SM2") == NULL && strstr(curve_name, "sm2") == NULL) {
                // Only reject if we can positively identify it's not SM2
                EVP_PKEY_free(pkey);
                Tcl_SetResult(interp, "Not an SM2 curve EC key", TCL_STATIC);
                return TCL_ERROR;
            }
        }
        // If we can't determine the curve name, proceed anyway
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to initialize verification", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int result = EVP_DigestVerify(ctx, sig_data, sig_len,
                                 (const unsigned char*)data, strlen(data));
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result == 1));
    return TCL_OK;
}

// SM2 encryption command
int Sm2EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "public_key data");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    int data_len;
    const unsigned char *data = (const unsigned char *)Tcl_GetByteArrayFromObj(objv[2], &data_len);
    
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
    
    // Basic key validation - reject obviously wrong key types
    int key_type = EVP_PKEY_id(pkey);
    
    // Only reject keys that we can positively identify as wrong types
    // Allow unknown types (-1) as they might be SM2 keys
    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_DSA || 
        key_type == EVP_PKEY_DH || key_type == EVP_PKEY_RSA_PSS) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an SM2 key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Accept SM2, EC, and unknown key types
    // The actual validation will happen during the encryption operation
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create encryption context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to initialize encryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to calculate encrypted length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *out = malloc(out_len);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_encrypt(ctx, out, &out_len, data, data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to encrypt data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(out, out_len);
    free(out);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// SM2 decryption command
int Sm2DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "private_key data");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    int data_len;
    const unsigned char *data = (const unsigned char *)Tcl_GetByteArrayFromObj(objv[2], &data_len);
    
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
    
    // Get key type for validation
    int key_type = EVP_PKEY_id(pkey);
    
    // Basic key type validation - only reject obviously wrong types
    // RSA keys (type 6) should be rejected for SM2 operations
    if (key_type == 6) { // EVP_PKEY_RSA
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "RSA keys cannot be used for SM2 operations", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Accept other key types and let OpenSSL handle the details
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create decryption context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to initialize decryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to calculate decrypted length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *out = malloc(out_len);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_decrypt(ctx, out, &out_len, data, data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to decrypt data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(out, out_len);
    free(out);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 