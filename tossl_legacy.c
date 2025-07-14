#include "tossl.h"

// Legacy cipher encryption command
int LegacyEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm key iv data");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *key_data = Tcl_GetString(objv[2]);
    const char *iv_data = Tcl_GetString(objv[3]);
    const char *data = Tcl_GetString(objv[4]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported legacy cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key_data, (const unsigned char*)iv_data) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize encryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int data_len = strlen(data);
    int out_len;
    unsigned char *out = malloc(data_len + EVP_MAX_BLOCK_LENGTH);
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_EncryptUpdate(ctx, out, &out_len, (const unsigned char*)data, data_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to encrypt data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, out + out_len, &final_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to finalize encryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(out, out_len + final_len);
    free(out);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Legacy cipher decryption command
int LegacyDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm key iv data");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *key_data = Tcl_GetString(objv[2]);
    const char *iv_data = Tcl_GetString(objv[3]);
    const char *data = Tcl_GetString(objv[4]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported legacy cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key_data, (const unsigned char*)iv_data) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize decryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int data_len = strlen(data);
    int out_len;
    unsigned char *out = malloc(data_len);
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DecryptUpdate(ctx, out, &out_len, (const unsigned char*)data, data_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to decrypt data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, out + out_len, &final_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to finalize decryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(out, out_len + final_len);
    free(out);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Legacy cipher list command
int LegacyCipherListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // List of legacy ciphers
    const char *legacy_ciphers[] = {
        "des-ecb", "des-cbc", "des-cfb", "des-ofb",
        "des-ede", "des-ede-cbc", "des-ede-cfb", "des-ede-ofb",
        "des-ede3", "des-ede3-cbc", "des-ede3-cfb", "des-ede3-ofb",
        "bf-ecb", "bf-cbc", "bf-cfb", "bf-ofb",
        "cast5-ecb", "cast5-cbc", "cast5-cfb", "cast5-ofb",
        "rc4", "rc4-40",
        "rc5-ecb", "rc5-cbc", "rc5-cfb", "rc5-ofb"
    };
    
    int num_ciphers = sizeof(legacy_ciphers) / sizeof(legacy_ciphers[0]);
    
    for (int i = 0; i < num_ciphers; i++) {
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(legacy_ciphers[i]);
        if (cipher) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(legacy_ciphers[i], -1));
        }
    }
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Legacy cipher info command
int LegacyCipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported legacy cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Get cipher information
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("name", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(EVP_CIPHER_name(cipher), -1));
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("block_size", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(EVP_CIPHER_block_size(cipher)));
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("key_length", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(EVP_CIPHER_key_length(cipher)));
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("iv_length", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(EVP_CIPHER_iv_length(cipher)));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Legacy cipher key generation command
int LegacyKeyGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported legacy cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len = EVP_CIPHER_key_length(cipher);
    unsigned char *key = malloc(key_len);
    if (!key) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(key, key_len) <= 0) {
        free(key);
        Tcl_SetResult(interp, "Failed to generate random key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, key_len);
    free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Legacy cipher IV generation command
int LegacyIvGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported legacy cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int iv_len = EVP_CIPHER_iv_length(cipher);
    if (iv_len <= 0) {
        Tcl_SetResult(interp, "This cipher does not require an IV", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *iv = malloc(iv_len);
    if (!iv) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(iv, iv_len) <= 0) {
        free(iv);
        Tcl_SetResult(interp, "Failed to generate random IV", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(iv, iv_len);
    free(iv);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 