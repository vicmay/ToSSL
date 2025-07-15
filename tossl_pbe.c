#include "tossl.h"

// PBE encryption command
int PbeEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm password salt data");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *password = Tcl_GetString(objv[2]);
    const char *salt_data = Tcl_GetString(objv[3]);
    const char *data = Tcl_GetString(objv[4]);
    
    // Parse salt
    int salt_len = strlen(salt_data);
    (void)algorithm; // Suppress unused variable warning
    (void)salt_len;  // Suppress unused variable warning
    unsigned char *salt = (unsigned char*)salt_data;
    
    // Generate key and IV from password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                       (const unsigned char*)password, strlen(password), 
                       1, key, iv) <= 0) {
        Tcl_SetResult(interp, "Failed to derive key from password", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Encrypt data
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
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

// PBE decryption command
int PbeDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm password salt data");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *password = Tcl_GetString(objv[2]);
    const char *salt_data = Tcl_GetString(objv[3]);
    const char *data = Tcl_GetString(objv[4]);
    
    // Parse salt
    int salt_len = strlen(salt_data);
    (void)algorithm; // Suppress unused variable warning
    (void)salt_len;  // Suppress unused variable warning
    unsigned char *salt = (unsigned char*)salt_data;
    
    // Generate key and IV from password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                       (const unsigned char*)password, strlen(password), 
                       1, key, iv) <= 0) {
        Tcl_SetResult(interp, "Failed to derive key from password", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Decrypt data
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
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

// PBE salt generation command
int PbeSaltGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "length");
        return TCL_ERROR;
    }
    
    int salt_len = atoi(Tcl_GetString(objv[1]));
    if (salt_len <= 0 || salt_len > 64) {
        Tcl_SetResult(interp, "Invalid salt length (1-64 bytes)", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *salt = malloc(salt_len);
    if (!salt) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(salt, salt_len) <= 0) {
        free(salt);
        Tcl_SetResult(interp, "Failed to generate random salt", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(salt, salt_len);
    free(salt);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// PBE key derivation command
int PbeKeyDeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm password salt iterations key_length");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *password = Tcl_GetString(objv[2]);
    const char *salt_data = Tcl_GetString(objv[3]);
    int iterations = atoi(Tcl_GetString(objv[4]));
    int key_length = atoi(Tcl_GetString(objv[5]));
    
    if (iterations <= 0 || key_length <= 0) {
        Tcl_SetResult(interp, "Invalid iterations or key length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse salt
    int salt_len = strlen(salt_data);
    (void)algorithm; // Suppress unused variable warning
    (void)salt_len;  // Suppress unused variable warning
    unsigned char *salt = (unsigned char*)salt_data;
    
    // Derive key using PBKDF2
    unsigned char *key = malloc(key_length);
    if (!key) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md) {
        free(key);
        Tcl_SetResult(interp, "Unsupported digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, 
                          iterations, md, key_length, key) <= 0) {
        free(key);
        Tcl_SetResult(interp, "Failed to derive key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, key_length);
    free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// PBE algorithm list command
int PbeAlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // List of PBE algorithms
    const char *pbe_algorithms[] = {
        "sha1", "sha256", "sha512", "md5"
    };
    
    int num_algorithms = sizeof(pbe_algorithms) / sizeof(pbe_algorithms[0]);
    
    for (int i = 0; i < num_algorithms; i++) {
        const EVP_MD *md = EVP_get_digestbyname(pbe_algorithms[i]);
        if (md) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(pbe_algorithms[i], -1));
        }
    }
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 