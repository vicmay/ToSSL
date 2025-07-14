#include "tossl.h"

// Key wrapping command
int KeyWrapCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "kek_algorithm kek_key data");
        return TCL_ERROR;
    }
    
    const char *kek_algorithm = Tcl_GetString(objv[1]);
    const char *kek_key_data = Tcl_GetString(objv[2]);
    const char *data = Tcl_GetString(objv[3]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(kek_algorithm);
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported KEK algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Generate random IV for key wrapping
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) <= 0) {
        Tcl_SetResult(interp, "Failed to generate random IV", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)kek_key_data, iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key wrapping", TCL_STATIC);
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
        Tcl_SetResult(interp, "Failed to wrap key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, out + out_len, &final_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to finalize key wrapping", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine IV and wrapped data
    int total_len = EVP_CIPHER_iv_length(cipher) + out_len + final_len;
    unsigned char *result_data = malloc(total_len);
    if (!result_data) {
        free(out);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    memcpy(result_data, iv, EVP_CIPHER_iv_length(cipher));
    memcpy(result_data + EVP_CIPHER_iv_length(cipher), out, out_len + final_len);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(result_data, total_len);
    free(out);
    free(result_data);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Key unwrapping command
int KeyUnwrapCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "kek_algorithm kek_key wrapped_data");
        return TCL_ERROR;
    }
    
    const char *kek_algorithm = Tcl_GetString(objv[1]);
    const char *kek_key_data = Tcl_GetString(objv[2]);
    const char *wrapped_data = Tcl_GetString(objv[3]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(kek_algorithm);
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported KEK algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int data_len = strlen(wrapped_data);
    
    if (data_len <= iv_len) {
        Tcl_SetResult(interp, "Invalid wrapped data length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Extract IV and wrapped data
    unsigned char *iv = (unsigned char*)wrapped_data;
    unsigned char *encrypted_data = (unsigned char*)(wrapped_data + iv_len);
    int encrypted_len = data_len - iv_len;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)kek_key_data, iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to initialize key unwrapping", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int out_len;
    unsigned char *out = malloc(encrypted_len);
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DecryptUpdate(ctx, out, &out_len, encrypted_data, encrypted_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to unwrap key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, out + out_len, &final_len) <= 0) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "Failed to finalize key unwrapping", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(out, out_len + final_len);
    free(out);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// KEK generation command
int KekGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported KEK algorithm", TCL_STATIC);
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
        Tcl_SetResult(interp, "Failed to generate random KEK", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, key_len);
    free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// KEK algorithm list command
int KekAlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // List of KEK algorithms
    const char *kek_algorithms[] = {
        "aes-128-ecb", "aes-192-ecb", "aes-256-ecb",
        "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"
    };
    
    int num_algorithms = sizeof(kek_algorithms) / sizeof(kek_algorithms[0]);
    
    for (int i = 0; i < num_algorithms; i++) {
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(kek_algorithms[i]);
        if (cipher) {
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(kek_algorithms[i], -1));
        }
    }
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Key wrapping info command
int KeyWrapInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        Tcl_SetResult(interp, "Unsupported KEK algorithm", TCL_STATIC);
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