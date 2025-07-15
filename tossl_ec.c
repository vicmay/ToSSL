#include "tossl.h"

// EC curve list command
int EcListCurvesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    size_t num_curves = EC_get_builtin_curves(NULL, 0);
    
    if (num_curves > 0) {
        EC_builtin_curve *curves = malloc(num_curves * sizeof(EC_builtin_curve));
        if (!curves) {
            Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
            return TCL_ERROR;
        }
        
        if (EC_get_builtin_curves(curves, num_curves) == num_curves) {
            for (size_t i = 0; i < num_curves; i++) {
                Tcl_Obj *curve_info = Tcl_NewListObj(0, NULL);
                Tcl_ListObjAppendElement(interp, curve_info, 
                    Tcl_NewStringObj(curves[i].comment, -1));
                Tcl_ListObjAppendElement(interp, curve_info, 
                    Tcl_NewStringObj(OBJ_nid2sn(curves[i].nid), -1));
                Tcl_ListObjAppendElement(interp, result, curve_info);
            }
        }
        
        free(curves);
    }
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// EC key validation command
int EcValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "key");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(key_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an EC key", TCL_STATIC);
        return TCL_ERROR;
    }

    int result = modern_ec_validate_key(pkey);
    EVP_PKEY_free(pkey);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result == 1));
    return TCL_OK;
}

// EC signing command
int EcSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data digest");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    const char *digest_name = Tcl_GetString(objv[3]);
    
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
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an EC key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD *md = modern_digest_fetch(digest_name);
    if (!md) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Invalid digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0) {
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

// EC verification command
int EcVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data signature digest");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    const char *sig_data = Tcl_GetString(objv[3]);
    const char *digest_name = Tcl_GetString(objv[4]);
    
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
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an EC key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD *md = modern_digest_fetch(digest_name);
    if (!md) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Invalid digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) <= 0) {
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

// EC point addition command
int EcPointAddCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "curve point1 point2");
        return TCL_ERROR;
    }
    
    const char *curve_name = Tcl_GetString(objv[1]);
    const char *point1_data = Tcl_GetString(objv[2]);
    const char *point2_data = Tcl_GetString(objv[3]);
    
    int nid = OBJ_sn2nid(curve_name);
    if (nid == NID_undef) {
        Tcl_SetResult(interp, "Invalid curve name", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        Tcl_SetResult(interp, "Failed to create EC group", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EC_POINT *point1 = EC_POINT_new(group);
    EC_POINT *point2 = EC_POINT_new(group);
    EC_POINT *result_point = EC_POINT_new(group);
    
    if (!point1 || !point2 || !result_point) {
        EC_GROUP_free(group);
        if (point1) EC_POINT_free(point1);
        if (point2) EC_POINT_free(point2);
        if (result_point) EC_POINT_free(result_point);
        Tcl_SetResult(interp, "Failed to create EC points", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse points (assuming hex format)
    if (!EC_POINT_hex2point(group, point1_data, point1, NULL) ||
        !EC_POINT_hex2point(group, point2_data, point2, NULL)) {
        EC_GROUP_free(group);
        EC_POINT_free(point1);
        EC_POINT_free(point2);
        EC_POINT_free(result_point);
        Tcl_SetResult(interp, "Failed to parse EC points", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add points
    if (!EC_POINT_add(group, result_point, point1, point2, NULL)) {
        EC_GROUP_free(group);
        EC_POINT_free(point1);
        EC_POINT_free(point2);
        EC_POINT_free(result_point);
        Tcl_SetResult(interp, "Failed to add EC points", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert result to hex
    char *result_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    
    EC_GROUP_free(group);
    EC_POINT_free(point1);
    EC_POINT_free(point2);
    EC_POINT_free(result_point);
    
    if (!result_hex) {
        Tcl_SetResult(interp, "Failed to convert result to hex", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, result_hex, TCL_DYNAMIC);
    return TCL_OK;
}

// EC point multiplication command
int EcPointMultiplyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "curve point scalar");
        return TCL_ERROR;
    }
    
    const char *curve_name = Tcl_GetString(objv[1]);
    const char *point_data = Tcl_GetString(objv[2]);
    const char *scalar_data = Tcl_GetString(objv[3]);
    
    int nid = OBJ_sn2nid(curve_name);
    if (nid == NID_undef) {
        Tcl_SetResult(interp, "Invalid curve name", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        Tcl_SetResult(interp, "Failed to create EC group", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EC_POINT *point = EC_POINT_new(group);
    EC_POINT *result_point = EC_POINT_new(group);
    BIGNUM *scalar = BN_new();
    
    if (!point || !result_point || !scalar) {
        EC_GROUP_free(group);
        if (point) EC_POINT_free(point);
        if (result_point) EC_POINT_free(result_point);
        if (scalar) BN_free(scalar);
        Tcl_SetResult(interp, "Failed to create EC objects", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse point and scalar
    if (!EC_POINT_hex2point(group, point_data, point, NULL) ||
        !BN_hex2bn(&scalar, scalar_data)) {
        EC_GROUP_free(group);
        EC_POINT_free(point);
        EC_POINT_free(result_point);
        BN_free(scalar);
        Tcl_SetResult(interp, "Failed to parse point or scalar", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Multiply point by scalar
    if (!EC_POINT_mul(group, result_point, NULL, point, scalar, NULL)) {
        EC_GROUP_free(group);
        EC_POINT_free(point);
        EC_POINT_free(result_point);
        BN_free(scalar);
        Tcl_SetResult(interp, "Failed to multiply EC point", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert result to hex
    char *result_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    
    EC_GROUP_free(group);
    EC_POINT_free(point);
    EC_POINT_free(result_point);
    BN_free(scalar);
    
    if (!result_hex) {
        Tcl_SetResult(interp, "Failed to convert result to hex", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, result_hex, TCL_DYNAMIC);
    return TCL_OK;
}

// EC key components extraction command
int EcComponentsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "key");
        return TCL_ERROR;
    }
    
    const char *key_data = Tcl_GetString(objv[1]);
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(key_data, -1);
    
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        Tcl_SetResult(interp, "Failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Not an EC key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // For OpenSSL 3.0, we need to use EVP_PKEY_get_bn_param
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    if (modern_ec_get_key_params(pkey, &x, &y, &d) > 0) {
        if (x) {
            char *x_hex = BN_bn2hex(x);
            if (x_hex) {
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("x", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(x_hex, -1));
                OPENSSL_free(x_hex);
            }
            BN_free(x);
        }
        if (y) {
            char *y_hex = BN_bn2hex(y);
            if (y_hex) {
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("y", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(y_hex, -1));
                OPENSSL_free(y_hex);
            }
            BN_free(y);
        }
        if (d) {
            char *d_hex = BN_bn2hex(d);
            if (d_hex) {
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("d", -1));
                Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(d_hex, -1));
                OPENSSL_free(d_hex);
            }
            BN_free(d);
        }
    }
    EVP_PKEY_free(pkey);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 