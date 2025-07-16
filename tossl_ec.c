#include "tossl.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#ifndef OSSL_PKEY_PARAM_PUB_KEY
#define OSSL_PKEY_PARAM_PUB_KEY "pub"
#endif

#ifndef OSSL_PKEY_PARAM_PRIV_KEY
#define OSSL_PKEY_PARAM_PRIV_KEY "priv"
#endif

// For OpenSSL version compatibility
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "OpenSSL 1.1.0 or later is required"
#endif

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
    int siglen = 0;
    unsigned char *sig_data = Tcl_GetByteArrayFromObj(objv[3], &siglen);
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
    
    int result = EVP_DigestVerify(ctx, sig_data, siglen,
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

    // Defensive: check for NULL or empty strings
    if (!curve_name || !*curve_name || !point_data || !*point_data || !scalar_data || !*scalar_data) {
        Tcl_SetResult(interp, "Curve, point, and scalar must be non-empty", TCL_STATIC);
        return TCL_ERROR;
    }

    // Defensive: strip 0x prefix if present
    if (strncmp(point_data, "0x", 2) == 0) point_data += 2;
    if (strncmp(scalar_data, "0x", 2) == 0) scalar_data += 2;

    // Defensive: check for valid hex (point, allow colons)
    int hex_count = 0;
    for (const char *p = point_data; *p; ++p) {
        if (*p == ':') continue;
        if (!( (*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f') )) {
            Tcl_SetResult(interp, "Point must be a valid hex string (with or without colons)", TCL_STATIC);
            return TCL_ERROR;
        }
        hex_count++;
    }
    if (hex_count == 0) {
        Tcl_SetResult(interp, "Point must not be empty", TCL_STATIC);
        return TCL_ERROR;
    }
    // Defensive: check for valid hex (scalar)
    for (const char *p = scalar_data; *p; ++p) {
        if (!( (*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f') )) {
            Tcl_SetResult(interp, "Scalar must be a valid hex string", TCL_STATIC);
            return TCL_ERROR;
        }
    }

    // Allocate buffer for cleaned point hex (no colons)
    char *clean_point = (char *)malloc(hex_count + 1);
    if (!clean_point) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    int j = 0;
    for (const char *p = point_data; *p; ++p) {
        if (*p != ':') clean_point[j++] = *p;
    }
    clean_point[j] = '\0';

    // Remove all debug output
    int nid = OBJ_sn2nid(curve_name);
    if (nid == NID_undef) {
        free(clean_point);
        Tcl_SetResult(interp, "Invalid curve name", TCL_STATIC);
        return TCL_ERROR;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        free(clean_point);
        Tcl_SetResult(interp, "Failed to create EC group", TCL_STATIC);
        return TCL_ERROR;
    }

    EC_POINT *point = NULL;
    EC_POINT *result_point = EC_POINT_new(group);
    BIGNUM *scalar = NULL;

    if (!result_point) {
        EC_GROUP_free(group);
        Tcl_SetResult(interp, "Failed to create EC objects", TCL_STATIC);
        return TCL_ERROR;
    }

    // Parse point and scalar
    point = EC_POINT_hex2point(group, clean_point, NULL, NULL);
    int ok_scalar = BN_hex2bn(&scalar, scalar_data);
    free(clean_point);
    if (!point || !ok_scalar) {
        EC_GROUP_free(group);
        if (point) EC_POINT_free(point);
        EC_POINT_free(result_point);
        if (scalar) BN_free(scalar);
        Tcl_SetResult(interp, "Failed to parse point or scalar", TCL_STATIC);
        return TCL_ERROR;
    }

    // Multiply point by scalar
    int mul_ok = EC_POINT_mul(group, result_point, NULL, point, scalar, NULL);
    if (!mul_ok) {
        EC_GROUP_free(group);
        EC_POINT_free(point);
        EC_POINT_free(result_point);
        if (scalar) BN_free(scalar);
        Tcl_SetResult(interp, "Failed to multiply EC point", TCL_STATIC);
        return TCL_ERROR;
    }

    // Convert result to hex
    char *result_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    EC_POINT_free(point);
    EC_POINT_free(result_point);
    if (scalar) BN_free(scalar);
    EC_GROUP_free(group);

    if (!result_hex) {
        Tcl_SetResult(interp, "Failed to convert result to hex", TCL_STATIC);
        return TCL_ERROR;
    }

    Tcl_SetResult(interp, result_hex, TCL_VOLATILE); // Tcl will copy, we can free
    OPENSSL_free(result_hex);
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
    // Get the curve name
    char curve_name[80] = "unknown";
    int nid = 0;
    if (EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name), NULL) <= 0) {
        // Fallback to old method if new API fails
        nid = EVP_PKEY_get_bits(pkey); // This is not the curve name, just a fallback
        snprintf(curve_name, sizeof(curve_name), "curve-%d", nid);
    }

    // Get public key in hex format
    unsigned char *pub = NULL;
    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) == 1) {
        pub = OPENSSL_malloc(pub_len);
        if (pub && EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, NULL) != 1) {
            OPENSSL_free(pub);
            pub = NULL;
        }
    }

    // Get private key in hex format if available
    BIGNUM *priv_bn = NULL;
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn);

    // Create result dictionary
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve_name, -1));

    // Add public key if available
    if (pub) {
        char *pub_hex = OPENSSL_buf2hexstr(pub, pub_len);
        if (pub_hex) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_hex, -1));
            OPENSSL_free(pub_hex);
        }
        OPENSSL_free(pub);
    }

    // Add private key if available
    if (priv_bn) {
        char *priv_hex = BN_bn2hex(priv_bn);
        if (priv_hex) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_hex, -1));
            OPENSSL_free(priv_hex);
        }
        BN_free(priv_bn);
    }
    EVP_PKEY_free(pkey);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
} 