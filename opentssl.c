#include <tcl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/macros.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>

// KeyUsage bitmask values (OpenSSL defines these in x509v3.h, but for clarity):
#ifndef KU_DIGITAL_SIGNATURE
#define KU_DIGITAL_SIGNATURE    0x80
#define KU_NON_REPUDIATION     0x40
#define KU_KEY_ENCIPHERMENT    0x20
#define KU_DATA_ENCIPHERMENT   0x10
#define KU_KEY_AGREEMENT       0x08
#define KU_KEY_CERT_SIGN       0x04
#define KU_CRL_SIGN            0x02
#define KU_ENCIPHER_ONLY       0x01
#define KU_DECIPHER_ONLY       0x8000
#endif

// Prototype for bin2hex
static void bin2hex(const unsigned char *in, int len, char *out);

// opentssl::hmac -alg <name> -key <key> <data>
static int HmacCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -key key data");
        return TCL_ERROR;
    }
    const char *alg = NULL;
    unsigned char *key = NULL, *data = NULL;
    int keylen = 0, datalen = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &keylen);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);

    int rc = TCL_ERROR;
    unsigned char mac[EVP_MAX_MD_SIZE];
    char hex[2*EVP_MAX_MD_SIZE+1];
    EVP_MAC *mac_algo = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    size_t outlen = sizeof(mac);

    mac_algo = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac_algo) {
        Tcl_SetResult(interp, "OpenSSL: HMAC fetch failed", TCL_STATIC);
        goto cleanup;
    }
    ctx = EVP_MAC_CTX_new(mac_algo);
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: HMAC ctx alloc failed", TCL_STATIC);
        goto cleanup;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)alg, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx, key, keylen, params)) {
        Tcl_SetResult(interp, "OpenSSL: HMAC init failed", TCL_STATIC);
        goto cleanup;
    }
    if (!EVP_MAC_update(ctx, data, datalen)) {
        Tcl_SetResult(interp, "OpenSSL: HMAC update failed", TCL_STATIC);
        goto cleanup;
    }
    if (!EVP_MAC_final(ctx, mac, &outlen, sizeof(mac))) {
        Tcl_SetResult(interp, "OpenSSL: HMAC final failed", TCL_STATIC);
        goto cleanup;
    }
    bin2hex(mac, (int)outlen, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    rc = TCL_OK;
cleanup:
    if (ctx) EVP_MAC_CTX_free(ctx);
    if (mac_algo) EVP_MAC_free(mac_algo);
    return rc;
}

// opentssl::key::parse <pem|der>
static int KeyParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem|der");
        return TCL_ERROR;
    }
    int input_len;
    unsigned char *input = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &input_len);
    // Try as PEM
    BIO *bio = BIO_new_mem_buf((void*)input, input_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as DER
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)input, input_len);
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    if (pkey) {
        int bits = EVP_PKEY_get_bits(pkey);
        int type = EVP_PKEY_base_id(pkey);
        Tcl_Obj *dict = Tcl_NewDictObj();
        if (type == EVP_PKEY_RSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("rsa", -1));
        } else if (type == EVP_PKEY_DSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        } else if (type == EVP_PKEY_EC) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("ec", -1));
            char curve[80] = {0};
            OSSL_PARAM params[2] = { OSSL_PARAM_utf8_string("group", curve, sizeof(curve)), OSSL_PARAM_END };
            EVP_PKEY_get_params(pkey, params);
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve[0] ? curve : "unknown", -1));
        } else {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("unknown", -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kind", -1), Tcl_NewStringObj("private", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
        Tcl_SetObjResult(interp, dict);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return TCL_OK;
    }
    // Try as public key PEM
    BIO_free(bio);
    bio = BIO_new_mem_buf((void*)input, input_len);
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as public key DER
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)input, input_len);
        pkey = d2i_PUBKEY_bio(bio, NULL);
    }
    if (pkey) {
        int bits = EVP_PKEY_get_bits(pkey);
        int type = EVP_PKEY_base_id(pkey);
        Tcl_Obj *dict = Tcl_NewDictObj();
        if (type == EVP_PKEY_RSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("rsa", -1));
        } else if (type == EVP_PKEY_DSA) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        } else if (type == EVP_PKEY_EC) {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("ec", -1));
            char curve[80] = {0};
            OSSL_PARAM params[2] = { OSSL_PARAM_utf8_string("group", curve, sizeof(curve)), OSSL_PARAM_END };
            EVP_PKEY_get_params(pkey, params);
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve[0] ? curve : "unknown", -1));
        } else {
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("unknown", -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kind", -1), Tcl_NewStringObj("public", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
        Tcl_SetObjResult(interp, dict);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return TCL_OK;
    }
    BIO_free(bio);
    Tcl_SetResult(interp, "Not a valid RSA, DSA, or EC PEM/DER key", TCL_STATIC);
    return TCL_ERROR;
}

// opentssl::key::write -key <key> -format <pem|der>
static int KeyWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key dict -format pem");
        return TCL_ERROR;
    }
    const char *format = NULL;
    Tcl_Obj *keyDict = NULL;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            keyDict = objv[i+1];
        } else if (strcmp(opt, "-format") == 0) {
            format = Tcl_GetString(objv[i+1]);
        }
    }
    if (!keyDict || !format) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *typeObj = NULL, *kindObj = NULL, *pemObj = NULL;
    if (Tcl_DictObjGet(interp, keyDict, Tcl_NewStringObj("type", -1), &typeObj) != TCL_OK || !typeObj ||
        Tcl_DictObjGet(interp, keyDict, Tcl_NewStringObj("kind", -1), &kindObj) != TCL_OK || !kindObj ||
        Tcl_DictObjGet(interp, keyDict, Tcl_NewStringObj("pem", -1), &pemObj) != TCL_OK || !pemObj) {
        Tcl_SetResult(interp, "Key dict must have 'type', 'kind', and 'pem' fields", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *type = Tcl_GetString(typeObj);
    if (strcmp(type, "rsa") == 0 || strcmp(type, "dsa") == 0 || strcmp(type, "ec") == 0) {
        Tcl_SetObjResult(interp, pemObj);
        return TCL_OK;
    } else {
        Tcl_SetResult(interp, "Only RSA, DSA, and EC keys are supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
}

// opentssl::key::generate ?-type <rsa> ?-bits <n>?
static int KeyGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;

    const char *type = "rsa";
    int bits = 2048;
    // Parse options
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-type") == 0 && i+1 < objc) {
            type = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-bits") == 0 && i+1 < objc) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &bits) != TCL_OK || bits < 512) {
                Tcl_SetResult(interp, "Invalid bit size", TCL_STATIC);
                return TCL_ERROR;
            }
        }
    }
    if (strcmp(type, "rsa") != 0 && strcmp(type, "dsa") != 0 && strcmp(type, "ec") != 0) {
        Tcl_SetResult(interp, "Only RSA, DSA, and EC supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
    // Generate RSA key
    BIO *priv = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    if (strcmp(type, "rsa") == 0) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY *pkey = NULL;
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (ctx) EVP_PKEY_CTX_free(ctx);
            if (pkey) EVP_PKEY_free(pkey);
            BIO_free(priv);
            BIO_free(pub);
            Tcl_SetResult(interp, "OpenSSL: RSA generation failed", TCL_STATIC);
            return TCL_ERROR;
        }
        PEM_write_bio_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_PUBKEY(pub, pkey);
        int keybits = EVP_PKEY_get_bits(pkey);
        char *priv_pem = NULL, *pub_pem = NULL;
        long priv_len = BIO_get_mem_data(priv, &priv_pem);
        long pub_len = BIO_get_mem_data(pub, &pub_pem);
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_pem, pub_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_pem, priv_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("rsa", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(keybits));
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free(priv);
        BIO_free(pub);
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else if (strcmp(type, "dsa") == 0) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
        EVP_PKEY *pkey = NULL;
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (ctx) EVP_PKEY_CTX_free(ctx);
            if (pkey) EVP_PKEY_free(pkey);
            BIO_free(priv);
            BIO_free(pub);
            Tcl_SetResult(interp, "OpenSSL: DSA generation failed", TCL_STATIC);
            return TCL_ERROR;
        }
        PEM_write_bio_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_PUBKEY(pub, pkey);
        int keybits = EVP_PKEY_get_bits(pkey);
        char *priv_pem = NULL, *pub_pem = NULL;
        long priv_len = BIO_get_mem_data(priv, &priv_pem);
        long pub_len = BIO_get_mem_data(pub, &pub_pem);
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_pem, pub_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_pem, priv_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(keybits));
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free(priv);
        BIO_free(pub);
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else if (strcmp(type, "ec") == 0) {
        const char *curve = "prime256v1";
        for (int i = 1; i < objc; i += 2) {
            const char *opt = Tcl_GetString(objv[i]);
            if (strcmp(opt, "-curve") == 0 && i+1 < objc) {
                curve = Tcl_GetString(objv[i+1]);
            }
        }
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY *pkey = NULL;
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_sn2nid(curve)) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (ctx) EVP_PKEY_CTX_free(ctx);
            if (pkey) EVP_PKEY_free(pkey);
            BIO_free(priv);
            BIO_free(pub);
            Tcl_SetResult(interp, "OpenSSL: EC key generation failed", TCL_STATIC);
            return TCL_ERROR;
        }
        PEM_write_bio_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_PUBKEY(pub, pkey);
        int keybits = EVP_PKEY_get_bits(pkey);
        char *priv_pem = NULL, *pub_pem = NULL;
        long priv_len = BIO_get_mem_data(priv, &priv_pem);
        long pub_len = BIO_get_mem_data(pub, &pub_pem);
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_pem, pub_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_pem, priv_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("ec", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("curve", -1), Tcl_NewStringObj(curve, -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(keybits));
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free(priv);
        BIO_free(pub);
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else if (strcmp(type, "dsa") == 0) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
        EVP_PKEY *pkey = NULL;
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (ctx) EVP_PKEY_CTX_free(ctx);
            if (pkey) EVP_PKEY_free(pkey);
            BIO_free(priv);
            BIO_free(pub);
            Tcl_SetResult(interp, "OpenSSL: DSA generation failed", TCL_STATIC);
            return TCL_ERROR;
        }
        PEM_write_bio_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_PUBKEY(pub, pkey);
        int keybits = EVP_PKEY_get_bits(pkey);
        char *priv_pem = NULL, *pub_pem = NULL;
        long priv_len = BIO_get_mem_data(priv, &priv_pem);
        long pub_len = BIO_get_mem_data(pub, &pub_pem);
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_pem, pub_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_pem, priv_len));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("dsa", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(keybits));
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free(priv);
        BIO_free(pub);
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    }
    return TCL_ERROR;
}

// Helper: Convert binary to hex string
static void bin2hex(const unsigned char *in, int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; ++i) {
        out[2*i] = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

// opentssl::base64::encode <data>
static int Base64EncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &datalen);
    int enclen = 4 * ((datalen + 2) / 3);
    unsigned char *enc = (unsigned char *)ckalloc(enclen + 1);
    int outlen = EVP_EncodeBlock(enc, data, datalen);
    enc[outlen] = '\0';
    Tcl_SetObjResult(interp, Tcl_NewStringObj((const char *)enc, outlen));
    ckfree((char *)enc);
    return TCL_OK;
}

// opentssl::base64::decode <base64>
static int Base64DecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "base64");
        return TCL_ERROR;
    }
    int inlen;
    const char *in = Tcl_GetStringFromObj(objv[1], &inlen);
    int declen = (inlen / 4) * 3;
    unsigned char *dec = (unsigned char *)ckalloc(declen + 1);
    int outlen = EVP_DecodeBlock(dec, (const unsigned char *)in, inlen);
    // Remove any trailing padding bytes (\0 from EVP_DecodeBlock is not counted)
    if (outlen > 0) {
        // Remove trailing zero bytes if base64 was padded
        while (outlen > 0 && dec[outlen - 1] == '\0') outlen--;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(dec, outlen));
    ckfree((char *)dec);
    return TCL_OK;
}

// opentssl::hex::encode <data>
static int HexEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
        return TCL_ERROR;
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &datalen);
    char *hex = (char *)ckalloc(2 * datalen + 1);
    bin2hex(data, datalen, hex);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(hex, 2 * datalen));
    ckfree(hex);
    return TCL_OK;
}

// opentssl::hex::decode <hex>
static int HexDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "hex");
        return TCL_ERROR;
    }
    int hexlen;
    const char *hex = Tcl_GetStringFromObj(objv[1], &hexlen);
    if (hexlen % 2 != 0) {
        Tcl_SetResult(interp, "Hex string must have even length", TCL_STATIC);
        return TCL_ERROR;
    }
    int outlen = hexlen / 2;
    unsigned char *out = (unsigned char *)ckalloc(outlen);
    for (int i = 0; i < outlen; ++i) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            ckfree((char *)out);
            Tcl_SetResult(interp, "Invalid hex digit", TCL_STATIC);
            return TCL_ERROR;
        }
        out[i] = (unsigned char)b;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, outlen));
    ckfree((char *)out);
    return TCL_OK;
}


// opentssl::digest -alg <name> <data>
static int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name data");
        return TCL_ERROR;
    }
    // Parse arguments
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-alg") != 0) {
        Tcl_SetResult(interp, "Expected -alg option", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[2]);
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &datalen);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create context", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, data, datalen) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hashlen)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest error", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX_free(mdctx);
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hashlen, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    return TCL_OK;
}


// opentssl::randbytes nbytes
static int RandBytesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "nbytes");
        return TCL_ERROR;
    }
    int nbytes;
    if (Tcl_GetIntFromObj(interp, objv[1], &nbytes) != TCL_OK || nbytes <= 0 || nbytes > 4096) {
        Tcl_SetResult(interp, "nbytes must be an integer between 1 and 4096", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char buf[4096];
    if (RAND_bytes(buf, nbytes) != 1) {
        Tcl_SetResult(interp, "OpenSSL: RAND_bytes failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buf, nbytes));
    return TCL_OK;
}

// opentssl::encrypt -alg <name> -key <key> -iv <iv> <data>
static int EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 8) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -key key -iv iv data");
        return TCL_ERROR;
    }
    const char *alg = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    int keylen = 0, ivlen = 0, datalen = 0;
    for (int i = 1; i < 7; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &keylen);
        } else if (strcmp(opt, "-iv") == 0) {
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &ivlen);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[7], &datalen);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: EncryptInit failed", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char outbuf[datalen + EVP_CIPHER_block_size(cipher)];
    int outlen = 0, tmplen = 0;
    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, data, datalen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: EncryptUpdate failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: EncryptFinal failed", TCL_STATIC);
        return TCL_ERROR;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(outbuf, outlen));
    return TCL_OK;
}

// opentssl::decrypt -alg <name> -key <key> -iv <iv> <data>
static int DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 8) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -key key -iv iv data");
        return TCL_ERROR;
    }
    const char *alg = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    int keylen = 0, ivlen = 0, datalen = 0;
    for (int i = 1; i < 7; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &keylen);
        } else if (strcmp(opt, "-iv") == 0) {
            iv = (unsigned char *)Tcl_GetByteArrayFromObj(objv[i+1], &ivlen);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[7], &datalen);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create cipher context", TCL_STATIC);
        return TCL_ERROR;
    }
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DecryptInit failed", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char outbuf[datalen + EVP_CIPHER_block_size(cipher)];
    int outlen = 0, tmplen = 0;
    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, data, datalen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DecryptUpdate failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DecryptFinal failed (bad padding or key?)", TCL_STATIC);
        return TCL_ERROR;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(outbuf, outlen));
    return TCL_OK;
}

#include <openssl/pem.h>
#include <openssl/rsa.h>

// opentssl::rsa::generate ?-bits n?
static int RsaGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    int bits = 2048;
    if (objc == 3) {
        const char *opt = Tcl_GetString(objv[1]);
        if (strcmp(opt, "-bits") != 0) {
            Tcl_SetResult(interp, "Expected -bits option", TCL_STATIC);
            return TCL_ERROR;
        }
        if (Tcl_GetIntFromObj(interp, objv[2], &bits) != TCL_OK || bits < 512) {
            Tcl_SetResult(interp, "Invalid bit size", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-bits n?");
        return TCL_ERROR;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "OpenSSL: RSA key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    // Write private key to PEM
    BIO *priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
    char *priv_pem = NULL;
    long priv_len = BIO_get_mem_data(priv, &priv_pem);
    // Write public key to PEM
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub, pkey);
    char *pub_pem = NULL;
    long pub_len = BIO_get_mem_data(pub, &pub_pem);
    // Build result dict
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("public", -1), Tcl_NewStringObj(pub_pem, pub_len));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("private", -1), Tcl_NewStringObj(priv_pem, priv_len));
    Tcl_SetObjResult(interp, dict);
    // Cleanup
    BIO_free(priv);
    BIO_free(pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return TCL_OK;
}

// opentssl::rsa::encrypt -pubkey <pem> <data>
static int RsaEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pubkey pem data");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-pubkey") != 0) {
        Tcl_SetResult(interp, "Expected -pubkey option", TCL_STATIC);
        return TCL_ERROR;
    }
    int pem_len;
    const char *pem = Tcl_GetStringFromObj(objv[2], &pem_len);
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &datalen);
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_CTX allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_encrypt_init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data, datalen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_encrypt (size) failed", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char *out = (unsigned char *)ckalloc(outlen);
    if (EVP_PKEY_encrypt(ctx, out, &outlen, data, datalen) <= 0) {
        ckfree((char *)out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_encrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, outlen));
    ckfree((char *)out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

// opentssl::rsa::decrypt -privkey <pem> <ciphertext>
static int RsaDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-privkey pem ciphertext");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-privkey") != 0) {
        Tcl_SetResult(interp, "Expected -privkey option", TCL_STATIC);
        return TCL_ERROR;
    }
    int pem_len;
    const char *pem = Tcl_GetStringFromObj(objv[2], &pem_len);
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &datalen);
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_CTX allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_decrypt_init failed", TCL_STATIC);
        return TCL_ERROR;
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, data, datalen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_decrypt (size) failed", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char *out = (unsigned char *)ckalloc(outlen);
    if (EVP_PKEY_decrypt(ctx, out, &outlen, data, datalen) <= 0) {
        ckfree((char *)out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: EVP_PKEY_decrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, outlen));
    ckfree((char *)out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return TCL_OK;
}

#include <openssl/x509.h>
#include <openssl/asn1.h>

// opentssl::x509::parse <pem>
static int X509ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem");
        return TCL_ERROR;
    }
    int pem_len;
    const char *pem = Tcl_GetStringFromObj(objv[1], &pem_len);
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse X.509 certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *dict = Tcl_NewDictObj();
    // Subject
    char subj[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("subject", -1), Tcl_NewStringObj(subj, -1));
    // Issuer
    char issuer[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
    // Serial
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    char *serial_hex = BN_bn2hex(bn);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("serial", -1), Tcl_NewStringObj(serial_hex, -1));
    BN_free(bn);
    OPENSSL_free(serial_hex);
    // Validity
    const ASN1_TIME *notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
    BIO *mem = BIO_new(BIO_s_mem());
    ASN1_TIME_print(mem, notBefore);
    char notbefore_str[64] = {0};
    BIO_read(mem, notbefore_str, sizeof(notbefore_str)-1);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("notBefore", -1), Tcl_NewStringObj(notbefore_str, -1));
    BIO_reset(mem);
    ASN1_TIME_print(mem, notAfter);
    char notafter_str[64] = {0};
    BIO_read(mem, notafter_str, sizeof(notafter_str)-1);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("notAfter", -1), Tcl_NewStringObj(notafter_str, -1));
    BIO_free(mem);
    // Subject Alternative Name (SAN)
    STACK_OF(GENERAL_NAME) *san_names = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        Tcl_Obj *sanList = Tcl_NewListObj(0, NULL);
        int num = sk_GENERAL_NAME_num(san_names);
        for (int i = 0; i < num; ++i) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS) {
                const unsigned char *dns = ASN1_STRING_get0_data(name->d.dNSName);
                int len = ASN1_STRING_length(name->d.dNSName);
                Tcl_ListObjAppendElement(interp, sanList, Tcl_NewStringObj((const char*)dns, len));
            } else if (name->type == GEN_IPADD) {
                const unsigned char *ip = ASN1_STRING_get0_data(name->d.iPAddress);
                int len = ASN1_STRING_length(name->d.iPAddress);
                char ipstr[64] = {0};
                if (len == 4) { // IPv4
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    Tcl_ListObjAppendElement(interp, sanList, Tcl_NewStringObj(ipstr, -1));
                } else if (len == 16) { // IPv6
                    snprintf(ipstr, sizeof(ipstr), "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                        ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
                    Tcl_ListObjAppendElement(interp, sanList, Tcl_NewStringObj(ipstr, -1));
                }
            }
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("san", -1), sanList);
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }

    // Cleanup
    X509_free(cert);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

// opentssl::dsa::sign -privkey <pem> -alg <digest> <data>
static int DsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-privkey pem -alg digest data");
        return TCL_ERROR;
    }
    const char *privkey = NULL, *alg = NULL;
    int privkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    BIO *bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
        if (pkey) EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse DSA private key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char sig[EVP_PKEY_size(pkey)];
    size_t siglen = 0;
    int ok = EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestSignUpdate(mdctx, data, datalen) &&
             EVP_DigestSignFinal(mdctx, sig, &siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    if (!ok) {
        Tcl_SetResult(interp, "OpenSSL: DSA signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, siglen));
    return TCL_OK;
}

// opentssl::dsa::verify -pubkey <pem> -alg <digest> <data> <signature>
static int DsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pubkey pem -alg digest data signature");
        return TCL_ERROR;
    }
    const char *pubkey = NULL, *alg = NULL;
    int pubkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen, siglen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(objv[6], &siglen);
    BIO *bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
        if (pkey) EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse DSA public key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    int ok = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestVerifyUpdate(mdctx, data, datalen) &&
             EVP_DigestVerifyFinal(mdctx, sig, siglen) == 1;
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok));
    return TCL_OK;
}

// opentssl::pkcs12::parse <data>
static int Pkcs12ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs12_data");
        return TCL_ERROR;
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &datalen);
    BIO *bio = BIO_new_mem_buf(data, datalen);
    if (!bio) {
        Tcl_SetResult(interp, "OpenSSL: BIO_new_mem_buf failed", TCL_STATIC);
        return TCL_ERROR;
    }
    PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
    if (!p12) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse PKCS#12", TCL_STATIC);
        return TCL_ERROR;
    }
    // Try with empty password
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ok = PKCS12_parse(p12, "", &pkey, &cert, &ca);
    if (!ok) {
        // Try with 'password' if empty fails (common default)
        ok = PKCS12_parse(p12, "password", &pkey, &cert, &ca);
    }
    if (!ok) {
        PKCS12_free(p12);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: PKCS12_parse failed (try with/without password)", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *dict = Tcl_NewDictObj();
    // Private key
    if (pkey) {
        BIO *mem = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL);
        char *pem = NULL;
        long pemlen = BIO_get_mem_data(mem, &pem);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key", -1), Tcl_NewStringObj(pem, pemlen));
        BIO_free(mem);
    }
    // Certificate
    if (cert) {
        BIO *mem = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(mem, cert);
        char *pem = NULL;
        long pemlen = BIO_get_mem_data(mem, &pem);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("cert", -1), Tcl_NewStringObj(pem, pemlen));
        BIO_free(mem);
    }
    // CA chain
    if (ca && sk_X509_num(ca) > 0) {
        Tcl_Obj *caList = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < sk_X509_num(ca); ++i) {
            X509 *cacert = sk_X509_value(ca, i);
            BIO *mem = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(mem, cacert);
            char *pem = NULL;
            long pemlen = BIO_get_mem_data(mem, &pem);
            Tcl_ListObjAppendElement(interp, caList, Tcl_NewStringObj(pem, pemlen));
            BIO_free(mem);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("ca", -1), caList);
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);
    PKCS12_free(p12);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// opentssl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?
static int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// opentssl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?
static int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// opentssl::pkcs7::encrypt -cert <cert> <data> ?-pem 0|1?
static int Pkcs7EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *cert_pem = NULL;
    int cert_len = 0, data_len = 0;
    int pemout = 1; // Default: PEM output
    Tcl_Obj *dataObj = NULL;
    // Parse options: -cert <cert> <data> ?-pem 0|1?
    int i = 1;
    for (; i + 1 < objc - 1; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-pem") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemout) != TCL_OK) return TCL_ERROR;
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (i >= objc) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert cert data ?-pem 0|1?");
        return TCL_ERROR;
    }
    dataObj = objv[objc-1];
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(dataObj, &data_len);
    // Load cert
    BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(certbio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse cert", TCL_STATIC);
        return TCL_ERROR;
    }
    // Create cert stack
    STACK_OF(X509) *recips = sk_X509_new_null();
    sk_X509_push(recips, cert);
    // Prepare data
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    // Encrypt
    PKCS7 *p7 = PKCS7_encrypt(recips, databio, EVP_aes_256_cbc(), 0);
    if (!p7) {
        sk_X509_free(recips);
        X509_free(cert);
        BIO_free(certbio);
        BIO_free(databio);
        Tcl_SetResult(interp, "OpenSSL: PKCS7_encrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    // Output
    BIO *outbio = BIO_new(BIO_s_mem());
    int ok = 0;
    if (pemout) {
        ok = PEM_write_bio_PKCS7(outbio, p7);
    } else {
        ok = i2d_PKCS7_bio(outbio, p7);
    }
    if (!ok) {
        PKCS7_free(p7);
        sk_X509_free(recips);
        X509_free(cert);
        BIO_free(certbio);
        BIO_free(databio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "OpenSSL: failed to serialize PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, pemout ? Tcl_NewStringObj(outbuf, outlen) : Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    PKCS7_free(p7);
    sk_X509_free(recips);
    X509_free(cert);
    BIO_free(certbio);
    BIO_free(databio);
    BIO_free(outbio);
    return TCL_OK;
}

// opentssl::pkcs7::decrypt -key <key> -cert <cert> <pkcs7> ?-pem 0|1?
static int Pkcs7DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *key_pem = NULL, *cert_pem = NULL;
    int key_len = 0, cert_len = 0, sig_len = 0;
    int pemin = 1; // Default: PEM input
    Tcl_Obj *sigObj = NULL;
    // Parse options: -key <key> -cert <cert> <pkcs7> ?-pem 0|1?
    int i = 1;
    for (; i + 1 < objc - 1; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-pem") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemin) != TCL_OK) return TCL_ERROR;
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (i >= objc) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key key -cert cert pkcs7 ?-pem 0|1?");
        return TCL_ERROR;
    }
    sigObj = objv[objc-1];
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(sigObj, &sig_len);
    // Load key and cert
    BIO *keybio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    if (!pkey || !cert) {
        if (pkey) EVP_PKEY_free(pkey);
        if (cert) X509_free(cert);
        BIO_free(keybio);
        BIO_free(certbio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key or cert", TCL_STATIC);
        return TCL_ERROR;
    }
    // Load PKCS7
    BIO *sigbio = BIO_new_mem_buf((void*)sig, sig_len);
    PKCS7 *p7 = NULL;
    if (pemin) {
        p7 = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
    } else {
        p7 = d2i_PKCS7_bio(sigbio, NULL);
    }
    if (!p7) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(keybio);
        BIO_free(certbio);
        BIO_free(sigbio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse PKCS7 envelope", TCL_STATIC);
        return TCL_ERROR;
    }
    // Decrypt
    BIO *outbio = BIO_new(BIO_s_mem());
    int ok = PKCS7_decrypt(p7, pkey, cert, outbio, 0);
    if (!ok) {
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(keybio);
        BIO_free(certbio);
        BIO_free(sigbio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "OpenSSL: PKCS7_decrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    PKCS7_free(p7);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(keybio);
    BIO_free(certbio);
    BIO_free(sigbio);
    BIO_free(outbio);
    return TCL_OK;
}

// opentssl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?
static int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *ca_pem = NULL;
    int ca_len = 0, sig_len = 0, data_len = 0;
    int pemin = 1; // Default: PEM input
    Tcl_Obj *sigObj = NULL, *dataObj = NULL;
    // Parse options: -ca <ca> <pkcs7> <data> ?-pem 0|1?
    int i = 1;
    for (; i + 1 < objc - 2; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-ca") == 0) {
            ca_pem = Tcl_GetStringFromObj(objv[i+1], &ca_len);
        } else if (strcmp(opt, "-pem") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemin) != TCL_OK) return TCL_ERROR;
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (i + 2 != objc) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ca ca pkcs7 data ?-pem 0|1?");
        return TCL_ERROR;
    }
    sigObj = objv[objc-2];
    dataObj = objv[objc-1];
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(sigObj, &sig_len);
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(dataObj, &data_len);
    // Load CA cert
    BIO *cabio = BIO_new_mem_buf((void*)ca_pem, ca_len);
    X509 *ca = PEM_read_bio_X509(cabio, NULL, NULL, NULL);
    if (!ca) {
        BIO_free(cabio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse CA cert", TCL_STATIC);
        return TCL_ERROR;
    }
    // Load PKCS7 signature
    BIO *sigbio = BIO_new_mem_buf((void*)sig, sig_len);
    PKCS7 *p7 = NULL;
    if (pemin) {
        p7 = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
    } else {
        p7 = d2i_PKCS7_bio(sigbio, NULL);
    }
    if (!p7) {
        X509_free(ca);
        BIO_free(cabio);
        BIO_free(sigbio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse PKCS7 signature", TCL_STATIC);
        return TCL_ERROR;
    }
    // Prepare data
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    // Build cert store
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    // Create cert stack
    STACK_OF(X509) *certs = sk_X509_new_null();
    sk_X509_push(certs, ca);
    // Verify
    int ok = PKCS7_verify(p7, certs, store, databio, NULL, 0);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok == 1));
    // Cleanup
    sk_X509_free(certs);
    X509_STORE_free(store);
    PKCS7_free(p7);
    X509_free(ca);
    BIO_free(cabio);
    BIO_free(sigbio);
    BIO_free(databio);
    return TCL_OK;
}

// opentssl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?
static int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *cert_pem = NULL, *key_pem = NULL;
    int cert_len = 0, key_len = 0, data_len = 0;
    int detached = 1; // Default: detached signature
    int pemout = 1;   // Default: PEM output
    Tcl_Obj *dataObj = NULL;
    // Parse options: -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?
    int i = 1;
    for (; i + 1 < objc - 1; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-detached") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &detached) != TCL_OK) return TCL_ERROR;
        } else if (strcmp(opt, "-pem") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemout) != TCL_OK) return TCL_ERROR;
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (i >= objc) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert cert -key key data ?-detached 0|1? ?-pem 0|1?");
        return TCL_ERROR;
    }
    dataObj = objv[objc-1];
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(dataObj, &data_len);
    // Load cert and key
    BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    BIO *keybio = BIO_new_mem_buf((void*)key_pem, key_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    if (!cert || !pkey) {
        if (cert) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
        BIO_free(certbio);
        BIO_free(keybio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse cert or key", TCL_STATIC);
        return TCL_ERROR;
    }
    // Prepare data
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    // Create PKCS7 signature
    PKCS7 *p7 = PKCS7_sign(cert, pkey, NULL, databio, detached ? PKCS7_DETACHED : 0);
    if (!p7) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(certbio);
        BIO_free(keybio);
        BIO_free(databio);
        Tcl_SetResult(interp, "OpenSSL: PKCS7_sign failed", TCL_STATIC);
        return TCL_ERROR;
    }
    // Output
    BIO *outbio = BIO_new(BIO_s_mem());
    int ok = 0;
    if (pemout) {
        ok = PEM_write_bio_PKCS7(outbio, p7);
    } else {
        ok = i2d_PKCS7_bio(outbio, p7);
    }
    if (!ok) {
        PKCS7_free(p7);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        BIO_free(certbio);
        BIO_free(keybio);
        BIO_free(databio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "OpenSSL: failed to serialize PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, pemout ? Tcl_NewStringObj(outbuf, outlen) : Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    PKCS7_free(p7);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(certbio);
    BIO_free(keybio);
    BIO_free(databio);
    BIO_free(outbio);
    return TCL_OK;
}

// opentssl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>
static int Pkcs12CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert cert -key key -ca ca -password pw");
        return TCL_ERROR;
    }
    const char *cert_pem = NULL, *key_pem = NULL, *ca_pem = NULL, *password = NULL;
    int cert_len = 0, key_len = 0, ca_len = 0;
    for (int i = 1; i < 9; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-key") == 0) {
            key_pem = Tcl_GetStringFromObj(objv[i+1], &key_len);
        } else if (strcmp(opt, "-ca") == 0) {
            ca_pem = Tcl_GetStringFromObj(objv[i+1], &ca_len);
        } else if (strcmp(opt, "-password") == 0) {
            password = Tcl_GetString(objv[i+1]);
        }
    }
    if (!cert_pem || !key_pem || !password) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *keybio = BIO_new_mem_buf((void*)key_pem, key_len);
    BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    STACK_OF(X509) *ca_stack = NULL;
    if (ca_pem && ca_len > 0) {
        ca_stack = sk_X509_new_null();
        BIO *cabio = BIO_new_mem_buf((void*)ca_pem, ca_len);
        while (1) {
            X509 *cacert = PEM_read_bio_X509(cabio, NULL, NULL, NULL);
            if (!cacert) break;
            sk_X509_push(ca_stack, cacert);
        }
        BIO_free(cabio);
    }
    PKCS12 *p12 = PKCS12_create(password, "OpenTSSL", pkey, cert, ca_stack, 0,0,0,0,0);
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
    BIO_free(keybio);
    BIO_free(certbio);
    if (!p12) {
        Tcl_SetResult(interp, "OpenSSL: PKCS12_create failed", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *outbio = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(outbio, p12);
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *)outbuf, outlen));
    PKCS12_free(p12);
    BIO_free(outbio);
    return TCL_OK;
}

// opentssl::ec::sign -privkey <pem> -alg <digest> <data>
static int EcSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-privkey pem -alg digest data");
        return TCL_ERROR;
    }
    const char *privkey = NULL, *alg = NULL;
    int privkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    BIO *bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        if (pkey) EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse EC private key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char sig[EVP_PKEY_size(pkey)];
    size_t siglen = 0;
    int ok = EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestSignUpdate(mdctx, data, datalen) &&
             EVP_DigestSignFinal(mdctx, sig, &siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    if (!ok) {
        Tcl_SetResult(interp, "OpenSSL: EC signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, siglen));
    return TCL_OK;
}

// opentssl::ec::verify -pubkey <pem> -alg <digest> <data> <signature>
static int EcVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pubkey pem -alg digest data signature");
        return TCL_ERROR;
    }
    const char *pubkey = NULL, *alg = NULL;
    int pubkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen, siglen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(objv[6], &siglen);
    BIO *bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        if (pkey) EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse EC public key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    int ok = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestVerifyUpdate(mdctx, data, datalen) &&
             EVP_DigestVerifyFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok));
    return TCL_OK;
}

// opentssl::rsa::sign -privkey <pem> -alg <digest> <data>
static int RsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-privkey pem -alg digest data");
        return TCL_ERROR;
    }
    const char *privkey = NULL, *alg = NULL;
    int privkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    BIO *bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char sig[EVP_PKEY_size(pkey)];
    size_t siglen = 0;
    int ok = EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestSignUpdate(mdctx, data, datalen) &&
             EVP_DigestSignFinal(mdctx, sig, &siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    if (!ok) {
        Tcl_SetResult(interp, "OpenSSL: signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, siglen));
    return TCL_OK;
}

// opentssl::rsa::verify -pubkey <pem> -alg <digest> <data> <signature>
static int RsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pubkey pem -alg digest data signature");
        return TCL_ERROR;
    }
    const char *pubkey = NULL, *alg = NULL;
    int pubkey_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen, siglen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[5], &datalen);
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(objv[6], &siglen);
    BIO *bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    int ok = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestVerifyUpdate(mdctx, data, datalen) &&
             EVP_DigestVerifyFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok));
    return TCL_OK;
}

// opentssl::x509::create -subject dn -issuer dn -pubkey pem -privkey pem -days n [-san {dns1 dns2 ...}]
static int X509CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 11 || objc > 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-subject dn -issuer dn -pubkey pem -privkey pem -days n [-san {dns1 dns2 ...}]");
        return TCL_ERROR;
    }
    const char *subject = NULL, *issuer = NULL, *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0, days = 0;
    Tcl_Obj *sanListObj = NULL;
    Tcl_Obj *keyUsageListObj = NULL;
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-subject") == 0) {
            subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-issuer") == 0) {
            issuer = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-days") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &days) != TCL_OK) return TCL_ERROR;
        } else if (strcmp(opt, "-san") == 0) {
            sanListObj = objv[i+1];
        } else if (strcmp(opt, "-keyusage") == 0) {
            keyUsageListObj = objv[i+1];
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!subject || !issuer || !pubkey || !privkey || days == 0) {
        Tcl_SetResult(interp, "Missing required option", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *pub_bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    BIO *priv_bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *issuer_pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    if (!pkey || !issuer_pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        if (issuer_pkey) EVP_PKEY_free(issuer_pkey);
        BIO_free(pub_bio); BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key(s)", TCL_STATIC);
        return TCL_ERROR;
    }
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey); EVP_PKEY_free(issuer_pkey);
        BIO_free(pub_bio); BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create X509 object", TCL_STATIC);
        return TCL_ERROR;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*days);
    X509_set_pubkey(cert, pkey);
    X509_NAME *subj = X509_NAME_new();
    X509_NAME *iss = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const unsigned char*)subject, -1, -1, 0);
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char*)issuer, -1, -1, 0);
    X509_set_subject_name(cert, subj);
    X509_set_issuer_name(cert, iss);
    // Add SAN extension if requested
    if (sanListObj) {
        int sanCount = 0;
        Tcl_Obj **sanElems;
        if (Tcl_ListObjGetElements(interp, sanListObj, &sanCount, &sanElems) == TCL_OK && sanCount > 0) {
            GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
            for (int i = 0; i < sanCount; ++i) {
                const char *sanStr = Tcl_GetString(sanElems[i]);
                GENERAL_NAME *name = NULL;
                // Try to parse as IPv4 or IPv6, else treat as DNS
                unsigned char ipbuf[16];
                int iptype = 0;
                if (strchr(sanStr, ':')) iptype = 6; // IPv6
                else if (strchr(sanStr, '.')) iptype = 4; // IPv4
                if ((iptype == 4 && inet_pton(AF_INET, sanStr, ipbuf) == 1) ||
                    (iptype == 6 && inet_pton(AF_INET6, sanStr, ipbuf) == 1)) {
                    name = GENERAL_NAME_new();
                    ASN1_OCTET_STRING *ip = ASN1_OCTET_STRING_new();
                    ASN1_OCTET_STRING_set(ip, ipbuf, iptype == 4 ? 4 : 16);
                    GENERAL_NAME_set0_value(name, GEN_IPADD, ip);
                } else {
                    name = GENERAL_NAME_new();
                    ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
                    ASN1_STRING_set(dns, sanStr, strlen(sanStr));
                    GENERAL_NAME_set0_value(name, GEN_DNS, dns);
                }
                sk_GENERAL_NAME_push(gens, name);
            }
            X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
            if (ext) {
                X509_add_ext(cert, ext, -1);
                X509_EXTENSION_free(ext);
            }
            sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
        }
    }
    // Add keyUsage extension if requested
    if (keyUsageListObj) {
        int kuCount = 0;
        Tcl_Obj **kuElems;
        unsigned int kuFlags = 0;
        if (Tcl_ListObjGetElements(interp, keyUsageListObj, &kuCount, &kuElems) == TCL_OK && kuCount > 0) {
            for (int i = 0; i < kuCount; ++i) {
                const char *kuStr = Tcl_GetString(kuElems[i]);
                if (strcmp(kuStr, "digitalSignature") == 0) kuFlags |= KU_DIGITAL_SIGNATURE;
                else if (strcmp(kuStr, "nonRepudiation") == 0) kuFlags |= KU_NON_REPUDIATION;
                else if (strcmp(kuStr, "keyEncipherment") == 0) kuFlags |= KU_KEY_ENCIPHERMENT;
                else if (strcmp(kuStr, "dataEncipherment") == 0) kuFlags |= KU_DATA_ENCIPHERMENT;
                else if (strcmp(kuStr, "keyAgreement") == 0) kuFlags |= KU_KEY_AGREEMENT;
                else if (strcmp(kuStr, "keyCertSign") == 0) kuFlags |= KU_KEY_CERT_SIGN;
                else if (strcmp(kuStr, "cRLSign") == 0) kuFlags |= KU_CRL_SIGN;
                else if (strcmp(kuStr, "encipherOnly") == 0) kuFlags |= KU_ENCIPHER_ONLY;
                else if (strcmp(kuStr, "decipherOnly") == 0) kuFlags |= KU_DECIPHER_ONLY;
            }
            ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
            ASN1_BIT_STRING_set_bit(ku, 0, (kuFlags & KU_DIGITAL_SIGNATURE) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 1, (kuFlags & KU_NON_REPUDIATION) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 2, (kuFlags & KU_KEY_ENCIPHERMENT) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 3, (kuFlags & KU_DATA_ENCIPHERMENT) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 4, (kuFlags & KU_KEY_AGREEMENT) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 5, (kuFlags & KU_KEY_CERT_SIGN) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 6, (kuFlags & KU_CRL_SIGN) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 7, (kuFlags & KU_ENCIPHER_ONLY) ? 1 : 0);
            ASN1_BIT_STRING_set_bit(ku, 8, (kuFlags & KU_DECIPHER_ONLY) ? 1 : 0);
            X509_EXTENSION *ext = X509V3_EXT_i2d(NID_key_usage, 0, ku);
            if (ext) {
                X509_add_ext(cert, ext, -1);
                X509_EXTENSION_free(ext);
            }
            ASN1_BIT_STRING_free(ku);
        }
    }
    int ok = X509_sign(cert, issuer_pkey, EVP_sha256());
    X509_NAME_free(subj); X509_NAME_free(iss);
    EVP_PKEY_free(pkey); EVP_PKEY_free(issuer_pkey);
    BIO_free(pub_bio); BIO_free(priv_bio);
    if (!ok) {
        X509_free(cert);
        Tcl_SetResult(interp, "OpenSSL: certificate signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    char *pem = NULL;
    long pemlen = BIO_get_mem_data(out, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, pemlen));
    BIO_free(out);
    X509_free(cert);
    return TCL_OK;
}

// opentssl::x509::verify -cert <pem> -ca <pem>
static int X509VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert pem -ca pem");
        return TCL_ERROR;
    }
    const char *cert_pem = NULL, *ca_pem = NULL;
    int cert_len = 0, ca_len = 0;
    for (int i = 1; i < 5; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-ca") == 0) {
            ca_pem = Tcl_GetStringFromObj(objv[i+1], &ca_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO *ca_bio = BIO_new_mem_buf((void*)ca_pem, ca_len);
    X509 *ca = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    EVP_PKEY *ca_pub = NULL;
    if (ca) {
        ca_pub = X509_get_pubkey(ca);
    } else {
        // Try as public key PEM
        ca_pub = PEM_read_bio_PUBKEY(ca_bio, NULL, NULL, NULL);
    }
    int ok = 0;
    if (cert && ca_pub) {
        ok = X509_verify(cert, ca_pub);
    }
    if (ca_pub) EVP_PKEY_free(ca_pub);
    if (cert) X509_free(cert);
    if (ca) X509_free(ca);
    BIO_free(cert_bio);
    BIO_free(ca_bio);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok));
    return TCL_OK;
}

// Package initialization
int Opentssl_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) {
        return TCL_ERROR;
    }
    Tcl_CreateObjCommand(interp, "opentssl::digest", DigestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::hmac", HmacCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::randbytes", RandBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::encrypt", EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::decrypt", DecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::generate", RsaGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::encrypt", RsaEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::decrypt", RsaDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::parse", X509ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::sign", RsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::verify", RsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::dsa::sign", DsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::dsa::verify", DsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::ec::sign", EcSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::ec::verify", EcVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::create", X509CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::verify", X509VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::key::generate", KeyGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::key::parse", KeyParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::key::write", KeyWriteCmd, NULL, NULL);
    Tcl_PkgProvide(interp, "opentssl", "0.1");
    Tcl_CreateObjCommand(interp, "opentssl::base64::encode", Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::base64::decode", Base64DecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::hex::encode", HexEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::hex::decode", HexDecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs12::parse", Pkcs12ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs12::create", Pkcs12CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs7::sign", Pkcs7SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs7::verify", Pkcs7VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs7::encrypt", Pkcs7EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::pkcs7::decrypt", Pkcs7DecryptCmd, NULL, NULL);
    return TCL_OK;
}
