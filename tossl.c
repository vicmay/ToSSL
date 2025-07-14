/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file incorporates work from the OpenSSL project,
 * developed by Eric Young and Tim Hudson.
 */

#include <tcl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
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
#include <openssl/provider.h>

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

// tossl::hmac -alg <name> -key <key> <data>
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

// tossl::key::parse <pem|der>
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

// tossl::key::write -key <key> -format <pem|der>
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
        Tcl_SetResult(interp, "Key dict must have \'type\', \'kind\', and \'pem\' fields", TCL_STATIC);
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

// tossl::key::generate ?-type <rsa> ?-bits <n>?
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

// tossl::key::getpub <private_key_data>
// Takes a private key (PEM or DER) and returns the corresponding public key in PEM format.
static int KeyGetPubCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "<private_key_data>");
        return TCL_ERROR;
    }

    int input_len;
    unsigned char *input_data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &input_len);

    EVP_PKEY *pkey = NULL;
    BIO *bio_in = NULL;

    // Try to read as PEM private key
    bio_in = BIO_new_mem_buf((void*)input_data, input_len);
    if (!bio_in) {
        Tcl_SetResult(interp, "OpenSSL: BIO_new_mem_buf failed for PEM input", TCL_STATIC);
        return TCL_ERROR;
    }
    pkey = PEM_read_bio_PrivateKey(bio_in, NULL, NULL, NULL);
    BIO_free(bio_in);
    bio_in = NULL; 

    if (!pkey) {
        // PEM failed, try to read as DER private key
        bio_in = BIO_new_mem_buf((void*)input_data, input_len);
        if (!bio_in) {
            Tcl_SetResult(interp, "OpenSSL: BIO_new_mem_buf failed for DER input", TCL_STATIC);
            return TCL_ERROR;
        }
        pkey = d2i_PrivateKey_bio(bio_in, NULL);
        BIO_free(bio_in);
        bio_in = NULL;
    }

    if (!pkey) {
        Tcl_SetResult(interp, "Failed to parse private key. Not a valid PEM or DER private key.", TCL_STATIC);
        return TCL_ERROR;
    }

    // Now we have pkey, extract public key in PEM format
    BIO *pub_bio_out = BIO_new(BIO_s_mem());
    if (!pub_bio_out) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "OpenSSL: BIO_new for public key output failed", TCL_STATIC);
        return TCL_ERROR;
    }

    if (!PEM_write_bio_PUBKEY(pub_bio_out, pkey)) {
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("OpenSSL: Failed to write public key to PEM: %s", errbuf));
        EVP_PKEY_free(pkey);
        BIO_free(pub_bio_out);
        return TCL_ERROR;
    }

    char *pub_pem_str = NULL;
    long pub_pem_len = BIO_get_mem_data(pub_bio_out, &pub_pem_str);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(pub_pem_str, pub_pem_len));

    EVP_PKEY_free(pkey);
    BIO_free(pub_bio_out);

    return TCL_OK;
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

// tossl::base64::encode <data>
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

// tossl::base64::decode <base64>
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

// tossl::hex::encode <data>
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

// tossl::hex::decode <hex>
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


// tossl::digest -alg <name> <data>
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

    // Map common algorithm names to OpenSSL names
    const char *openssl_alg = alg;
    if (strcmp(alg, "sha1") == 0) openssl_alg = "sha1";
    else if (strcmp(alg, "sha224") == 0) openssl_alg = "sha224";
    else if (strcmp(alg, "sha256") == 0) openssl_alg = "sha256";
    else if (strcmp(alg, "sha384") == 0) openssl_alg = "sha384";
    else if (strcmp(alg, "sha512") == 0) openssl_alg = "sha512";
    else if (strcmp(alg, "sha3-224") == 0) openssl_alg = "sha3-224";
    else if (strcmp(alg, "sha3-256") == 0) openssl_alg = "sha3-256";
    else if (strcmp(alg, "sha3-384") == 0) openssl_alg = "sha3-384";
    else if (strcmp(alg, "sha3-512") == 0) openssl_alg = "sha3-512";
    else if (strcmp(alg, "ripemd160") == 0) openssl_alg = "ripemd160";
    else if (strcmp(alg, "ripemd256") == 0) openssl_alg = "ripemd256";
    else if (strcmp(alg, "ripemd320") == 0) openssl_alg = "ripemd320";
    else if (strcmp(alg, "blake2b256") == 0) openssl_alg = "blake2b256";
    else if (strcmp(alg, "blake2b512") == 0) openssl_alg = "blake2b512";
    else if (strcmp(alg, "blake2s256") == 0) openssl_alg = "blake2s256";
    else if (strcmp(alg, "sm3") == 0) openssl_alg = "sm3";
    else if (strcmp(alg, "md5") == 0) openssl_alg = "md5";
    else if (strcmp(alg, "md4") == 0) openssl_alg = "md4";
    else if (strcmp(alg, "whirlpool") == 0) openssl_alg = "whirlpool";

    const EVP_MD *md = EVP_get_digestbyname(openssl_alg);
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

// tossl::digest::stream -alg <name> -file <filename>
static int DigestStreamCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -file filename");
        return TCL_ERROR;
    }
    const char *alg = NULL, *filename = NULL;
    for (int i = 1; i < 3; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-file") == 0) {
            filename = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Expected -alg or -file option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!alg || !filename) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }

    // Map common algorithm names to OpenSSL names
    const char *openssl_alg = alg;
    if (strcmp(alg, "sha1") == 0) openssl_alg = "sha1";
    else if (strcmp(alg, "sha224") == 0) openssl_alg = "sha224";
    else if (strcmp(alg, "sha256") == 0) openssl_alg = "sha256";
    else if (strcmp(alg, "sha384") == 0) openssl_alg = "sha384";
    else if (strcmp(alg, "sha512") == 0) openssl_alg = "sha512";
    else if (strcmp(alg, "sha3-224") == 0) openssl_alg = "sha3-224";
    else if (strcmp(alg, "sha3-256") == 0) openssl_alg = "sha3-256";
    else if (strcmp(alg, "sha3-384") == 0) openssl_alg = "sha3-384";
    else if (strcmp(alg, "sha3-512") == 0) openssl_alg = "sha3-512";
    else if (strcmp(alg, "ripemd160") == 0) openssl_alg = "ripemd160";
    else if (strcmp(alg, "ripemd256") == 0) openssl_alg = "ripemd256";
    else if (strcmp(alg, "ripemd320") == 0) openssl_alg = "ripemd320";
    else if (strcmp(alg, "blake2b256") == 0) openssl_alg = "blake2b256";
    else if (strcmp(alg, "blake2b512") == 0) openssl_alg = "blake2b512";
    else if (strcmp(alg, "blake2s256") == 0) openssl_alg = "blake2s256";
    else if (strcmp(alg, "sm3") == 0) openssl_alg = "sm3";
    else if (strcmp(alg, "md5") == 0) openssl_alg = "md5";
    else if (strcmp(alg, "md4") == 0) openssl_alg = "md4";
    else if (strcmp(alg, "whirlpool") == 0) openssl_alg = "whirlpool";

    const EVP_MD *md = EVP_get_digestbyname(openssl_alg);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        Tcl_SetResult(interp, "Cannot open file for reading", TCL_STATIC);
        return TCL_ERROR;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        Tcl_SetResult(interp, "OpenSSL: failed to create context", TCL_STATIC);
        return TCL_ERROR;
    }

    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        Tcl_SetResult(interp, "OpenSSL: digest init failed", TCL_STATIC);
        return TCL_ERROR;
    }

    unsigned char buffer[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            Tcl_SetResult(interp, "OpenSSL: digest update failed", TCL_STATIC);
            return TCL_ERROR;
        }
    }

    fclose(file);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0;
    if (!EVP_DigestFinal_ex(mdctx, hash, &hashlen)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest final failed", TCL_STATIC);
        return TCL_ERROR;
    }

    EVP_MD_CTX_free(mdctx);
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hashlen, hex);
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::digest::compare <hash1> <hash2>
static int DigestCompareCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "hash1 hash2");
        return TCL_ERROR;
    }
    
    const char *hash1 = Tcl_GetString(objv[1]);
    const char *hash2 = Tcl_GetString(objv[2]);
    
    if (strlen(hash1) != strlen(hash2)) {
        Tcl_SetResult(interp, "0", TCL_STATIC);
        return TCL_OK;
    }
    
    int result = (strcmp(hash1, hash2) == 0) ? 1 : 0;
    Tcl_SetResult(interp, result ? "1" : "0", TCL_STATIC);
    return TCL_OK;
}


// tossl::randbytes nbytes
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

// tossl::rand::key -alg <name>
static int RandKeyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-alg") != 0) {
        Tcl_SetResult(interp, "Expected -alg option", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[2]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len = EVP_CIPHER_key_length(cipher);
    if (key_len <= 0) {
        Tcl_SetResult(interp, "Invalid key length", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = OPENSSL_malloc(key_len);
    if (!key) {
        Tcl_SetResult(interp, "OpenSSL: memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(key, key_len) != 1) {
        OPENSSL_free(key);
        Tcl_SetResult(interp, "OpenSSL: RAND_bytes failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, key_len);
    OPENSSL_free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::digest::list
static int DigestListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    
    // Common hash algorithm names to check
    const char *hash_names[] = {
        "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "ripemd160", "ripemd256", "ripemd320",
        "blake2b256", "blake2b512", "blake2s256",
        "sm3", "md5", "md4", "whirlpool",
        NULL
    };
    
    for (int i = 0; hash_names[i] != NULL; i++) {
        const EVP_MD *md = EVP_get_digestbyname(hash_names[i]);
        if (md) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(hash_names[i], -1));
        }
    }
    
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

// tossl::rand::iv -alg <name>
static int RandIvCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-alg") != 0) {
        Tcl_SetResult(interp, "Expected -alg option", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[2]);
    
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int iv_len = EVP_CIPHER_iv_length(cipher);
    if (iv_len <= 0) {
        Tcl_SetResult(interp, "Cipher does not require IV", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *iv = OPENSSL_malloc(iv_len);
    if (!iv) {
        Tcl_SetResult(interp, "OpenSSL: memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (RAND_bytes(iv, iv_len) != 1) {
        OPENSSL_free(iv);
        Tcl_SetResult(interp, "OpenSSL: RAND_bytes failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(iv, iv_len);
    OPENSSL_free(iv);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::kdf::pbkdf2 -password <password> -salt <salt> -iterations <n> -keylen <n> ?-digest <name>?
static int Pbkdf2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 9 && objc != 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-password password -salt salt -iterations n -keylen n ?-digest name?");
        return TCL_ERROR;
    }
    const char *password = NULL, *salt = NULL, *digest = "sha256";
    int password_len = 0, salt_len = 0;
    int iterations = 0, keylen = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &password_len);
        } else if (strcmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcmp(opt, "-iterations") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &iterations) != TCL_OK || iterations <= 0) {
                Tcl_SetResult(interp, "iterations must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &keylen) != TCL_OK || keylen <= 0 || keylen > 4096) {
                Tcl_SetResult(interp, "keylen must be a positive integer between 1 and 4096", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-digest") == 0) {
            digest = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || iterations == 0 || keylen == 0) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const EVP_MD *md = EVP_get_digestbyname(digest);
    if (!md) {
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = OPENSSL_malloc(keylen);
    if (!key) {
        Tcl_SetResult(interp, "OpenSSL: memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!PKCS5_PBKDF2_HMAC(password, password_len, (const unsigned char*)salt, salt_len, 
                           iterations, md, keylen, key)) {
        OPENSSL_free(key);
        Tcl_SetResult(interp, "OpenSSL: PBKDF2 failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, keylen);
    OPENSSL_free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::kdf::scrypt -password <password> -salt <salt> -n <n> -r <r> -p <p> -keylen <n>
static int ScryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-password password -salt salt -n n -r r -p p -keylen n");
        return TCL_ERROR;
    }
    const char *password = NULL, *salt = NULL;
    int password_len = 0, salt_len = 0;
    int n = 0, r = 0, p = 0, keylen = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &password_len);
        } else if (strcmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcmp(opt, "-n") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &n) != TCL_OK || n <= 0) {
                Tcl_SetResult(interp, "n must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-r") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &r) != TCL_OK || r <= 0) {
                Tcl_SetResult(interp, "r must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-p") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &p) != TCL_OK || p <= 0) {
                Tcl_SetResult(interp, "p must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &keylen) != TCL_OK || keylen <= 0 || keylen > 4096) {
                Tcl_SetResult(interp, "keylen must be a positive integer between 1 and 4096", TCL_STATIC);
                return TCL_ERROR;
            }
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || n == 0 || r == 0 || p == 0 || keylen == 0) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *key = OPENSSL_malloc(keylen);
    if (!key) {
        Tcl_SetResult(interp, "OpenSSL: memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!EVP_PBE_scrypt(password, password_len, (const unsigned char*)salt, salt_len, 
                        n, r, p, 0, key, keylen)) {
        OPENSSL_free(key);
        Tcl_SetResult(interp, "OpenSSL: scrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(key, keylen);
    OPENSSL_free(key);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::kdf::argon2 -password <password> -salt <salt> -time <t> -memory <m> -parallel <p> -keylen <n> ?-type <type>?
static int Argon2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 13 && objc != 15) {
        Tcl_WrongNumArgs(interp, 1, objv, "-password password -salt salt -time t -memory m -parallel p -keylen n ?-type type?");
        return TCL_ERROR;
    }
    const char *password = NULL, *salt = NULL;
    int password_len = 0, salt_len = 0;
    int time_cost = 0, memory_cost = 0, parallelism = 0, keylen = 0;
    const char *type = "argon2id";
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-password") == 0) {
            password = Tcl_GetStringFromObj(objv[i+1], &password_len);
        } else if (strcmp(opt, "-salt") == 0) {
            salt = Tcl_GetStringFromObj(objv[i+1], &salt_len);
        } else if (strcmp(opt, "-time") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &time_cost) != TCL_OK || time_cost <= 0) {
                Tcl_SetResult(interp, "time must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-memory") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &memory_cost) != TCL_OK || memory_cost <= 0) {
                Tcl_SetResult(interp, "memory must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-parallel") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &parallelism) != TCL_OK || parallelism <= 0) {
                Tcl_SetResult(interp, "parallel must be a positive integer", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-keylen") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &keylen) != TCL_OK || keylen <= 0 || keylen > 4096) {
                Tcl_SetResult(interp, "keylen must be a positive integer between 1 and 4096", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!password || !salt || time_cost == 0 || memory_cost == 0 || parallelism == 0 || keylen == 0) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Note: OpenSSL doesn't have built-in Argon2 support in all versions
    // This is a placeholder implementation - in practice, you might need to use a separate library
    Tcl_SetResult(interp, "Argon2 not supported in this OpenSSL build", TCL_STATIC);
    return TCL_ERROR;
}

// tossl::cipher::info <algorithm>
static int CipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm");
        return TCL_ERROR;
    }
    const char *alg = Tcl_GetString(objv[1]);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        Tcl_SetResult(interp, "Unknown cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("name", -1), Tcl_NewStringObj(alg, -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("block_size", -1), Tcl_NewIntObj(EVP_CIPHER_block_size(cipher)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_length", -1), Tcl_NewIntObj(EVP_CIPHER_key_length(cipher)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iv_length", -1), Tcl_NewIntObj(EVP_CIPHER_iv_length(cipher)));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("flags", -1), Tcl_NewLongObj(EVP_CIPHER_flags(cipher)));
    
    // Determine mode
    const char *mode = "unknown";
    if (EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE) {
        int mode_flags = EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE;
        if (mode_flags == EVP_CIPH_ECB_MODE) mode = "ecb";
        else if (mode_flags == EVP_CIPH_CBC_MODE) mode = "cbc";
        else if (mode_flags == EVP_CIPH_CFB_MODE) mode = "cfb";
        else if (mode_flags == EVP_CIPH_OFB_MODE) mode = "ofb";
        else if (mode_flags == EVP_CIPH_CTR_MODE) mode = "ctr";
        else if (mode_flags == EVP_CIPH_GCM_MODE) mode = "gcm";
        else if (mode_flags == EVP_CIPH_CCM_MODE) mode = "ccm";
        else if (mode_flags == EVP_CIPH_XTS_MODE) mode = "xts";
    }
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("mode", -1), Tcl_NewStringObj(mode, -1));
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::cipher::list ?-type type?
static int CipherListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *type_filter = NULL;
    if (objc == 3) {
        const char *opt = Tcl_GetString(objv[1]);
        if (strcmp(opt, "-type") == 0) {
            type_filter = Tcl_GetString(objv[2]);
        } else {
            Tcl_SetResult(interp, "Expected -type option", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-type type?");
        return TCL_ERROR;
    }

    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    
    // Common cipher names to check
    const char *cipher_names[] = {
        // AES ciphers
        "aes-128-ecb", "aes-192-ecb", "aes-256-ecb",
        "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
        "aes-128-xts", "aes-256-xts",
        
        // DES ciphers
        "des-ecb", "des-cbc", "des-cfb", "des-ofb",
        "des-ede", "des-ede-cbc", "des-ede-cfb", "des-ede-ofb",
        "des-ede3", "des-ede3-cbc", "des-ede3-cfb", "des-ede3-ofb",
        
        // Blowfish
        "bf-ecb", "bf-cbc", "bf-cfb", "bf-ofb",
        
        // CAST5
        "cast5-ecb", "cast5-cbc", "cast5-cfb", "cast5-ofb",
        
        // RC4
        "rc4", "rc4-40",
        
        // ChaCha20
        "chacha20", "chacha20-poly1305",
        
        // Camellia
        "camellia-128-ecb", "camellia-192-ecb", "camellia-256-ecb",
        "camellia-128-cbc", "camellia-192-cbc", "camellia-256-cbc",
        "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
        "camellia-128-ofb", "camellia-192-ofb", "camellia-256-ofb",
        
        // SEED
        "seed-ecb", "seed-cbc", "seed-cfb", "seed-ofb",
        
        // SM4 (Chinese standard)
        "sm4-ecb", "sm4-cbc", "sm4-cfb", "sm4-ofb", "sm4-ctr",
        
        NULL
    };

    for (int i = 0; cipher_names[i] != NULL; i++) {
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_names[i]);
        if (cipher) {
            if (type_filter) {
                // Check if cipher matches type filter
                const char *mode = "unknown";
                if (EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE) {
                    int mode_flags = EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE;
                    if (mode_flags == EVP_CIPH_ECB_MODE) mode = "ecb";
                    else if (mode_flags == EVP_CIPH_CBC_MODE) mode = "cbc";
                    else if (mode_flags == EVP_CIPH_CFB_MODE) mode = "cfb";
                    else if (mode_flags == EVP_CIPH_OFB_MODE) mode = "ofb";
                    else if (mode_flags == EVP_CIPH_CTR_MODE) mode = "ctr";
                    else if (mode_flags == EVP_CIPH_GCM_MODE) mode = "gcm";
                    else if (mode_flags == EVP_CIPH_CCM_MODE) mode = "ccm";
                    else if (mode_flags == EVP_CIPH_XTS_MODE) mode = "xts";
                }
                
                if (strcmp(mode, type_filter) == 0) {
                    Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(cipher_names[i], -1));
                }
            } else {
                Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(cipher_names[i], -1));
            }
        }
    }

    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

// tossl::encrypt -alg <name> -key <key> -iv <iv> <data>
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
    int is_gcm = 0;
    if (alg && (strstr(alg, "gcm") != NULL)) {
        is_gcm = 1;
    }
    if (is_gcm) {
        unsigned char tag[16];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: failed to get GCM tag", TCL_STATIC);
            return TCL_ERROR;
        }
        Tcl_Obj *dict = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("ciphertext", -1), Tcl_NewByteArrayObj(outbuf, outlen));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("tag", -1), Tcl_NewByteArrayObj(tag, 16));
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetObjResult(interp, dict);
        return TCL_OK;
    } else {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(outbuf, outlen));
        return TCL_OK;
    }
}


// tossl::decrypt -alg <name> -key <key> -iv <iv> <data> ?-tag tag?
static int DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {

    (void)cd;
    // Accepts 8 (no tag) or 10 (with -tag) arguments
    if (objc != 8 && objc != 10) {
        Tcl_WrongNumArgs(interp, 1, objv, "-alg name -key key -iv iv data ?-tag tag?");
        return TCL_ERROR;
    }
    const char *alg = NULL;
    unsigned char *key = NULL, *iv = NULL, *data = NULL;
    unsigned char *tag = NULL;
    int keylen = 0, ivlen = 0, datalen = 0, taglen = 0;
    int data_idx = 7;
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
    // If -tag is present, parse it
    if (objc == 10) {
        const char *opt = Tcl_GetString(objv[7]);
        if (strcmp(opt, "-tag") != 0) {
            Tcl_SetResult(interp, "Unknown option (expected -tag)", TCL_STATIC);
            return TCL_ERROR;
        }
        tag = (unsigned char *)Tcl_GetByteArrayFromObj(objv[8], &taglen);
        data_idx = 9;
    }
    data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[data_idx], &datalen);
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
    int is_gcm = 0;
    if (alg && (strstr(alg, "gcm") != NULL)) {
        is_gcm = 1;
    }
    // For GCM, set tag before final
    if (is_gcm) {
        if (tag == NULL || taglen != 16) {
            EVP_CIPHER_CTX_free(ctx);
            Tcl_SetResult(interp, "GCM mode requires -tag of 16 bytes", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    unsigned char outbuf[datalen + EVP_CIPHER_block_size(cipher)];
    int outlen = 0, tmplen = 0;
    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, data, datalen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DecryptUpdate failed", TCL_STATIC);
        return TCL_ERROR;
    }
    if (is_gcm) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            Tcl_SetResult(interp, "OpenSSL: failed to set GCM tag", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: DecryptFinal failed (bad tag, padding, or key?)", TCL_STATIC);
        return TCL_ERROR;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(outbuf, outlen));
    return TCL_OK;
}


#include <openssl/pem.h>
#include <openssl/rsa.h>

// tossl::rsa::generate ?-bits n?
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

// tossl::rsa::encrypt -pubkey <pem> <data>
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

// tossl::rsa::decrypt -privkey <pem> <ciphertext>
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

// tossl::x509::parse <pem>
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
    
    // Certificate version
    long version = X509_get_version(cert);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("version", -1), Tcl_NewLongObj(version));

    // Signature algorithm
    const X509_ALGOR *sig_alg = X509_get0_tbs_sigalg(cert);
    if (sig_alg) {
        const ASN1_OBJECT *sig_obj;
        X509_ALGOR_get0(&sig_obj, NULL, NULL, sig_alg);
        if (sig_obj) {
            char sig_name[128];
            OBJ_obj2txt(sig_name, sizeof(sig_name), sig_obj, 0);
            Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("signature_algorithm", -1), Tcl_NewStringObj(sig_name, -1));
        }
    }

    // Public key info
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
        int key_bits = EVP_PKEY_get_bits(pkey);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_bits", -1), Tcl_NewIntObj(key_bits));
        
        const char *key_type_str = "unknown";
        if (key_type == EVP_PKEY_RSA) key_type_str = "rsa";
        else if (key_type == EVP_PKEY_DSA) key_type_str = "dsa";
        else if (key_type == EVP_PKEY_EC) key_type_str = "ec";
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_type", -1), Tcl_NewStringObj(key_type_str, -1));
        
        EVP_PKEY_free(pkey);
    }

    // Subject Alternative Name (SAN) - with defensive programming
    int san_idx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (san_idx >= 0) {
        X509_EXTENSION *san_ext = X509_get_ext(cert, san_idx);
        if (san_ext) {
            STACK_OF(GENERAL_NAME) *san_names = (STACK_OF(GENERAL_NAME) *)X509V3_EXT_d2i(san_ext);
            if (san_names) {
                Tcl_Obj *sanList = Tcl_NewListObj(0, NULL);
                int num = sk_GENERAL_NAME_num(san_names);
                for (int i = 0; i < num; ++i) {
                    const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
                    if (!name) continue; // Defensive
                    if (name->type == GEN_DNS && name->d.dNSName) {
                        const unsigned char *dns = ASN1_STRING_get0_data(name->d.dNSName);
                        int len = ASN1_STRING_length(name->d.dNSName);
                        if (dns)
                            Tcl_ListObjAppendElement(interp, sanList, Tcl_NewStringObj((const char*)dns, len));
                    } else if (name->type == GEN_IPADD && name->d.iPAddress) {
                        const unsigned char *ip = ASN1_STRING_get0_data(name->d.iPAddress);
                        int len = ASN1_STRING_length(name->d.iPAddress);
                        if (ip) {
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
                }
                Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("san", -1), sanList);
                sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
            }
            X509_EXTENSION_free(san_ext);
        }
    }

    // Key Usage
    ASN1_BIT_STRING *key_usage = (ASN1_BIT_STRING *)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (key_usage) {
        Tcl_Obj *usageList = Tcl_NewListObj(0, NULL);
        if (ASN1_BIT_STRING_get_bit(key_usage, 0)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("digitalSignature", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 1)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("nonRepudiation", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 2)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("keyEncipherment", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 3)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("dataEncipherment", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 4)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("keyAgreement", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 5)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("keyCertSign", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 6)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("cRLSign", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 7)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("encipherOnly", -1));
        if (ASN1_BIT_STRING_get_bit(key_usage, 8)) Tcl_ListObjAppendElement(interp, usageList, Tcl_NewStringObj("decipherOnly", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_usage", -1), usageList);
        ASN1_BIT_STRING_free(key_usage);
    }

    // Extended Key Usage
    STACK_OF(ASN1_OBJECT) *ext_key_usage = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (ext_key_usage) {
        Tcl_Obj *extUsageList = Tcl_NewListObj(0, NULL);
        int num = sk_ASN1_OBJECT_num(ext_key_usage);
        for (int i = 0; i < num; ++i) {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(ext_key_usage, i);
            char obj_name[128];
            OBJ_obj2txt(obj_name, sizeof(obj_name), obj, 0);
            Tcl_ListObjAppendElement(interp, extUsageList, Tcl_NewStringObj(obj_name, -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("extended_key_usage", -1), extUsageList);
        sk_ASN1_OBJECT_pop_free(ext_key_usage, ASN1_OBJECT_free);
    }

    // Basic Constraints
    int bc_idx = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
    if (bc_idx >= 0) {
        X509_EXTENSION *basic_constraints = X509_get_ext(cert, bc_idx);
        if (basic_constraints) {
            BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(basic_constraints);
            if (bc) {
                Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("ca", -1), Tcl_NewBooleanObj(bc->ca));
                if (bc->pathlen) {
                    long pathlen = ASN1_INTEGER_get(bc->pathlen);
                    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("pathlen", -1), Tcl_NewLongObj(pathlen));
                }
                BASIC_CONSTRAINTS_free(bc);
            }
            // Do NOT free basic_constraints here!
        }
    }

    // Authority Information Access
    AUTHORITY_INFO_ACCESS *aia = (AUTHORITY_INFO_ACCESS *)X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (aia) {
        Tcl_Obj *aiaList = Tcl_NewListObj(0, NULL);
        int num = sk_ACCESS_DESCRIPTION_num(aia);
        for (int i = 0; i < num; ++i) {
            ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
            if (!ad) continue; // Defensive
            char method[128] = {0};
            if (ad->method)
                OBJ_obj2txt(method, sizeof(method), ad->method, 0);
            if (ad->location && ad->location->type == GEN_URI && ad->location->d.uniformResourceIdentifier) {
                const unsigned char *uri = ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
                int len = ASN1_STRING_length(ad->location->d.uniformResourceIdentifier);
                if (uri) {
                    Tcl_Obj *entry = Tcl_NewDictObj();
                    Tcl_DictObjPut(interp, entry, Tcl_NewStringObj("method", -1), Tcl_NewStringObj(method, -1));
                    Tcl_DictObjPut(interp, entry, Tcl_NewStringObj("uri", -1), Tcl_NewStringObj((const char*)uri, len));
                    Tcl_ListObjAppendElement(interp, aiaList, entry);
                }
            }
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("authority_info_access", -1), aiaList);
        AUTHORITY_INFO_ACCESS_free(aia);
    }

    // CRL Distribution Points
    STACK_OF(DIST_POINT) *crl_dps = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crl_dps) {
        Tcl_Obj *crlList = Tcl_NewListObj(0, NULL);
        int num = sk_DIST_POINT_num(crl_dps);
        for (int i = 0; i < num; ++i) {
            DIST_POINT *dp = sk_DIST_POINT_value(crl_dps, i);
            if (!dp || !dp->distpoint || dp->distpoint->type != 0) continue; // Defensive
            GENERAL_NAMES *names = dp->distpoint->name.fullname;
            if (!names) continue;
            int name_num = sk_GENERAL_NAME_num(names);
            for (int j = 0; j < name_num; ++j) {
                GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
                if (!name) continue;
                if (name->type == GEN_URI && name->d.uniformResourceIdentifier) {
                    const unsigned char *uri = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
                    int len = ASN1_STRING_length(name->d.uniformResourceIdentifier);
                    if (uri)
                        Tcl_ListObjAppendElement(interp, crlList, Tcl_NewStringObj((const char*)uri, len));
                }
            }
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("crl_distribution_points", -1), crlList);
        sk_DIST_POINT_pop_free(crl_dps, DIST_POINT_free);
    }

    // Subject Key Identifier
    ASN1_OCTET_STRING *ski = (ASN1_OCTET_STRING *)X509_get_ext_d2i(cert, NID_subject_key_identifier, NULL, NULL);
    if (ski) {
        char ski_hex[256];
        bin2hex(ASN1_STRING_get0_data(ski), ASN1_STRING_length(ski), ski_hex);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("subject_key_identifier", -1), Tcl_NewStringObj(ski_hex, -1));
        ASN1_OCTET_STRING_free(ski);
    }

    // Authority Key Identifier
    AUTHORITY_KEYID *aki = (AUTHORITY_KEYID *)X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
    if (aki && aki->keyid) {
        char aki_hex[256];
        bin2hex(ASN1_STRING_get0_data(aki->keyid), ASN1_STRING_length(aki->keyid), aki_hex);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("authority_key_identifier", -1), Tcl_NewStringObj(aki_hex, -1));
        AUTHORITY_KEYID_free(aki);
    }

    // Certificate Policies
    STACK_OF(POLICYINFO) *policies = (STACK_OF(POLICYINFO) *)X509_get_ext_d2i(cert, NID_certificate_policies, NULL, NULL);
    if (policies) {
        Tcl_Obj *policyList = Tcl_NewListObj(0, NULL);
        int num = sk_POLICYINFO_num(policies);
        for (int i = 0; i < num; ++i) {
            POLICYINFO *policy = sk_POLICYINFO_value(policies, i);
            if (!policy || !policy->policyid) continue;
            char policy_name[128];
            OBJ_obj2txt(policy_name, sizeof(policy_name), policy->policyid, 0);
            Tcl_ListObjAppendElement(interp, policyList, Tcl_NewStringObj(policy_name, -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("certificate_policies", -1), policyList);
        sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    }

    // Cleanup
    X509_free(cert);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::x509::modify -cert <pem> -add_extension <oid> <value> <critical> ?-remove_extension <oid>?
static int X509ModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6 && objc != 8) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert pem -add_extension oid value critical ?-remove_extension oid?");
        return TCL_ERROR;
    }
    const char *cert_pem = NULL, *add_oid = NULL, *add_value = NULL, *remove_oid = NULL;
    int cert_len = 0;
    int add_critical = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-add_extension") == 0) {
            add_oid = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-remove_extension") == 0) {
            remove_oid = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // Parse critical flag
    if (objc >= 6) {
        const char *critical_str = Tcl_GetString(objv[5]);
        add_critical = (strcmp(critical_str, "true") == 0 || strcmp(critical_str, "1") == 0);
    }
    
    if (!cert_pem || !add_oid) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse certificate
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Remove extension if specified
    if (remove_oid) {
        int nid = OBJ_txt2nid(remove_oid);
        if (nid == NID_undef) {
            X509_free(cert);
            BIO_free(cert_bio);
            Tcl_SetResult(interp, "Unknown extension OID", TCL_STATIC);
            return TCL_ERROR;
        }
        int ext_idx = X509_get_ext_by_NID(cert, nid, -1);
        if (ext_idx >= 0) {
            X509_EXTENSION *ext = X509_get_ext(cert, ext_idx);
            if (ext) {
                X509_delete_ext(cert, ext_idx);
                X509_EXTENSION_free(ext);
            }
        }
    }
    
    // Add extension
    int nid = OBJ_txt2nid(add_oid);
    if (nid == NID_undef) {
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Unknown extension OID", TCL_STATIC);
        return TCL_ERROR;
    }
    
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, nid, (char*)add_value);
    if (!ext) {
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create extension", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (add_critical) {
        X509_EXTENSION_set_critical(ext, 1);
    }
    
    if (!X509_add_ext(cert, ext, -1)) {
        X509_EXTENSION_free(ext);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to add extension", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Output modified certificate
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, cert);
    char *pem = NULL;
    long pemlen = BIO_get_mem_data(out, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, pemlen));
    
    // Cleanup
    BIO_free(out);
    X509_EXTENSION_free(ext);
    X509_free(cert);
    BIO_free(cert_bio);
    
    return TCL_OK;
}

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

// tossl::dsa::sign -privkey <pem> -alg <digest> <data>
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

// tossl::dsa::verify -pubkey <pem> -alg <digest> <data> <signature>
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

// tossl::pkcs12::parse <data>
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

// tossl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?
static int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// tossl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?
static int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// tossl::x509::validate -cert <pem> -ca <pem>
static int X509ValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// tossl::x509::fingerprint -cert <pem> ?-alg <digest>?
static int X509FingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// tossl::pkcs7::encrypt -cert <cert1> ?-cert <cert2> ...? -cipher <cipher> <data> ?-pem 0|1?
static int Pkcs7EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    int data_len = 0, pemout = 1;
    const char *cipher_name = "aes-256-cbc";
    Tcl_Obj *dataObj = NULL;
    STACK_OF(X509) *recips = sk_X509_new_null();
    int i = 1;
    // Parse options: -cert <cert> (multiple allowed), -cipher <cipher>, -pem 0|1, <data>
    for (; i + 1 < objc - 1; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            int cert_len = 0;
            const char *cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
            BIO *certbio = BIO_new_mem_buf((void*)cert_pem, cert_len);
            X509 *cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
            BIO_free(certbio);
            if (!cert) {
                sk_X509_pop_free(recips, X509_free);
                Tcl_SetResult(interp, "OpenSSL: failed to parse cert", TCL_STATIC);
                return TCL_ERROR;
            }
            sk_X509_push(recips, cert);
        } else if (strcmp(opt, "-cipher") == 0) {
            cipher_name = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-pem") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemout) != TCL_OK) {
                sk_X509_pop_free(recips, X509_free);
                return TCL_ERROR;
            }
        } else {
            sk_X509_pop_free(recips, X509_free);
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (sk_X509_num(recips) == 0 || i >= objc) {
        sk_X509_pop_free(recips, X509_free);
        Tcl_WrongNumArgs(interp, 1, objv, "-cert cert ... ?-cipher cipher? data ?-pem 0|1?");
        return TCL_ERROR;
    }
    dataObj = objv[objc-1];
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(dataObj, &data_len);
    // Prepare data
    BIO *databio = BIO_new_mem_buf((void*)data, data_len);
    // Select cipher
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        sk_X509_pop_free(recips, X509_free);
        BIO_free(databio);
        Tcl_SetResult(interp, "OpenSSL: unknown cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    // Encrypt
    PKCS7 *p7 = PKCS7_encrypt(recips, databio, cipher, 0);
    if (!p7) {
        sk_X509_pop_free(recips, X509_free);
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
        sk_X509_pop_free(recips, X509_free);
        BIO_free(databio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "OpenSSL: failed to serialize PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, pemout ? Tcl_NewStringObj(outbuf, outlen) : Tcl_NewByteArrayObj((unsigned char*)outbuf, outlen));
    PKCS7_free(p7);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(databio);
    BIO_free(outbio);
    return TCL_OK;
}

// tossl::pkcs7::decrypt -key <key> -cert <cert> <pkcs7> ?-pem 0|1?
static int Pkcs7DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *key_pem = NULL, *cert_pem = NULL;
    int key_len = 0, cert_len = 0, env_len = 0, pemin = 1;
    Tcl_Obj *envObj = NULL;
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
        Tcl_WrongNumArgs(interp, 1, objv, "-key key -cert cert env ?-pem 0|1?");
        return TCL_ERROR;
    }
    envObj = objv[objc-1];
    unsigned char *env = (unsigned char *)Tcl_GetByteArrayFromObj(envObj, &env_len);
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
    // Load PKCS7 envelope
    BIO *envbio = BIO_new_mem_buf((void*)env, env_len);
    PKCS7 *p7 = NULL;
    if (pemin) {
        p7 = PEM_read_bio_PKCS7(envbio, NULL, NULL, NULL);
    } else {
        p7 = d2i_PKCS7_bio(envbio, NULL);
    }
    if (!p7) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(keybio);
        BIO_free(certbio);
        BIO_free(envbio);
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
        BIO_free(envbio);
        BIO_free(outbio);
        Tcl_SetResult(interp, "OpenSSL: PKCS7_decrypt failed", TCL_STATIC);
        return TCL_ERROR;
    }
    char *outbuf = NULL;
    long outlen = BIO_get_mem_data(outbio, &outbuf);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *)outbuf, outlen));
    PKCS7_free(p7);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(keybio);
    BIO_free(certbio);
    BIO_free(envbio);
    BIO_free(outbio);
    return TCL_OK;
}

// tossl::pkcs7::info <pkcs7> ?-pem 0|1?
static int Pkcs7InfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    int sig_len = 0, pemin = 1;
    Tcl_Obj *sigObj = NULL;
    // Parse: <pkcs7> ?-pem 0|1?
    int i = 1;
    for (; i < objc; ++i) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-pem") == 0) {
            if (i+1 >= objc) {
                Tcl_WrongNumArgs(interp, 1, objv, "pkcs7 ?-pem 0|1?");
                return TCL_ERROR;
            }
            if (Tcl_GetIntFromObj(interp, objv[i+1], &pemin) != TCL_OK) return TCL_ERROR;
            ++i;
        } else {
            sigObj = objv[i];
        }
    }
    if (!sigObj) {
        Tcl_WrongNumArgs(interp, 1, objv, "pkcs7 ?-pem 0|1?");
        return TCL_ERROR;
    }
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(sigObj, &sig_len);
    BIO *sigbio = BIO_new_mem_buf((void*)sig, sig_len);
    PKCS7 *p7 = NULL;
    if (pemin) {
        p7 = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
    } else {
        p7 = d2i_PKCS7_bio(sigbio, NULL);
    }
    if (!p7) {
        BIO_free(sigbio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse PKCS7", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *dict = Tcl_NewDictObj();
    int type = OBJ_obj2nid(p7->type);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj(OBJ_nid2sn(type), -1));
    // Signers
    if (type == NID_pkcs7_signed) {
        STACK_OF(PKCS7_SIGNER_INFO) *signers = PKCS7_get_signer_info(p7);
        Tcl_Obj *signerList = Tcl_NewListObj(0, NULL);
        for (int j = 0; signers && j < sk_PKCS7_SIGNER_INFO_num(signers); ++j) {
            PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(signers, j);
            Tcl_Obj *sdict = Tcl_NewDictObj();
            if (si->issuer_and_serial) {
                X509_NAME *issuer = si->issuer_and_serial->issuer;
                ASN1_INTEGER *serial = si->issuer_and_serial->serial;
                char issuerbuf[256];
                X509_NAME_oneline(issuer, issuerbuf, sizeof(issuerbuf));
                Tcl_DictObjPut(interp, sdict, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuerbuf, -1));
                BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
                char *serial_hex = BN_bn2hex(bn);
                Tcl_DictObjPut(interp, sdict, Tcl_NewStringObj("serial", -1), Tcl_NewStringObj(serial_hex, -1));
                OPENSSL_free(serial_hex);
                BN_free(bn);
            }
            Tcl_ListObjAppendElement(interp, signerList, sdict);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("signers", -1), signerList);
    }
    // Recipients
    if (type == NID_pkcs7_enveloped) {
        STACK_OF(PKCS7_RECIP_INFO) *recips = p7->d.enveloped->recipientinfo;
        Tcl_Obj *recipList = Tcl_NewListObj(0, NULL);
        for (int j = 0; recips && j < sk_PKCS7_RECIP_INFO_num(recips); ++j) {
            PKCS7_RECIP_INFO *ri = sk_PKCS7_RECIP_INFO_value(recips, j);
            Tcl_Obj *rdict = Tcl_NewDictObj();
            if (ri->issuer_and_serial) {
                X509_NAME *issuer = ri->issuer_and_serial->issuer;
                ASN1_INTEGER *serial = ri->issuer_and_serial->serial;
                char issuerbuf[256];
                X509_NAME_oneline(issuer, issuerbuf, sizeof(issuerbuf));
                Tcl_DictObjPut(interp, rdict, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuerbuf, -1));
                BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
                char *serial_hex = BN_bn2hex(bn);
                Tcl_DictObjPut(interp, rdict, Tcl_NewStringObj("serial", -1), Tcl_NewStringObj(serial_hex, -1));
                OPENSSL_free(serial_hex);
                BN_free(bn);
            }
            Tcl_ListObjAppendElement(interp, recipList, rdict);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("recipients", -1), recipList);
        // Encryption algorithm
        int enc_nid = OBJ_obj2nid(p7->d.enveloped->enc_data->algorithm->algorithm);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("cipher", -1), Tcl_NewStringObj(OBJ_nid2sn(enc_nid), -1));
    }
    PKCS7_free(p7);
    BIO_free(sigbio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?
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

// tossl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?
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

// tossl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>
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
    PKCS12 *p12 = PKCS12_create(password, "ToSSL", pkey, cert, ca_stack, 0,0,0,0,0);
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

// tossl::ec::sign -privkey <pem> -alg <digest> <data>
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
    // Two-step signature allocation for OpenSSL 3.x
    size_t siglen = 0;
    int ok = EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) &&
             EVP_DigestSignUpdate(mdctx, data, datalen) &&
             EVP_DigestSignFinal(mdctx, NULL, &siglen);
    if (!ok) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        char errbuf[512];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            Tcl_SetObjResult(interp, Tcl_NewStringObj(errbuf, -1));
        } else {
            Tcl_SetResult(interp, "OpenSSL: EC signing failed", TCL_STATIC);
        }
        return TCL_ERROR;
    }
    unsigned char *sig = ckalloc(siglen);
    ok = EVP_DigestSignFinal(mdctx, sig, &siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    if (!ok) {
        ckfree((char *)sig);
        char errbuf[512];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            Tcl_SetObjResult(interp, Tcl_NewStringObj(errbuf, -1));
        } else {
            Tcl_SetResult(interp, "OpenSSL: EC signing failed", TCL_STATIC);
        }
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, siglen));
    ckfree((char *)sig);
    return TCL_OK;
}

// tossl::ec::verify -pubkey <pem> -alg <digest> <data> <signature>
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

// tossl::rsa::sign -privkey <pem> -alg <digest> <data> ?-padding <scheme>?
static int RsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 6 && objc != 8) {
        Tcl_WrongNumArgs(interp, 1, objv, "-privkey pem -alg digest data ?-padding scheme?");
        return TCL_ERROR;
    }
    const char *privkey = NULL, *alg = NULL, *padding = "pkcs1";
    int privkey_len = 0;
    for (int i = 1; i < objc - 1; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[objc-1], &datalen);
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
    
    // Set padding scheme
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create PKEY context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (EVP_PKEY_sign_init(pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to initialize signing", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (strcmp(padding, "pss") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to set PSS padding", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to set PKCS1 padding", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown padding scheme (use 'pkcs1' or 'pss')", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set the digest algorithm
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, md) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to set signature digest", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Hash the data first
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, data, datalen) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hashlen)) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Two-step signature allocation for OpenSSL 3.x
    size_t siglen = 0;
    int ok = EVP_PKEY_sign(pkey_ctx, NULL, &siglen, hash, hashlen);
    if (!ok) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        char errbuf[512];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            Tcl_SetObjResult(interp, Tcl_NewStringObj(errbuf, -1));
        } else {
            Tcl_SetResult(interp, "OpenSSL: signing failed", TCL_STATIC);
        }
        return TCL_ERROR;
    }
    unsigned char *sig = ckalloc(siglen);
    ok = EVP_PKEY_sign(pkey_ctx, sig, &siglen, hash, hashlen);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    if (!ok) {
        ckfree((char *)sig);
        char errbuf[512];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            Tcl_SetObjResult(interp, Tcl_NewStringObj(errbuf, -1));
        } else {
            Tcl_SetResult(interp, "OpenSSL: signing failed", TCL_STATIC);
        }
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(sig, siglen));
    ckfree((char *)sig);
    return TCL_OK;
}

// tossl::rsa::verify -pubkey <pem> -alg <digest> <data> <signature> ?-padding <scheme>?
static int RsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 7 && objc != 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-pubkey pem -alg digest data signature ?-padding scheme?");
        return TCL_ERROR;
    }
    const char *pubkey = NULL, *alg = NULL, *padding = "pkcs1";
    int pubkey_len = 0;
    for (int i = 1; i < objc - 2; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-padding") == 0) {
            padding = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    int datalen, siglen;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[objc-2], &datalen);
    unsigned char *sig = (unsigned char *)Tcl_GetByteArrayFromObj(objv[objc-1], &siglen);
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
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ok = EVP_DigestVerifyInit(mdctx, &pkey_ctx, md, NULL, pkey);
    if (!ok) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to init verify", TCL_STATIC);
        return TCL_ERROR;
    }
    // Set padding
    if (strcmp(padding, "pss") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to set PSS padding", TCL_STATIC);
            return TCL_ERROR;
        }
    } else if (strcmp(padding, "pkcs1") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to set PKCS1 padding", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unknown padding scheme (use 'pkcs1' or 'pss')", TCL_STATIC);
        return TCL_ERROR;
    }
    // Hash the data
    if (!EVP_DigestVerifyUpdate(mdctx, data, datalen)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: verify update failed", TCL_STATIC);
        return TCL_ERROR;
    }
    ok = EVP_DigestVerifyFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok == 1));
    return TCL_OK;
}

// tossl::x509::create -subject dn -issuer dn -pubkey pem -privkey pem -days n [-san {dns1 dns2 ...}]
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



// --- SSL/TLS API Stubs ---
// --- SSL/TLS Context Handle Management ---
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>

// Structure to represent an SSL_CTX handle for Tcl
typedef struct SslContextHandle {
    SSL_CTX *ctx;
    char *handleName; // e.g., sslctx1
} SslContextHandle;

// Global hash table for SSL_CTX handles
static Tcl_HashTable sslContextTable;
static int sslContextTableInitialized = 0;
static int sslContextNextId = 1;

// Helper: Generate a unique handle name
static char *GenerateSslContextHandleName(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "sslctx%d", sslContextNextId++);
    return strdup(buf);
}

// tossl::ssl::context create ?options?
// Options:
//   -protocols {TLSv1.2 TLSv1.3 ...}
//   -ciphers "ECDHE+AESGCM"
//   -cert <pem>   -key <pem>
//   -cafile <pem> -verify 0|1
//   -alpn {proto1 proto2 ...} (e.g., {h2 http/1.1})
// Returns: handle name (e.g., sslctx1)
static int SslContextCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (!sslContextTableInitialized) {
        Tcl_InitHashTable(&sslContextTable, TCL_STRING_KEYS);
        sslContextTableInitialized = 1;
    }
    // Parse options (for now, just accept and ignore)
    int verify = 0;
    const char *cert = NULL, *key = NULL, *cafile = NULL, *ciphers = NULL;
    Tcl_Obj *protocolsObj = NULL;
    Tcl_Obj *alpnObj = NULL;
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-protocols") == 0) {
            protocolsObj = objv[i+1];
        } else if (strcmp(opt, "-ciphers") == 0) {
            ciphers = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-cert") == 0) {
            cert = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-key") == 0) {
            key = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-cafile") == 0) {
            cafile = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-verify") == 0) {
            if (Tcl_GetIntFromObj(interp, objv[i+1], &verify) != TCL_OK) return TCL_ERROR;
        } else if (strcmp(opt, "-alpn") == 0) {
            alpnObj = objv[i+1];
        } else {
            Tcl_SetResult(interp, "Unknown option to tossl::ssl::context create", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    // --- Create and configure SSL_CTX ---
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method = NULL;
    // Protocol selection: default to TLS_method()
    method = TLS_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create SSL_CTX", TCL_STATIC);
        return TCL_ERROR;
    }
    // Protocol restrictions (if -protocols specified)
    if (protocolsObj) {
        int protLen;
        Tcl_Obj **protElems;
        if (Tcl_ListObjGetElements(interp, protocolsObj, &protLen, &protElems) == TCL_OK) {
            long opts = 0;
            int want_v12 = 0, want_v13 = 0;
            for (int j = 0; j < protLen; ++j) {
                const char *p = Tcl_GetString(protElems[j]);
                if (strcmp(p, "TLSv1.2") == 0) want_v12 = 1;
                else if (strcmp(p, "TLSv1.3") == 0) want_v13 = 1;
            }
            // Only allow what is requested
#ifdef SSL_OP_NO_TLSv1_2
            if (!want_v12) opts |= SSL_OP_NO_TLSv1_2;
#endif
#ifdef SSL_OP_NO_TLSv1_3
            if (!want_v13) opts |= SSL_OP_NO_TLSv1_3;
#endif
            SSL_CTX_set_options(ctx, opts);
        }
    }
    // Cipher selection
    if (ciphers) {
        if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Invalid cipher list", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        // Set secure default cipher list
        const char *default_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
        if (!SSL_CTX_set_cipher_list(ctx, default_ciphers)) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Failed to set default cipher list", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // Enable session caching
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_AUTO_CLEAR);
    SSL_CTX_sess_set_cache_size(ctx, 1024);
    SSL_CTX_set_session_id_context(ctx, (const unsigned char*)"TOSSL", 5);
    
    // Set session timeout
    SSL_CTX_set_timeout(ctx, 300); // 5 minutes
    
    // Enable automatic session resumption
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    // Enable session tickets
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    
    // Enable OCSP stapling
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, NULL); // No callback for now
    
    // Certificate and key
    if (cert) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Failed to load certificate", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Failed to load private key", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (cert && key) {
        if (SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Certificate and key do not match", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    // CA file
    if (cafile) {
        if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
            SSL_CTX_free(ctx);
            Tcl_SetResult(interp, "Failed to load CA file", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    // Peer verification
    SSL_CTX_set_verify(ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    // ALPN support
    if (alpnObj) {
        int alpnLen;
        Tcl_Obj **alpnElems;
        if (Tcl_ListObjGetElements(interp, alpnObj, &alpnLen, &alpnElems) == TCL_OK && alpnLen > 0) {
            // ALPN wire format: list of length-prefixed strings
            unsigned char *alpn_wire = (unsigned char *)ckalloc(256);
            int offset = 0;
            for (int j = 0; j < alpnLen; ++j) {
                const char *proto = Tcl_GetString(alpnElems[j]);
                int plen = (int)strlen(proto);
                if (plen < 1 || plen > 255 || offset + plen + 1 > 255) {
                    ckfree((char *)alpn_wire);
                    SSL_CTX_free(ctx);
                    Tcl_SetResult(interp, "Invalid ALPN protocol list", TCL_STATIC);
                    return TCL_ERROR;
                }
                alpn_wire[offset++] = (unsigned char)plen;
                memcpy(alpn_wire + offset, proto, plen);
                offset += plen;
            }
            if (SSL_CTX_set_alpn_protos(ctx, alpn_wire, offset) != 0) {
                ckfree((char *)alpn_wire);
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to set ALPN protocols", TCL_STATIC);
                return TCL_ERROR;
            }
            ckfree((char *)alpn_wire);
        }
    }
    // Allocate handle and store SSL_CTX
    SslContextHandle *handle = (SslContextHandle *)ckalloc(sizeof(SslContextHandle));
    handle->ctx = ctx;
    handle->handleName = GenerateSslContextHandleName();
    Tcl_HashEntry *entryPtr;
    int newFlag;
    entryPtr = Tcl_CreateHashEntry(&sslContextTable, handle->handleName, &newFlag);
    Tcl_SetHashValue(entryPtr, handle);
    Tcl_SetResult(interp, handle->handleName, TCL_VOLATILE);
    return TCL_OK;

}

// tossl::ssl::context free <ctx>
// Frees the context handle and underlying SSL_CTX
static int SslContextFreeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "free <ctx>");
        return TCL_ERROR;
    }
    const char *handleName = Tcl_GetString(objv[2]);
    if (!sslContextTableInitialized) {
        Tcl_SetResult(interp, "No SSL contexts allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslContextTable, handleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL context handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslContextHandle *handle = (SslContextHandle *)Tcl_GetHashValue(entryPtr);
    if (handle->ctx) {
        SSL_CTX_free(handle->ctx);
    }
    ckfree(handle->handleName);
    ckfree((char *)handle);
    Tcl_DeleteHashEntry(entryPtr);
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

// --- SSL/TLS Socket Handle Management ---
typedef struct SslSocketHandle {
    SSL *ssl;
    char *handleName; // e.g., sslsock1
    char *chanName;   // Tcl channel name
    SslContextHandle *ctxHandle;
} SslSocketHandle;

static Tcl_HashTable sslSocketTable;
static int sslSocketTableInitialized = 0;
static int sslSocketNextId = 1;

static char *GenerateSslSocketHandleName(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "sslsock%d", sslSocketNextId++);
    return strdup(buf);
}

// Helper: Get file descriptor from Tcl channel (POSIX only)
#include <unistd.h>
static int GetFdFromChannel(Tcl_Interp *interp, const char *chanName) {
    Tcl_Channel chan = Tcl_GetChannel(interp, chanName, NULL);
    if (!chan) return -1;
    ClientData cd;
    if (Tcl_GetChannelHandle(chan, TCL_READABLE | TCL_WRITABLE, &cd) != TCL_OK) return -1;
    return (int)(intptr_t)cd;
}

// tossl::ssl::connect <sslsock>
// Performs SSL/TLS handshake as a client on the associated Tcl channel
static int SslConnectCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "connect <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[2]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    // Get file descriptor from Tcl channel
    int fd = GetFdFromChannel(interp, sockHandle->chanName);
    if (fd < 0) {
        Tcl_SetResult(interp, "Failed to get file descriptor from Tcl channel", TCL_STATIC);
        return TCL_ERROR;
    }
    // Attach BIO to SSL
    BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO for socket", TCL_STATIC);
        return TCL_ERROR;
    }
    SSL_set_bio(sockHandle->ssl, bio, bio);
    // Perform SSL handshake (client mode)
    int ret = SSL_connect(sockHandle->ssl);
    if (ret != 1) {
        int err = SSL_get_error(sockHandle->ssl, ret);
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("SSL_connect failed: %s (error %d)", errbuf, err));
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::accept <sslsock>
// Performs SSL/TLS handshake as a server on the associated Tcl channel
static int SslAcceptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "accept <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[2]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    // Get file descriptor from Tcl channel
    int fd = GetFdFromChannel(interp, sockHandle->chanName);
    if (fd < 0) {
        Tcl_SetResult(interp, "Failed to get file descriptor from Tcl channel", TCL_STATIC);
        return TCL_ERROR;
    }
    // Attach BIO to SSL
    BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) {
        Tcl_SetResult(interp, "Failed to create BIO for socket", TCL_STATIC);
        return TCL_ERROR;
    }
    SSL_set_bio(sockHandle->ssl, bio, bio);
    // Perform SSL handshake (server mode)
    int ret = SSL_accept(sockHandle->ssl);
    if (ret != 1) {
        int err = SSL_get_error(sockHandle->ssl, ret);
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("SSL_accept failed: %s (error %d)", errbuf, err));
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::read <sslsock> ?nbytes?
// Reads up to nbytes (default 4096) from the SSL connection
static int SslReadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3 && objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "read <sslsock> ?nbytes?");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[2]);
    int nbytes = 4096;
    if (objc == 4) {
        if (Tcl_GetIntFromObj(interp, objv[3], &nbytes) != TCL_OK || nbytes <= 0) {
            Tcl_SetResult(interp, "Invalid nbytes", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    unsigned char *buf = (unsigned char *)ckalloc(nbytes);
    int n = SSL_read(sockHandle->ssl, buf, nbytes);
    if (n <= 0) {
        int err = SSL_get_error(sockHandle->ssl, n);
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        ckfree(buf);
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("SSL_read failed: %s (error %d)", errbuf, err));
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buf, n));
    ckfree(buf);
    return TCL_OK;
}

// tossl::ssl::write <sslsock> <data>
// Writes data to the SSL connection, returns number of bytes written
static int SslWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "write <sslsock> <data>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[2]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    int len = 0;
    unsigned char *data = Tcl_GetByteArrayFromObj(objv[3], &len);
    int n = SSL_write(sockHandle->ssl, data, len);
    if (n <= 0) {
        int err = SSL_get_error(sockHandle->ssl, n);
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("SSL_write failed: %s (error %d)", errbuf, err));
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewIntObj(n));
    return TCL_OK;
}

// tossl::ssl::close <sslsock>
// Shuts down SSL connection and frees resources
static int SslCloseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "close <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[2]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    if (sockHandle->ssl) {
        SSL_shutdown(sockHandle->ssl);
        SSL_free(sockHandle->ssl);
    }
    if (sockHandle->chanName) ckfree(sockHandle->chanName);
    ckfree(sockHandle->handleName);
    ckfree((char *)sockHandle);
    Tcl_DeleteHashEntry(entryPtr);
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

// --- SSL/TLS Session Resumption Management ---
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <assert.h>

// Session handle struct
typedef struct SslSessionHandle {
    SSL_SESSION *session;
    char *handleName; // e.g., sslsession1
} SslSessionHandle;

static Tcl_HashTable sslSessionTable;
static int sslSessionTableInitialized = 0;
static int sslSessionNextId = 1;

static char *GenerateSslSessionHandleName(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "sslsession%d", sslSessionNextId++);
    return strdup(buf);
}

// tossl::ssl::session export <sslsock>
// Serializes the session and returns a base64 string
static int SslSessionExportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "session export <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[3]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    SSL_SESSION *sess = SSL_get_session(sockHandle->ssl);
    if (!sess) {
        Tcl_SetResult(interp, "No session available", TCL_STATIC);
        return TCL_ERROR;
    }
    int len = i2d_SSL_SESSION(sess, NULL);
    if (len <= 0) {
        Tcl_SetResult(interp, "Failed to serialize session", TCL_STATIC);
        return TCL_ERROR;
    }
    unsigned char *buf = (unsigned char *)ckalloc(len);
    unsigned char *p = buf;
    if (i2d_SSL_SESSION(sess, &p) != len) {
        ckfree(buf);
        Tcl_SetResult(interp, "Failed to serialize session (i2d)", TCL_STATIC);
        return TCL_ERROR;
    }
    // Encode as base64
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, buf, len);
    BIO_flush(b64);
    char *base64 = NULL;
    long blen = BIO_get_mem_data(mem, &base64);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(base64, blen));
    BIO_free_all(b64);
    ckfree(buf);
    return TCL_OK;
}

// tossl::ssl::session import <ctx> <base64blob>
// Imports a session and returns a session handle
static int SslSessionImportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "session import <ctx> <base64blob>");
        return TCL_ERROR;
    }
    const char *ctxHandleName = Tcl_GetString(objv[3]);
    const char *base64 = Tcl_GetString(objv[4]);
    if (!sslContextTableInitialized) {
        Tcl_SetResult(interp, "No SSL contexts allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *ctxEntry = Tcl_FindHashEntry(&sslContextTable, ctxHandleName);
    if (!ctxEntry) {
        Tcl_SetResult(interp, "Unknown SSL context handle", TCL_STATIC);
        return TCL_ERROR;
    }
    // Decode base64
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(base64, -1);
    BIO_push(b64, mem);
    unsigned char buf[16384];
    int len = BIO_read(b64, buf, sizeof(buf));
    BIO_free_all(b64);
    if (len <= 0) {
        Tcl_SetResult(interp, "Failed to decode base64 session", TCL_STATIC);
        return TCL_ERROR;
    }
    const unsigned char *p = buf;
    SSL_SESSION *sess = d2i_SSL_SESSION(NULL, &p, len);
    if (!sess) {
        Tcl_SetResult(interp, "Failed to parse session", TCL_STATIC);
        return TCL_ERROR;
    }
    // Store session handle
    if (!sslSessionTableInitialized) {
        Tcl_InitHashTable(&sslSessionTable, TCL_STRING_KEYS);
        sslSessionTableInitialized = 1;
    }
    SslSessionHandle *handle = (SslSessionHandle *)ckalloc(sizeof(SslSessionHandle));
    handle->session = sess;
    handle->handleName = GenerateSslSessionHandleName();
    Tcl_HashEntry *entryPtr;
    int newFlag;
    entryPtr = Tcl_CreateHashEntry(&sslSessionTable, handle->handleName, &newFlag);
    Tcl_SetHashValue(entryPtr, handle);
    Tcl_SetResult(interp, handle->handleName, TCL_VOLATILE);
    return TCL_OK;
}

// Helper: Look up a session handle by name
static SslSessionHandle *FindSslSessionHandle(const char *name) {
    if (!sslSessionTableInitialized) return NULL;
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSessionTable, name);
    if (!entryPtr) return NULL;
    return (SslSessionHandle *)Tcl_GetHashValue(entryPtr);
}

// --- Update SslSocketCmd to allow -session <sessionhandle> ---
// tossl::ssl::socket <ctx> <sock> ?-session <sessionhandle>?
// Looks up SSL_CTX handle, creates SSL*, associates with Tcl channel, optionally resumes session
static int SslSocketCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4 && objc != 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "<ctx> <sock> ?-session <sessionhandle>?");
        return TCL_ERROR;
    }
    const char *ctxHandleName = Tcl_GetString(objv[2]);
    const char *chanName = Tcl_GetString(objv[3]);
    const char *sessionHandleName = NULL;
    if (objc == 6) {
        if (strcmp(Tcl_GetString(objv[4]), "-session") != 0) {
            Tcl_SetResult(interp, "Expected -session option", TCL_STATIC);
            return TCL_ERROR;
        }
        sessionHandleName = Tcl_GetString(objv[5]);
    }
    // Look up context handle
    if (!sslContextTableInitialized) {
        Tcl_SetResult(interp, "No SSL contexts allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *ctxEntry = Tcl_FindHashEntry(&sslContextTable, ctxHandleName);
    if (!ctxEntry) {
        Tcl_SetResult(interp, "Unknown SSL context handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslContextHandle *ctxHandle = (SslContextHandle *)Tcl_GetHashValue(ctxEntry);
    if (!ctxHandle->ctx) {
        Tcl_SetResult(interp, "Invalid SSL_CTX in handle", TCL_STATIC);
        return TCL_ERROR;
    }
    // Check Tcl channel exists
    Tcl_Channel chan = Tcl_GetChannel(interp, chanName, NULL);
    if (!chan) {
        Tcl_SetResult(interp, "Unknown Tcl channel", TCL_STATIC);
        return TCL_ERROR;
    }
    // Create SSL object
    SSL *ssl = SSL_new(ctxHandle->ctx);
    if (!ssl) {
        Tcl_SetResult(interp, "Failed to create SSL object", TCL_STATIC);
        return TCL_ERROR;
    }
    // If session handle provided, set session
    if (sessionHandleName) {
        SslSessionHandle *sessHandle = FindSslSessionHandle(sessionHandleName);
        if (!sessHandle) {
            SSL_free(ssl);
            Tcl_SetResult(interp, "Unknown SSL session handle", TCL_STATIC);
            return TCL_ERROR;
        }
        if (SSL_set_session(ssl, sessHandle->session) != 1) {
            SSL_free(ssl);
            Tcl_SetResult(interp, "Failed to set SSL session", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    // For now, do not yet associate BIOs; just store the handle for later handshake
    if (!sslSocketTableInitialized) {
        Tcl_InitHashTable(&sslSocketTable, TCL_STRING_KEYS);
        sslSocketTableInitialized = 1;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)ckalloc(sizeof(SslSocketHandle));
    sockHandle->ssl = ssl;
    sockHandle->handleName = GenerateSslSocketHandleName();
    sockHandle->chanName = strdup(chanName);
    sockHandle->ctxHandle = ctxHandle;
    Tcl_HashEntry *entryPtr;
    int newFlag;
    entryPtr = Tcl_CreateHashEntry(&sslSocketTable, sockHandle->handleName, &newFlag);
    Tcl_SetHashValue(entryPtr, sockHandle);
    Tcl_SetResult(interp, sockHandle->handleName, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::session info <sslsock>
// Returns a Tcl dict with protocol, cipher, session id, peer cert subject, etc.
static int SslSessionInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "session info <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[3]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    SSL *ssl = sockHandle->ssl;
    Tcl_Obj *dict = Tcl_NewDictObj();
    // Protocol
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("protocol", -1), Tcl_NewStringObj(SSL_get_version(ssl), -1));
    // Cipher
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("cipher", -1), Tcl_NewStringObj(SSL_CIPHER_get_name(cipher), -1));
    }
    // Session ID
    SSL_SESSION *sess = SSL_get_session(ssl);
    if (sess) {
        unsigned int sidlen = 0;
        const unsigned char *sid = SSL_SESSION_get_id(sess, &sidlen);
        char hex[128] = {0};
        for (unsigned int i = 0; i < sidlen && i < sizeof(hex)/2-1; ++i) {
            sprintf(hex + i*2, "%02x", sid[i]);
        }
        Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("session_id", -1), Tcl_NewStringObj(hex, -1));
    }
    // Peer certificate subject
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer) {
        char subj[512];
        X509_NAME_oneline(X509_get_subject_name(peer), subj, sizeof(subj));
        Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("peer_subject", -1), Tcl_NewStringObj(subj, -1));
        X509_free(peer);
    }
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::ssl::peer cert <sslsock>
// Returns the PEM-encoded peer certificate (if available)
static int SslPeerCertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "peer cert <sslsock>");
        return TCL_ERROR;
    }
    const char *sockHandleName = Tcl_GetString(objv[3]);
    if (!sslSocketTableInitialized) {
        Tcl_SetResult(interp, "No SSL sockets allocated", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_HashEntry *entryPtr = Tcl_FindHashEntry(&sslSocketTable, sockHandleName);
    if (!entryPtr) {
        Tcl_SetResult(interp, "Unknown SSL socket handle", TCL_STATIC);
        return TCL_ERROR;
    }
    SslSocketHandle *sockHandle = (SslSocketHandle *)Tcl_GetHashValue(entryPtr);
    SSL *ssl = sockHandle->ssl;
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer) {
        Tcl_SetResult(interp, "No peer certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, peer);
    char *pem = NULL;
    long len = BIO_get_mem_data(mem, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, len));
    BIO_free(mem);
    X509_free(peer);
    return TCL_OK;
}

// tossl::csr::create -subject <dn> -pubkey <pem> -privkey <pem> [-san {dns1 dns2 ...}] [-keyusage {usage1 usage2 ...}]
static int CsrCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 7 || objc > 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-subject dn -pubkey pem -privkey pem [-san {dns1 dns2 ...}] [-keyusage {usage1 usage2 ...}]");
        return TCL_ERROR;
    }
    const char *subject = NULL, *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0;
    Tcl_Obj *sanListObj = NULL;
    Tcl_Obj *keyUsageListObj = NULL;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-subject") == 0) {
            subject = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-pubkey") == 0) {
            pubkey = Tcl_GetStringFromObj(objv[i+1], &pubkey_len);
        } else if (strcmp(opt, "-privkey") == 0) {
            privkey = Tcl_GetStringFromObj(objv[i+1], &privkey_len);
        } else if (strcmp(opt, "-san") == 0) {
            sanListObj = objv[i+1];
        } else if (strcmp(opt, "-keyusage") == 0) {
            keyUsageListObj = objv[i+1];
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    if (!subject || !pubkey || !privkey) {
        Tcl_SetResult(interp, "Missing required options", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Load public and private keys
    BIO *pub_bio = BIO_new_mem_buf((void*)pubkey, pubkey_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    BIO *priv_bio = BIO_new_mem_buf((void*)privkey, privkey_len);
    EVP_PKEY *signing_key = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    
    if (!pkey || !signing_key) {
        if (pkey) EVP_PKEY_free(pkey);
        if (signing_key) EVP_PKEY_free(signing_key);
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key(s)", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create CSR
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(signing_key);
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create X509_REQ object", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set version (v1)
    if (!X509_REQ_set_version(req, 0)) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(signing_key);
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to set CSR version", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set subject
    X509_NAME *subj = X509_NAME_new();
    if (!subj) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(signing_key);
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create subject name", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse subject DN (simple CN= format for now)
    if (strncmp(subject, "CN=", 3) == 0) {
        X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const unsigned char*)(subject + 3), -1, -1, 0);
    } else {
        // Try to add as CN directly
        X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const unsigned char*)subject, -1, -1, 0);
    }
    
    X509_REQ_set_subject_name(req, subj);
    X509_NAME_free(subj);
    
    // Set public key
    X509_REQ_set_pubkey(req, pkey);
    
    // Add extensions if provided
    if (sanListObj || keyUsageListObj) {
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        
        // Subject Alternative Name
        if (sanListObj) {
            int san_count;
            Tcl_Obj **san_items;
            if (Tcl_ListObjGetElements(interp, sanListObj, &san_count, &san_items) == TCL_OK) {
                GENERAL_NAMES *sans = sk_GENERAL_NAME_new_null();
                for (int i = 0; i < san_count; ++i) {
                    const char *dns = Tcl_GetString(san_items[i]);
                    GENERAL_NAME *name = GENERAL_NAME_new();
                    name->type = GEN_DNS;
                    name->d.dNSName = ASN1_IA5STRING_new();
                    ASN1_STRING_set(name->d.dNSName, dns, strlen(dns));
                    sk_GENERAL_NAME_push(sans, name);
                }
                X509_EXTENSION *san_ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, sans);
                if (san_ext) {
                    sk_X509_EXTENSION_push(exts, san_ext);
                }
                sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
            }
        }
        
        // Key Usage
        if (keyUsageListObj) {
            int usage_count;
            Tcl_Obj **usage_items;
            if (Tcl_ListObjGetElements(interp, keyUsageListObj, &usage_count, &usage_items) == TCL_OK) {
                ASN1_BIT_STRING *key_usage = ASN1_BIT_STRING_new();
                for (int i = 0; i < usage_count; ++i) {
                    const char *usage = Tcl_GetString(usage_items[i]);
                    if (strcmp(usage, "digitalSignature") == 0) ASN1_BIT_STRING_set_bit(key_usage, 0, 1);
                    else if (strcmp(usage, "nonRepudiation") == 0) ASN1_BIT_STRING_set_bit(key_usage, 1, 1);
                    else if (strcmp(usage, "keyEncipherment") == 0) ASN1_BIT_STRING_set_bit(key_usage, 2, 1);
                    else if (strcmp(usage, "dataEncipherment") == 0) ASN1_BIT_STRING_set_bit(key_usage, 3, 1);
                    else if (strcmp(usage, "keyAgreement") == 0) ASN1_BIT_STRING_set_bit(key_usage, 4, 1);
                    else if (strcmp(usage, "keyCertSign") == 0) ASN1_BIT_STRING_set_bit(key_usage, 5, 1);
                    else if (strcmp(usage, "cRLSign") == 0) ASN1_BIT_STRING_set_bit(key_usage, 6, 1);
                    else if (strcmp(usage, "encipherOnly") == 0) ASN1_BIT_STRING_set_bit(key_usage, 7, 1);
                    else if (strcmp(usage, "decipherOnly") == 0) ASN1_BIT_STRING_set_bit(key_usage, 8, 1);
                }
                X509_EXTENSION *usage_ext = X509V3_EXT_i2d(NID_key_usage, 0, key_usage);
                if (usage_ext) {
                    sk_X509_EXTENSION_push(exts, usage_ext);
                }
                ASN1_BIT_STRING_free(key_usage);
            }
        }
        
        // Add extensions to CSR
        if (sk_X509_EXTENSION_num(exts) > 0) {
            X509_REQ_add_extensions(req, exts);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    
    // Sign the CSR
    if (!X509_REQ_sign(req, signing_key, EVP_sha256())) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(signing_key);
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        Tcl_SetResult(interp, "OpenSSL: CSR signing failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Output PEM
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(out, req);
    char *pem = NULL;
    long pemlen = BIO_get_mem_data(out, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, pemlen));
    
    // Cleanup
    BIO_free(out);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(signing_key);
    BIO_free(pub_bio);
    BIO_free(priv_bio);
    
    return TCL_OK;
}

// tossl::csr::parse <pem>
static int CsrParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem");
        return TCL_ERROR;
    }
    int pem_len;
    const char *pem = Tcl_GetStringFromObj(objv[1], &pem_len);
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    
    // Subject
    char subj[256];
    X509_NAME_oneline(X509_REQ_get_subject_name(req), subj, sizeof(subj));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("subject", -1), Tcl_NewStringObj(subj, -1));
    
    // Version
    long version = X509_REQ_get_version(req);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("version", -1), Tcl_NewLongObj(version));
    
    // Public key info
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (pkey) {
        int bits = EVP_PKEY_get_bits(pkey);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_bits", -1), Tcl_NewIntObj(bits));
        
        int type = EVP_PKEY_base_id(pkey);
        const char *type_str = "unknown";
        if (type == EVP_PKEY_RSA) type_str = "rsa";
        else if (type == EVP_PKEY_DSA) type_str = "dsa";
        else if (type == EVP_PKEY_EC) type_str = "ec";
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("key_type", -1), Tcl_NewStringObj(type_str, -1));
        
        EVP_PKEY_free(pkey);
    }
    
    // Extensions
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if (exts) {
        Tcl_Obj *extList = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
            int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
            const char *ext_name = OBJ_nid2sn(nid);
            Tcl_ListObjAppendElement(interp, extList, Tcl_NewStringObj(ext_name ? ext_name : "unknown", -1));
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("extensions", -1), extList);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    
    // Parse all PKCS#10 attributes
    int attr_count = X509_REQ_get_attr_count(req);
    if (attr_count > 0) {
        Tcl_Obj *attrList = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < attr_count; ++i) {
            X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, i);
            int nid = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr));
            const char *attr_name = OBJ_nid2sn(nid);
            Tcl_Obj *entry = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, entry, Tcl_NewStringObj("oid", -1), Tcl_NewStringObj(attr_name ? attr_name : "unknown", -1));
            int val_count = X509_ATTRIBUTE_count(attr);
            Tcl_Obj *valList = Tcl_NewListObj(0, NULL);
            for (int j = 0; j < val_count; ++j) {
                ASN1_TYPE *val = X509_ATTRIBUTE_get0_type(attr, j);
                if (val->type == V_ASN1_UTF8STRING) {
                    Tcl_ListObjAppendElement(interp, valList, Tcl_NewStringObj((const char*)ASN1_STRING_get0_data(val->value.utf8string), ASN1_STRING_length(val->value.utf8string)));
                } else if (val->type == V_ASN1_IA5STRING) {
                    Tcl_ListObjAppendElement(interp, valList, Tcl_NewStringObj((const char*)ASN1_STRING_get0_data(val->value.ia5string), ASN1_STRING_length(val->value.ia5string)));
                } else if (val->type == V_ASN1_OCTET_STRING) {
                    char hex[256];
                    bin2hex(ASN1_STRING_get0_data(val->value.octet_string), ASN1_STRING_length(val->value.octet_string), hex);
                    Tcl_ListObjAppendElement(interp, valList, Tcl_NewStringObj(hex, -1));
                } else {
                    Tcl_ListObjAppendElement(interp, valList, Tcl_NewStringObj("(unparsed)", -1));
                }
            }
            Tcl_DictObjPut(interp, entry, Tcl_NewStringObj("values", -1), valList);
            Tcl_ListObjAppendElement(interp, attrList, entry);
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("attributes", -1), attrList);
    }
    
    // Cleanup
    X509_REQ_free(req);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::x509::verify -cert <pem> -ca <pem>
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

// tossl::jwk::extract -key <pem>
static int JwkExtractCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-key") != 0) {
        Tcl_SetResult(interp, "Expected -key option", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len;
    const char *key_pem = Tcl_GetStringFromObj(objv[2], &key_len);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    
    // Try as private key first
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as public key
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)key_pem, key_len);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int type = EVP_PKEY_base_id(pkey);
    Tcl_Obj *dict = Tcl_NewDictObj();
    
    if (type == EVP_PKEY_RSA) {
        // Extract RSA components
        RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        if (!rsa) {
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to get RSA key", TCL_STATIC);
            return TCL_ERROR;
        }
        
        const BIGNUM *n, *e;
        RSA_get0_key(rsa, &n, &e, NULL);
        
        // Convert to base64url
        int n_len = BN_num_bytes(n);
        int e_len = BN_num_bytes(e);
        unsigned char *n_buf = (unsigned char *)ckalloc(n_len);
        unsigned char *e_buf = (unsigned char *)ckalloc(e_len);
        
        BN_bn2bin(n, n_buf);
        BN_bn2bin(e, e_buf);
        
        // Remove leading zero if present
        if (n_len > 0 && n_buf[0] == 0) {
            n_buf++;
            n_len--;
        }
        
        // Encode as base64url
        int n_b64_len = 4 * ((n_len + 2) / 3);
        int e_b64_len = 4 * ((e_len + 2) / 3);
        unsigned char *n_b64 = (unsigned char *)ckalloc(n_b64_len + 1);
        unsigned char *e_b64 = (unsigned char *)ckalloc(e_b64_len + 1);
        
        EVP_EncodeBlock(n_b64, n_buf, n_len);
        EVP_EncodeBlock(e_b64, e_buf, e_len);
        
        // Convert to base64url (replace + with -, / with _, remove =)
        for (int i = 0; i < n_b64_len; i++) {
            if (n_b64[i] == '+') n_b64[i] = '-';
            else if (n_b64[i] == '/') n_b64[i] = '_';
            else if (n_b64[i] == '=') n_b64[i] = '\0';
        }
        for (int i = 0; i < e_b64_len; i++) {
            if (e_b64[i] == '+') e_b64[i] = '-';
            else if (e_b64[i] == '/') e_b64[i] = '_';
            else if (e_b64[i] == '=') e_b64[i] = '\0';
        }
        
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kty", -1), Tcl_NewStringObj("RSA", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("n", -1), Tcl_NewStringObj((char*)n_b64, -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("e", -1), Tcl_NewStringObj((char*)e_b64, -1));
        
        ckfree((char*)n_b64);
        ckfree((char*)e_b64);
        ckfree((char*)n_buf);
        ckfree((char*)e_buf);
        
    } else if (type == EVP_PKEY_EC) {
        // Extract EC components
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec) {
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to get EC key", TCL_STATIC);
            return TCL_ERROR;
        }
        
        const EC_POINT *point = EC_KEY_get0_public_key(ec);
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        
        // Get curve name
        int nid = EC_GROUP_get_curve_name(group);
        const char *curve_name = OBJ_nid2sn(nid);
        
        // Convert point to octet string
        size_t point_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        unsigned char *point_buf = (unsigned char *)ckalloc(point_len);
        EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, point_buf, point_len, NULL);
        
        // Encode as base64url
        int b64_len = 4 * ((point_len + 2) / 3);
        unsigned char *b64 = (unsigned char *)ckalloc(b64_len + 1);
        EVP_EncodeBlock(b64, point_buf, point_len);
        
        // Convert to base64url
        for (int i = 0; i < b64_len; i++) {
            if (b64[i] == '+') b64[i] = '-';
            else if (b64[i] == '/') b64[i] = '_';
            else if (b64[i] == '=') b64[i] = '\0';
        }
        
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("kty", -1), Tcl_NewStringObj("EC", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("crv", -1), Tcl_NewStringObj(curve_name ? curve_name : "unknown", -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("x", -1), Tcl_NewStringObj((char*)b64, -1));
        
        ckfree((char*)b64);
        ckfree((char*)point_buf);
        
    } else {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Unsupported key type for JWK", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::jwk::thumbprint -jwk <json>
static int JwkThumbprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-jwk json");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-jwk") != 0) {
        Tcl_SetResult(interp, "Expected -jwk option", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int json_len;
    const char *json = Tcl_GetStringFromObj(objv[2], &json_len);
    
    // Calculate SHA-256 hash
    const EVP_MD *md = EVP_get_digestbyname("sha256");
    if (!md) {
        Tcl_SetResult(interp, "OpenSSL: SHA-256 not available", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, json, json_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Encode as base64url
    int b64_len = 4 * ((hash_len + 2) / 3);
    unsigned char *b64 = (unsigned char *)ckalloc(b64_len + 1);
    EVP_EncodeBlock(b64, hash, hash_len);
    
    // Convert to base64url
    for (int i = 0; i < b64_len; i++) {
        if (b64[i] == '+') b64[i] = '-';
        else if (b64[i] == '/') b64[i] = '_';
        else if (b64[i] == '=') b64[i] = '\0';
    }
    
    Tcl_SetObjResult(interp, Tcl_NewStringObj((char*)b64, -1));
    ckfree((char*)b64);
    return TCL_OK;
}

// tossl::rsa::validate -key <pem>
static int RsaValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-key") != 0) {
        Tcl_SetResult(interp, "Expected -key option", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len;
    const char *key_pem = Tcl_GetStringFromObj(objv[2], &key_len);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    
    // Try as private key first
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Try as public key
        BIO_free(bio);
        bio = BIO_new_mem_buf((void*)key_pem, key_len);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Not an RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Validate RSA key
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to get RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int valid = RSA_check_key(rsa);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(valid == 1));
    return TCL_OK;
}

// tossl::rsa::components -key <pem>
static int RsaComponentsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-key pem");
        return TCL_ERROR;
    }
    const char *opt = Tcl_GetString(objv[1]);
    if (strcmp(opt, "-key") != 0) {
        Tcl_SetResult(interp, "Expected -key option", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int key_len;
    const char *key_pem = Tcl_GetStringFromObj(objv[2], &key_len);
    BIO *bio = BIO_new_mem_buf((void*)key_pem, key_len);
    
    // Try as private key first
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "Not an RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to get RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    
    // Convert BIGNUMs to hex strings
    if (n) {
        char *n_hex = BN_bn2hex(n);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("n", -1), Tcl_NewStringObj(n_hex, -1));
        OPENSSL_free(n_hex);
    }
    if (e) {
        char *e_hex = BN_bn2hex(e);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("e", -1), Tcl_NewStringObj(e_hex, -1));
        OPENSSL_free(e_hex);
    }
    if (d) {
        char *d_hex = BN_bn2hex(d);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("d", -1), Tcl_NewStringObj(d_hex, -1));
        OPENSSL_free(d_hex);
    }
    if (p) {
        char *p_hex = BN_bn2hex(p);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("p", -1), Tcl_NewStringObj(p_hex, -1));
        OPENSSL_free(p_hex);
    }
    if (q) {
        char *q_hex = BN_bn2hex(q);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("q", -1), Tcl_NewStringObj(q_hex, -1));
        OPENSSL_free(q_hex);
    }
    if (dmp1) {
        char *dmp1_hex = BN_bn2hex(dmp1);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("dmp1", -1), Tcl_NewStringObj(dmp1_hex, -1));
        OPENSSL_free(dmp1_hex);
    }
    if (dmq1) {
        char *dmq1_hex = BN_bn2hex(dmq1);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("dmq1", -1), Tcl_NewStringObj(dmq1_hex, -1));
        OPENSSL_free(dmq1_hex);
    }
    if (iqmp) {
        char *iqmp_hex = BN_bn2hex(iqmp);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("iqmp", -1), Tcl_NewStringObj(iqmp_hex, -1));
        OPENSSL_free(iqmp_hex);
    }
    
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::csr::validate <pem>
static int CsrValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem");
        return TCL_ERROR;
    }
    int pem_len;
    const char *pem = Tcl_GetStringFromObj(objv[1], &pem_len);
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Validate CSR signature
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    int valid = 0;
    if (pkey) {
        valid = X509_REQ_verify(req, pkey);
        EVP_PKEY_free(pkey);
    }
    
    // Cleanup
    X509_REQ_free(req);
    BIO_free(bio);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(valid == 1));
    return TCL_OK;
}

// tossl::csr::fingerprint <pem> ?-algorithm sha1|sha256|sha512?
static int CsrFingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 2 || objc > 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "pem ?-algorithm sha1|sha256|sha512?");
        return TCL_ERROR;
    }
    
    const char *algorithm = "sha256"; // Default
    const char *pem = NULL;
    int pem_len = 0;
    
    if (objc == 4) {
        const char *opt = Tcl_GetString(objv[1]);
        if (strcmp(opt, "-algorithm") == 0) {
            algorithm = Tcl_GetString(objv[2]);
            pem = Tcl_GetStringFromObj(objv[3], &pem_len);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        pem = Tcl_GetStringFromObj(objv[1], &pem_len);
    }
    
    // Parse CSR
    BIO *bio = BIO_new_mem_buf((void*)pem, pem_len);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get DER encoding
    BIO *der_bio = BIO_new(BIO_s_mem());
    i2d_X509_REQ_bio(der_bio, req);
    char *der_data = NULL;
    long der_len = BIO_get_mem_data(der_bio, &der_data);
    
    // Calculate hash
    const EVP_MD *md = NULL;
    if (strcmp(algorithm, "sha1") == 0) md = EVP_sha1();
    else if (strcmp(algorithm, "sha256") == 0) md = EVP_sha256();
    else if (strcmp(algorithm, "sha512") == 0) md = EVP_sha512();
    else {
        X509_REQ_free(req);
        BIO_free(bio);
        BIO_free(der_bio);
        Tcl_SetResult(interp, "Unsupported algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_Digest(der_data, der_len, hash, &hash_len, md, NULL);
    
    // Convert to hex
    char hex_hash[EVP_MAX_MD_SIZE * 2 + 1];
    bin2hex(hash, hash_len, hex_hash);
    
    // Cleanup
    X509_REQ_free(req);
    BIO_free(bio);
    BIO_free(der_bio);
    
    Tcl_SetObjResult(interp, Tcl_NewStringObj(hex_hash, -1));
    return TCL_OK;
}

// tossl::csr::modify -csr <pem> -add_extension <oid> <value> <critical> ?-remove_extension <oid>?
static int CsrModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    const char *csr_pem = NULL, *oid = NULL, *value = NULL;
    int csr_len = 0, critical = 0;
    const char *remove_oid = NULL;
    int i = 1;
    for (; i < objc; ++i) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-csr") == 0 && i+1 < objc) {
            csr_pem = Tcl_GetStringFromObj(objv[++i], &csr_len);
        } else if (strcmp(opt, "-add_extension") == 0 && i+3 < objc) {
            oid = Tcl_GetString(objv[++i]);
            value = Tcl_GetString(objv[++i]);
            if (Tcl_GetIntFromObj(interp, objv[++i], &critical) != TCL_OK) return TCL_ERROR;
        } else if (strcmp(opt, "-remove_extension") == 0 && i+1 < objc) {
            remove_oid = Tcl_GetString(objv[++i]);
        } else {
            break;
        }
    }
    if (!csr_pem) {
        Tcl_SetResult(interp, "Missing -csr option", TCL_STATIC);
        return TCL_ERROR;
    }
    BIO *bio = BIO_new_mem_buf((void*)csr_pem, csr_len);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (!req) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse CSR", TCL_STATIC);
        return TCL_ERROR;
    }
    // Remove extension if requested
    if (remove_oid) {
        int nid = OBJ_txt2nid(remove_oid);
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
        if (exts) {
            for (int j = 0; j < sk_X509_EXTENSION_num(exts); ++j) {
                X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, j);
                if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == nid) {
                    sk_X509_EXTENSION_delete(exts, j);
                    break;
                }
            }
            X509_REQ_add_extensions(req, exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }
    // Add extension if requested
    if (oid && value) {
        int nid = OBJ_txt2nid(oid);
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
        if (!ext) {
            X509_REQ_free(req);
            BIO_free(bio);
            Tcl_SetResult(interp, "OpenSSL: failed to create extension", TCL_STATIC);
            return TCL_ERROR;
        }
        X509_EXTENSION_set_critical(ext, critical);
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
        if (!exts) exts = sk_X509_EXTENSION_new_null();
        sk_X509_EXTENSION_push(exts, ext);
        X509_REQ_add_extensions(req, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    // Output PEM
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(out, req);
    char *pem = NULL;
    long pemlen = BIO_get_mem_data(out, &pem);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(pem, pemlen));
    BIO_free(out);
    X509_REQ_free(req);
    BIO_free(bio);
    return TCL_OK;
}

// Package initialization
int Tossl_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) {
        return TCL_ERROR;
    }
    // Load OpenSSL default and legacy providers for all digests
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!defprov || !legacy) {
        Tcl_SetResult(interp, "OpenSSL: failed to load default or legacy provider (hashes)", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_CreateObjCommand(interp, "tossl::digest", DigestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::list", DigestListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::stream", DigestStreamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::compare", DigestCompareCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::hmac", HmacCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::randbytes", RandBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rand::iv", RandIvCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rand::key", RandKeyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::pbkdf2", Pbkdf2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::scrypt", ScryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::argon2", Argon2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::cipher::info", CipherInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::cipher::list", CipherListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::encrypt", EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::decrypt", DecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::generate", RsaGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::encrypt", RsaEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::decrypt", RsaDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::parse", X509ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::modify", X509ModifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::sign", RsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::verify", RsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::dsa::sign", DsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::dsa::verify", DsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::sign", EcSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::verify", EcVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::create", X509CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::verify", X509VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::validate", X509ValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::fingerprint", X509FingerprintCmd, NULL, NULL);
    // --- SSL/TLS API Commands ---
    Tcl_CreateObjCommand(interp, "tossl::ssl::context", SslContextCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::context_free", SslContextFreeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::socket", SslSocketCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::connect", SslConnectCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::accept", SslAcceptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::read", SslReadCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::write", SslWriteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::close", SslCloseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::session_info", SslSessionInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::peer_cert", SslPeerCertCmd, NULL, NULL);
    // Advanced session resumption commands
    //   tossl::ssl::session export <sslsock>
    //   tossl::ssl::session import <ctx> <base64blob>
    Tcl_CreateObjCommand(interp, "tossl::ssl::session_export", SslSessionExportCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::session_import", SslSessionImportCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::generate", KeyGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::parse", KeyParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::write", KeyWriteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::getpub", KeyGetPubCmd, NULL, NULL);
    Tcl_PkgProvide(interp, "tossl", "0.1");
    Tcl_CreateObjCommand(interp, "tossl::base64::encode", Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::base64::decode", Base64DecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::hex::encode", HexEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::hex::decode", HexDecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs12::parse", Pkcs12ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs12::create", Pkcs12CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::sign", Pkcs7SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::verify", Pkcs7VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::encrypt", Pkcs7EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::decrypt", Pkcs7DecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::info", Pkcs7InfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::create", CsrCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::parse", CsrParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::validate", CsrValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::fingerprint", CsrFingerprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwk::extract", JwkExtractCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwk::thumbprint", JwkThumbprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::validate", RsaValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::components", RsaComponentsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::validate", CsrValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::fingerprint", CsrFingerprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::modify", CsrModifyCmd, NULL, NULL);
    return TCL_OK;
}

// tossl::x509::validate -cert <pem> -ca <pem>
static int X509ValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    
    if (!cert || !ca) {
        if (cert) X509_free(cert);
        if (ca) X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse certificate(s)", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create certificate store
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        X509_free(cert);
        X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create certificate store", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add CA certificate to store
    if (!X509_STORE_add_cert(store, ca)) {
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to add CA to store", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create certificate chain
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create certificate chain", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add certificates to chain
    sk_X509_push(chain, cert);
    sk_X509_push(chain, ca);
    
    // Verify certificate
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        sk_X509_free(chain);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create store context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!X509_STORE_CTX_init(ctx, store, cert, chain)) {
        X509_STORE_CTX_free(ctx);
        sk_X509_free(chain);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca);
        BIO_free(cert_bio);
        BIO_free(ca_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to initialize store context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    int valid = X509_verify_cert(ctx);
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(valid == 1));
    
    if (valid != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        const char *err_str = X509_verify_cert_error_string(err);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("error", -1), Tcl_NewStringObj(err_str, -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("error_code", -1), Tcl_NewIntObj(err));
    }
    
    X509_STORE_CTX_free(ctx);
    sk_X509_free(chain);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(ca);
    BIO_free(cert_bio);
    BIO_free(ca_bio);
    
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

// tossl::x509::fingerprint -cert <pem> ?-alg <digest>?
static int X509FingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3 && objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-cert pem ?-alg digest?");
        return TCL_ERROR;
    }
    const char *cert_pem = NULL, *alg = "sha256";
    int cert_len = 0;
    
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-cert") == 0) {
            cert_pem = Tcl_GetStringFromObj(objv[i+1], &cert_len);
        } else if (strcmp(opt, "-alg") == 0) {
            alg = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, cert_len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert certificate to DER
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len <= 0) {
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to convert certificate to DER", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Calculate hash
    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) {
        OPENSSL_free(der);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Unknown digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        OPENSSL_free(der);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: failed to create digest context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_DigestInit_ex(mdctx, md, NULL) ||
        !EVP_DigestUpdate(mdctx, der, der_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(der);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "OpenSSL: digest calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char hex[2*EVP_MAX_MD_SIZE+1];
    bin2hex(hash, hash_len, hex);
    
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);
    X509_free(cert);
    BIO_free(cert_bio);
    
    Tcl_SetResult(interp, hex, TCL_VOLATILE);
    return TCL_OK;
}
