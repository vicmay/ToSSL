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
 */

#include <tcl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/pem.h>

// JWT structure
typedef struct {
    char *header;
    char *payload;
    char *signature;
    char *algorithm;
    int is_valid;
    char *error_message;
} JwtToken;

// JWT algorithms
typedef enum {
    JWT_ALG_HS256,
    JWT_ALG_HS384,
    JWT_ALG_HS512,
    JWT_ALG_RS256,
    JWT_ALG_RS384,
    JWT_ALG_RS512,
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    JWT_ALG_NONE
} JwtAlgorithm;

// Base64URL encoding/decoding functions
static char *base64url_encode(const unsigned char *data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    char *result = malloc(bufferPtr->length + 1);
    memcpy(result, bufferPtr->data, bufferPtr->length);
    result[bufferPtr->length] = '\0';
    
    // Replace '+' with '-', '/' with '_', and remove '='
    for (int i = 0; result[i]; i++) {
        if (result[i] == '+') result[i] = '-';
        else if (result[i] == '/') result[i] = '_';
    }
    
    // Remove padding
    while (strlen(result) > 0 && result[strlen(result) - 1] == '=') {
        result[strlen(result) - 1] = '\0';
    }
    
    BIO_free_all(bio);
    return result;
}

static unsigned char *base64url_decode(const char *input, size_t *len) {
    int input_len = strlen(input);
    int temp_len = input_len;
    
    // Calculate required padding
    while (temp_len % 4 != 0) {
        temp_len++;
    }
    
    // Allocate space for the padded string
    char *temp = malloc(temp_len + 1);
    if (!temp) return NULL;
    
    // Copy the input
    strcpy(temp, input);
    
    // Restore padding
    for (int i = input_len; i < temp_len; i++) {
        temp[i] = '=';
    }
    temp[temp_len] = '\0';
    
    // Replace '-' with '+', '_' with '/'
    for (int i = 0; temp[i]; i++) {
        if (temp[i] == '-') temp[i] = '+';
        else if (temp[i] == '_') temp[i] = '/';
    }
    
    BIO *bio, *b64;
    bio = BIO_new_mem_buf(temp, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    unsigned char *buffer = malloc(1024);
    *len = BIO_read(bio, buffer, 1024);
    
    BIO_free_all(bio);
    free(temp);
    
    return buffer;
}

// HMAC signature functions
static char *hmac_sign(const char *data, const char *key, JwtAlgorithm alg) {
    const EVP_MD *md;
    switch (alg) {
        case JWT_ALG_HS256: md = EVP_sha256(); break;
        case JWT_ALG_HS384: md = EVP_sha384(); break;
        case JWT_ALG_HS512: md = EVP_sha512(); break;
        default: return NULL;
    }
    
    unsigned char *hmac = HMAC(md, key, strlen(key), 
                               (unsigned char *)data, strlen(data), NULL, NULL);
    if (!hmac) return NULL;
    
    unsigned int hmac_len;
    HMAC(md, key, strlen(key), (unsigned char *)data, strlen(data), hmac, &hmac_len);
    
    return base64url_encode(hmac, hmac_len);
}

static int hmac_verify(const char *data, const char *signature, const char *key, JwtAlgorithm alg) {
    char *expected_sig = hmac_sign(data, key, alg);
    if (!expected_sig) return 0;
    
    int result = (strcmp(expected_sig, signature) == 0);
    free(expected_sig);
    return result;
}

// RSA signature functions
static char *rsa_sign(const char *data, EVP_PKEY *pkey, JwtAlgorithm alg) {
    if (!data || !pkey) {
        fprintf(stderr, "[rsa_sign] NULL data or pkey\n");
        return NULL;
    }
    
    const EVP_MD *md;
    switch (alg) {
        case JWT_ALG_RS256: md = EVP_sha256(); break;
        case JWT_ALG_RS384: md = EVP_sha384(); break;
        case JWT_ALG_RS512: md = EVP_sha512(); break;
        default: 
            fprintf(stderr, "[rsa_sign] Invalid algorithm: %d\n", alg);
            return NULL;
    }
    
    if (!md) {
        fprintf(stderr, "[rsa_sign] Failed to get digest method\n");
        return NULL;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[rsa_sign] Failed to create MD context\n");
        return NULL;
    }
    
    fprintf(stderr, "[rsa_sign] About to call EVP_DigestSignInit\n");
    fprintf(stderr, "[rsa_sign] pkey address: %p\n", (void*)pkey);
    if (pkey) {
        fprintf(stderr, "[rsa_sign] pkey type: %d\n", EVP_PKEY_id(pkey));
    } else {
        fprintf(stderr, "[rsa_sign] pkey is NULL, cannot print type\n");
    }
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        fprintf(stderr, "[rsa_sign] EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    size_t sig_len;
    if (EVP_DigestSign(ctx, NULL, &sig_len, (unsigned char *)data, strlen(data)) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char *sig = malloc(sig_len);
    if (EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *)data, strlen(data)) != 1) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    
    char *result = base64url_encode(sig, sig_len);
    free(sig);
    return result;
}

static int rsa_verify(const char *data, const char *signature, EVP_PKEY *pkey, JwtAlgorithm alg) {
    const EVP_MD *md;
    switch (alg) {
        case JWT_ALG_RS256: md = EVP_sha256(); break;
        case JWT_ALG_RS384: md = EVP_sha384(); break;
        case JWT_ALG_RS512: md = EVP_sha512(); break;
        default: return 0;
    }
    
    size_t sig_len;
    unsigned char *sig = base64url_decode(signature, &sig_len);
    if (!sig) return 0;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(sig);
        return 0;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    int result = (EVP_DigestVerify(ctx, sig, sig_len, (unsigned char *)data, strlen(data)) == 1);
    
    free(sig);
    EVP_MD_CTX_free(ctx);
    return result;
}

// EC signature functions
static char *ec_sign(const char *data, EVP_PKEY *pkey, JwtAlgorithm alg) {
    const EVP_MD *md;
    switch (alg) {
        case JWT_ALG_ES256: md = EVP_sha256(); break;
        case JWT_ALG_ES384: md = EVP_sha384(); break;
        case JWT_ALG_ES512: md = EVP_sha512(); break;
        default: return NULL;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    size_t sig_len;
    if (EVP_DigestSign(ctx, NULL, &sig_len, (unsigned char *)data, strlen(data)) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char *sig = malloc(sig_len);
    if (EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *)data, strlen(data)) != 1) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    
    char *result = base64url_encode(sig, sig_len);
    free(sig);
    return result;
}

static int ec_verify(const char *data, const char *signature, EVP_PKEY *pkey, JwtAlgorithm alg) {
    const EVP_MD *md;
    switch (alg) {
        case JWT_ALG_ES256: md = EVP_sha256(); break;
        case JWT_ALG_ES384: md = EVP_sha384(); break;
        case JWT_ALG_ES512: md = EVP_sha512(); break;
        default: return 0;
    }
    
    size_t sig_len;
    unsigned char *sig = base64url_decode(signature, &sig_len);
    if (!sig) return 0;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(sig);
        return 0;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    int result = (EVP_DigestVerify(ctx, sig, sig_len, (unsigned char *)data, strlen(data)) == 1);
    
    free(sig);
    EVP_MD_CTX_free(ctx);
    return result;
}

// Parse algorithm string
static JwtAlgorithm parse_algorithm(const char *alg_str) {
    if (strcmp(alg_str, "HS256") == 0) return JWT_ALG_HS256;
    if (strcmp(alg_str, "HS384") == 0) return JWT_ALG_HS384;
    if (strcmp(alg_str, "HS512") == 0) return JWT_ALG_HS512;
    if (strcmp(alg_str, "RS256") == 0) return JWT_ALG_RS256;
    if (strcmp(alg_str, "RS384") == 0) return JWT_ALG_RS384;
    if (strcmp(alg_str, "RS512") == 0) return JWT_ALG_RS512;
    if (strcmp(alg_str, "ES256") == 0) return JWT_ALG_ES256;
    if (strcmp(alg_str, "ES384") == 0) return JWT_ALG_ES384;
    if (strcmp(alg_str, "ES512") == 0) return JWT_ALG_ES512;
    if (strcmp(alg_str, "none") == 0) return JWT_ALG_NONE;
    return JWT_ALG_HS256; // default
}

// Create JWT token
int JwtCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-header <header_dict> -payload <payload_dict> -key <key> -alg <algorithm>");
        return TCL_ERROR;
    }
    
    const char *header_str = NULL;
    const char *payload_str = NULL;
    const char *key_str = NULL;
    const char *alg_str = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-header") == 0) {
            header_str = value;
        } else if (strcmp(option, "-payload") == 0) {
            payload_str = value;
        } else if (strcmp(option, "-key") == 0) {
            key_str = value;
        } else if (strcmp(option, "-alg") == 0) {
            alg_str = value;
        }
    }
    
    if (!header_str || !payload_str || !key_str || !alg_str) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    JwtAlgorithm alg = parse_algorithm(alg_str);
    
    // Encode header and payload
    char *header_encoded = base64url_encode((unsigned char *)header_str, strlen(header_str));
    char *payload_encoded = base64url_encode((unsigned char *)payload_str, strlen(payload_str));
    
    if (!header_encoded || !payload_encoded) {
        if (header_encoded) free(header_encoded);
        if (payload_encoded) free(payload_encoded);
        Tcl_SetResult(interp, "Failed to encode header or payload", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create data to sign
    char *data_to_sign = malloc(strlen(header_encoded) + strlen(payload_encoded) + 2);
    sprintf(data_to_sign, "%s.%s", header_encoded, payload_encoded);
    
    // Generate signature
    char *signature = NULL;
    
    if (alg == JWT_ALG_NONE) {
        signature = strdup("");
    } else if (alg >= JWT_ALG_HS256 && alg <= JWT_ALG_HS512) {
        signature = hmac_sign(data_to_sign, key_str, alg);
    } else if (alg >= JWT_ALG_RS256 && alg <= JWT_ALG_RS512) {
        // Parse RSA key
        BIO *bio = BIO_new_mem_buf(key_str, -1);
        if (!bio) {
            free(header_encoded);
            free(payload_encoded);
            free(data_to_sign);
            fprintf(stderr, "[JwtCreateCmd] Failed to create BIO for RSA key\n");
            Tcl_SetResult(interp, "Failed to create BIO for RSA key", TCL_STATIC);
            return TCL_ERROR;
        }
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (!pkey) {
            free(header_encoded);
            free(payload_encoded);
            free(data_to_sign);
            BIO_free(bio);
            fprintf(stderr, "[JwtCreateCmd] Invalid RSA private key or PEM format error\n");
            Tcl_SetResult(interp, "Invalid RSA private key or PEM format error", TCL_STATIC);
            return TCL_ERROR;
        }
        BIO_free(bio);
        signature = rsa_sign(data_to_sign, pkey, alg);
        EVP_PKEY_free(pkey);
    } else if (alg >= JWT_ALG_ES256 && alg <= JWT_ALG_ES512) {
        // Parse EC key
        BIO *bio = BIO_new_mem_buf(key_str, -1);
        if (!bio) {
            free(header_encoded);
            free(payload_encoded);
            free(data_to_sign);
            fprintf(stderr, "[JwtCreateCmd] Failed to create BIO for EC key\n");
            Tcl_SetResult(interp, "Failed to create BIO for EC key", TCL_STATIC);
            return TCL_ERROR;
        }
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (!pkey) {
            free(header_encoded);
            free(payload_encoded);
            free(data_to_sign);
            BIO_free(bio);
            fprintf(stderr, "[JwtCreateCmd] Invalid EC private key or PEM format error\n");
            Tcl_SetResult(interp, "Invalid EC private key or PEM format error", TCL_STATIC);
            return TCL_ERROR;
        }
        BIO_free(bio);
        signature = ec_sign(data_to_sign, pkey, alg);
        EVP_PKEY_free(pkey);
    }
    
    if (!signature) {
        free(header_encoded);
        free(payload_encoded);
        free(data_to_sign);
        Tcl_SetResult(interp, "Failed to generate signature", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create JWT token
    int jwt_len = strlen(header_encoded) + strlen(payload_encoded) + strlen(signature) + 3;
    char *jwt = (char *)Tcl_Alloc(jwt_len);
    sprintf(jwt, "%s.%s.%s", header_encoded, payload_encoded, signature);
    
    Tcl_SetResult(interp, jwt, TCL_DYNAMIC);
    
    // Cleanup
    free(header_encoded);
    free(payload_encoded);
    free(data_to_sign);
    free(signature);
    
    return TCL_OK;
}

// Verify JWT token
int JwtVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <jwt_string> -key <key> -alg <algorithm>");
        return TCL_ERROR;
    }
    
    const char *token_str = NULL;
    const char *key_str = NULL;
    const char *alg_str = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-token") == 0) {
            token_str = value;
        } else if (strcmp(option, "-key") == 0) {
            key_str = value;
        } else if (strcmp(option, "-alg") == 0) {
            alg_str = value;
        }
    }
    
    if (!token_str || !key_str || !alg_str) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    JwtAlgorithm alg = parse_algorithm(alg_str);
    
    // Split token into parts manually to handle empty signature
    char *token_copy = strdup(token_str);
    char *header_part = NULL;
    char *payload_part = NULL;
    char *signature_part = NULL;
    
    // Find first dot
    char *first_dot = strchr(token_copy, '.');
    if (!first_dot) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    *first_dot = '\0';
    header_part = token_copy;
    
    // Find second dot
    char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    *second_dot = '\0';
    payload_part = first_dot + 1;
    
    // Signature part (may be empty)
    signature_part = second_dot + 1;
    
    if (!header_part || !payload_part) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create data that was signed
    char *data_to_verify = malloc(strlen(header_part) + strlen(payload_part) + 2);
    sprintf(data_to_verify, "%s.%s", header_part, payload_part);
    
    // Verify signature
    int is_valid = 0;
    
    if (alg == JWT_ALG_NONE) {
        is_valid = (strlen(signature_part) == 0);
    } else if (alg >= JWT_ALG_HS256 && alg <= JWT_ALG_HS512) {
        is_valid = hmac_verify(data_to_verify, signature_part, key_str, alg);
    } else if (alg >= JWT_ALG_RS256 && alg <= JWT_ALG_RS512) {
        // Parse RSA public key
        BIO *bio = BIO_new_mem_buf(key_str, -1);
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!pkey) {
            free(token_copy);
            free(data_to_verify);
            Tcl_SetResult(interp, "Invalid RSA public key", TCL_STATIC);
            return TCL_ERROR;
        }
        
        is_valid = rsa_verify(data_to_verify, signature_part, pkey, alg);
        EVP_PKEY_free(pkey);
    } else if (alg >= JWT_ALG_ES256 && alg <= JWT_ALG_ES512) {
        // Parse EC public key
        BIO *bio = BIO_new_mem_buf(key_str, -1);
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!pkey) {
            free(token_copy);
            free(data_to_verify);
            Tcl_SetResult(interp, "Invalid EC public key", TCL_STATIC);
            return TCL_ERROR;
        }
        
        is_valid = ec_verify(data_to_verify, signature_part, pkey, alg);
        EVP_PKEY_free(pkey);
    }
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_Obj *valid_obj = Tcl_NewBooleanObj(is_valid);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), valid_obj);
    
    if (!is_valid) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj("Invalid signature", -1));
    }
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free(token_copy);
    free(data_to_verify);
    
    return TCL_OK;
}

// Decode JWT token (without verification)
int JwtDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <jwt_string>");
        return TCL_ERROR;
    }
    
    const char *token_str = Tcl_GetString(objv[2]);
    
    // Split token into parts manually to handle empty signature
    char *token_copy = strdup(token_str);
    char *header_part = NULL;
    char *payload_part = NULL;
    char *signature_part = NULL;
    
    // Find first dot
    char *first_dot = strchr(token_copy, '.');
    if (!first_dot) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    *first_dot = '\0';
    header_part = token_copy;
    
    // Find second dot
    char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    *second_dot = '\0';
    payload_part = first_dot + 1;
    
    // Signature part (may be empty)
    signature_part = second_dot + 1;
    
    if (!header_part || !payload_part) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Decode header and payload
    size_t header_len, payload_len;
    unsigned char *header_decoded = base64url_decode(header_part, &header_len);
    unsigned char *payload_decoded = base64url_decode(payload_part, &payload_len);
    
    if (!header_decoded || !payload_decoded) {
        if (header_decoded) free(header_decoded);
        if (payload_decoded) free(payload_decoded);
        free(token_copy);
        Tcl_SetResult(interp, "Failed to decode JWT parts", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    // Add header
    Tcl_Obj *header_obj = Tcl_NewStringObj((char *)header_decoded, header_len);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("header", -1), header_obj);
    
    // Add payload
    Tcl_Obj *payload_obj = Tcl_NewStringObj((char *)payload_decoded, payload_len);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("payload", -1), payload_obj);
    
    // Add signature
    Tcl_Obj *signature_obj = Tcl_NewStringObj(signature_part, -1);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("signature", -1), signature_obj);
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free(header_decoded);
    free(payload_decoded);
    free(token_copy);
    
    return TCL_OK;
}

// JWT claims validation structure
typedef struct {
    char *issuer;
    char *audience;
    char *subject;
    time_t issued_at;
    time_t not_before;
    time_t expiration;
    char *jwt_id;
    char *error;
} JwtClaims;

// Free JWT claims
static void free_jwt_claims(JwtClaims *claims) {
    if (claims->issuer) free(claims->issuer);
    if (claims->audience) free(claims->audience);
    if (claims->subject) free(claims->subject);
    if (claims->jwt_id) free(claims->jwt_id);
    if (claims->error) free(claims->error);
    free(claims);
}

// Parse JWT claims from payload
static JwtClaims *parse_jwt_claims(const char *payload_str) {
    JwtClaims *claims = calloc(1, sizeof(JwtClaims));
    if (!claims) return NULL;
    
    json_object *payload = json_tokener_parse(payload_str);
    if (!payload) {
        claims->error = strdup("Invalid JSON payload");
        return claims;
    }
    
    json_object *iss_obj, *aud_obj, *sub_obj, *iat_obj, *nbf_obj, *exp_obj, *jti_obj;
    
    if (json_object_object_get_ex(payload, "iss", &iss_obj)) {
        claims->issuer = strdup(json_object_get_string(iss_obj));
    }
    
    if (json_object_object_get_ex(payload, "aud", &aud_obj)) {
        claims->audience = strdup(json_object_get_string(aud_obj));
    }
    
    if (json_object_object_get_ex(payload, "sub", &sub_obj)) {
        claims->subject = strdup(json_object_get_string(sub_obj));
    }
    
    if (json_object_object_get_ex(payload, "iat", &iat_obj)) {
        claims->issued_at = json_object_get_int(iat_obj);
    }
    
    if (json_object_object_get_ex(payload, "nbf", &nbf_obj)) {
        claims->not_before = json_object_get_int(nbf_obj);
    }
    
    if (json_object_object_get_ex(payload, "exp", &exp_obj)) {
        claims->expiration = json_object_get_int(exp_obj);
    }
    
    if (json_object_object_get_ex(payload, "jti", &jti_obj)) {
        claims->jwt_id = strdup(json_object_get_string(jti_obj));
    }
    
    json_object_put(payload);
    return claims;
}

// Validate JWT claims
static int validate_jwt_claims(JwtClaims *claims, const char *expected_issuer, 
                              const char *expected_audience, int check_expiration) {
    time_t now = time(NULL);
    
    // Check expiration
    if (check_expiration && claims->expiration > 0) {
        if (now >= claims->expiration) {
            claims->error = strdup("Token has expired");
            return 0;
        }
    }
    
    // Check not before
    if (claims->not_before > 0) {
        if (now < claims->not_before) {
            claims->error = strdup("Token not yet valid");
            return 0;
        }
    }
    
    // Check issuer
    if (expected_issuer && claims->issuer) {
        if (strcmp(claims->issuer, expected_issuer) != 0) {
            claims->error = strdup("Invalid issuer");
            return 0;
        }
    }
    
    // Check audience
    if (expected_audience && claims->audience) {
        if (strcmp(claims->audience, expected_audience) != 0) {
            claims->error = strdup("Invalid audience");
            return 0;
        }
    }
    
    return 1;
}

// Enhanced JWT validation command
int JwtValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <jwt_string> ?-audience <aud>? ?-issuer <iss>? ?-check_expiration <bool>?");
        return TCL_ERROR;
    }
    
    const char *token = NULL;
    const char *audience = NULL;
    const char *issuer = NULL;
    int check_expiration = 1;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-token") == 0) {
            token = value;
        } else if (strcmp(option, "-audience") == 0) {
            audience = value;
        } else if (strcmp(option, "-issuer") == 0) {
            issuer = value;
        } else if (strcmp(option, "-check_expiration") == 0) {
            check_expiration = atoi(value);
        }
    }
    
    if (!token) {
        Tcl_SetResult(interp, "Missing token parameter", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse JWT manually to handle empty signature
    char *token_copy = strdup(token);
    char *header_part = NULL;
    char *payload_part = NULL;
    char *signature_part = NULL;
    
    // Find first dot
    char *first_dot = strchr(token_copy, '.');
    if (!first_dot) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    *first_dot = '\0';
    header_part = token_copy;
    
    // Find second dot
    char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    *second_dot = '\0';
    payload_part = first_dot + 1;
    
    // Signature part (may be empty)
    signature_part = second_dot + 1;
    
    if (!header_part || !payload_part) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    
    // Decode payload
    size_t payload_len;
    unsigned char *payload_data = base64url_decode(payload_part, &payload_len);
    if (!payload_data) {
        Tcl_SetResult(interp, "Failed to decode JWT payload", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    
    char *payload_str = malloc(payload_len + 1);
    memcpy(payload_str, payload_data, payload_len);
    payload_str[payload_len] = '\0';
    
    // Parse and validate claims
    JwtClaims *claims = parse_jwt_claims(payload_str);
    if (!claims) {
        Tcl_SetResult(interp, "Failed to parse JWT claims", TCL_STATIC);
        free(payload_str);
        free(payload_data);
        free(token_copy);
        return TCL_ERROR;
    }
    
    int valid = validate_jwt_claims(claims, issuer, audience, check_expiration);
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewIntObj(valid));
    
    if (claims->issuer) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issuer", -1), 
                       Tcl_NewStringObj(claims->issuer, -1));
    }
    
    if (claims->audience) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("audience", -1), 
                       Tcl_NewStringObj(claims->audience, -1));
    }
    
    if (claims->subject) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("subject", -1), 
                       Tcl_NewStringObj(claims->subject, -1));
    }
    
    if (claims->issued_at > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issued_at", -1), 
                       Tcl_NewIntObj(claims->issued_at));
    }
    
    if (claims->not_before > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("not_before", -1), 
                       Tcl_NewIntObj(claims->not_before));
    }
    
    if (claims->expiration > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expiration", -1), 
                       Tcl_NewIntObj(claims->expiration));
    }
    
    if (claims->jwt_id) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("jwt_id", -1), 
                       Tcl_NewStringObj(claims->jwt_id, -1));
    }
    
    if (claims->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(claims->error, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_jwt_claims(claims);
    free(payload_str);
    free(payload_data);
    free(token_copy);
    
    return TCL_OK;
}

// JWT claims extraction command
int JwtExtractClaimsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <jwt_string>");
        return TCL_ERROR;
    }
    
    const char *token = Tcl_GetString(objv[2]);
    
    // Parse JWT manually to handle empty signature
    char *token_copy = strdup(token);
    char *header_part = NULL;
    char *payload_part = NULL;
    char *signature_part = NULL;
    
    // Find first dot
    char *first_dot = strchr(token_copy, '.');
    if (!first_dot) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    *first_dot = '\0';
    header_part = token_copy;
    
    // Find second dot
    char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    *second_dot = '\0';
    payload_part = first_dot + 1;
    
    // Signature part (may be empty)
    signature_part = second_dot + 1;
    
    if (!header_part || !payload_part) {
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    
    // Decode payload
    size_t payload_len;
    unsigned char *payload_data = base64url_decode(payload_part, &payload_len);
    if (!payload_data) {
        Tcl_SetResult(interp, "Failed to decode JWT payload", TCL_STATIC);
        free(token_copy);
        return TCL_ERROR;
    }
    
    char *payload_str = malloc(payload_len + 1);
    memcpy(payload_str, payload_data, payload_len);
    payload_str[payload_len] = '\0';
    
    // Parse claims
    JwtClaims *claims = parse_jwt_claims(payload_str);
    if (!claims) {
        Tcl_SetResult(interp, "Failed to parse JWT claims", TCL_STATIC);
        free(payload_str);
        free(payload_data);
        free(token_copy);
        return TCL_ERROR;
    }
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (claims->issuer) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issuer", -1), 
                       Tcl_NewStringObj(claims->issuer, -1));
    }
    
    if (claims->audience) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("audience", -1), 
                       Tcl_NewStringObj(claims->audience, -1));
    }
    
    if (claims->subject) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("subject", -1), 
                       Tcl_NewStringObj(claims->subject, -1));
    }
    
    if (claims->issued_at > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issued_at", -1), 
                       Tcl_NewIntObj(claims->issued_at));
    }
    
    if (claims->not_before > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("not_before", -1), 
                       Tcl_NewIntObj(claims->not_before));
    }
    
    if (claims->expiration > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expiration", -1), 
                       Tcl_NewIntObj(claims->expiration));
    }
    
    if (claims->jwt_id) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("jwt_id", -1), 
                       Tcl_NewStringObj(claims->jwt_id, -1));
    }
    
    if (claims->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(claims->error, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_jwt_claims(claims);
    free(payload_str);
    free(payload_data);
    free(token_copy);
    
    return TCL_OK;
}

// Initialize JWT module
int Tossl_JwtInit(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::jwt::create", JwtCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwt::verify", JwtVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwt::decode", JwtDecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwt::validate", JwtValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::jwt::extract_claims", JwtExtractClaimsCmd, NULL, NULL);
    return TCL_OK;
} 