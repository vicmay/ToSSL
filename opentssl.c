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

// Helper: Convert binary to hex string
static void bin2hex(const unsigned char *in, int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; ++i) {
        out[2*i] = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

// opentssl::digest -alg <name> <data>
static int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (!rsa || !e || !BN_set_word(e, RSA_F4) || !RSA_generate_key_ex(rsa, bits, e, NULL)) {
        if (rsa) RSA_free(rsa);
        if (e) BN_free(e);
        Tcl_SetResult(interp, "OpenSSL: RSA key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    // Write private key to PEM
    BIO *priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    char *priv_pem = NULL;
    long priv_len = BIO_get_mem_data(priv, &priv_pem);
    // Write public key to PEM
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(pub, rsa);
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
    RSA_free(rsa);
    BN_free(e);
    return TCL_OK;
}

// opentssl::rsa::encrypt -pubkey <pem> <data>
static int RsaEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse public key", TCL_STATIC);
        return TCL_ERROR;
    }
    int rsa_size = RSA_size(rsa);
    unsigned char *out = (unsigned char *)ckalloc(rsa_size);
    int outlen = RSA_public_encrypt(datalen, data, out, rsa, RSA_PKCS1_OAEP_PADDING);
    if (outlen == -1) {
        RSA_free(rsa);
        BIO_free(bio);
        ckfree((char *)out);
        Tcl_SetResult(interp, "OpenSSL: RSA encryption failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, outlen));
    RSA_free(rsa);
    BIO_free(bio);
    ckfree((char *)out);
    return TCL_OK;
}

// opentssl::rsa::decrypt -privkey <pem> <ciphertext>
static int RsaDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa) {
        BIO_free(bio);
        Tcl_SetResult(interp, "OpenSSL: failed to parse private key", TCL_STATIC);
        return TCL_ERROR;
    }
    int rsa_size = RSA_size(rsa);
    unsigned char *out = (unsigned char *)ckalloc(rsa_size);
    int outlen = RSA_private_decrypt(datalen, data, out, rsa, RSA_PKCS1_OAEP_PADDING);
    if (outlen == -1) {
        RSA_free(rsa);
        BIO_free(bio);
        ckfree((char *)out);
        Tcl_SetResult(interp, "OpenSSL: RSA decryption failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, outlen));
    RSA_free(rsa);
    BIO_free(bio);
    ckfree((char *)out);
    return TCL_OK;
}

#include <openssl/x509.h>
#include <openssl/asn1.h>

// opentssl::x509::parse <pem>
static int X509ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    ASN1_TIME *notBefore = X509_get0_notBefore(cert);
    ASN1_TIME *notAfter = X509_get0_notAfter(cert);
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

// opentssl::rsa::sign -privkey <pem> -alg <digest> <data>
static int RsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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
    if (objc < 11 || objc > 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-subject dn -issuer dn -pubkey pem -privkey pem -days n [-san {dns1 dns2 ...}]");
        return TCL_ERROR;
    }
    const char *subject = NULL, *issuer = NULL, *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0, days = 0;
    Tcl_Obj *sanListObj = NULL;
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
    Tcl_CreateObjCommand(interp, "opentssl::randbytes", RandBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::encrypt", EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::decrypt", DecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::generate", RsaGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::encrypt", RsaEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::decrypt", RsaDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::parse", X509ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::sign", RsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::rsa::verify", RsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::create", X509CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "opentssl::x509::verify", X509VerifyCmd, NULL, NULL);
    Tcl_PkgProvide(interp, "opentssl", "0.1");
    return TCL_OK;
}
