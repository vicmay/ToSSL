#include <tcl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <ctype.h>
#include "tossl_pgp_error.h"
#include "tossl_pgp_crypto.h"
#include "tossl_pgp_packet.h"
#include "tossl_pgp_signature.h"

// Helper: Write a multi-byte big-endian integer
static void write_uint32(unsigned char *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

// Helper: Write a 2-byte big-endian integer
static void write_uint16(unsigned char *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

// Helper: Write a 1-byte integer
static void write_uint8(unsigned char *buf, uint8_t val) {
    buf[0] = val;
}

// Helper: Write a length-prefixed MPI (RFC 4880 §3.2)
static int write_mpi(unsigned char *buf, const BIGNUM *bn) {
    int nbits = BN_num_bits(bn);
    int nbytes = (nbits + 7) / 8;
    write_uint16(buf, nbits);
    BN_bn2bin(bn, buf + 2);
    return nbytes + 2;
}

// Helper: ASCII armor encoding (minimal, no CRC)
static char *armor_block(const unsigned char *data, int len, const char *header) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int outlen = ((len + 2) / 3) * 4 + 128;
    char *out = malloc(outlen);
    int pos = 0;
    pos += sprintf(out + pos, "-----BEGIN %s-----\n", header);
    for (int i = 0; i < len; i += 3) {
        uint32_t v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out[pos++] = b64[(v >> 18) & 0x3F];
        out[pos++] = b64[(v >> 12) & 0x3F];
        out[pos++] = (i + 1 < len) ? b64[(v >> 6) & 0x3F] : '=';
        out[pos++] = (i + 2 < len) ? b64[v & 0x3F] : '=';
        if (((i / 3 + 1) % 16) == 0) out[pos++] = '\n';
    }
    if (pos == 0 || out[pos - 1] != '\n') out[pos++] = '\n';
    pos += sprintf(out + pos, "-----END %s-----\n", header);
    out[pos] = 0;
    return out;
}

// Helper: decode ASCII armor (returns malloc'd buffer, sets *outlen)
static unsigned char *dearmor(const char *in, int *outlen) {
    const char *p = strstr(in, "-----BEGIN");
    if (!p) p = in;
    p = strchr(p, '\n');
    if (!p) return NULL;
    p++;
    char buf[4096];
    int blen = 0;
    while (*p && strncmp(p, "-----END", 9) != 0) {
        if (isalnum(*p) || *p == '+' || *p == '/' || *p == '=')
            buf[blen++] = *p;
        p++;
    }
    int len = (blen / 4) * 3;
    unsigned char *out = malloc(len);
    int i, j = 0;
    for (i = 0; i < blen; i += 4) {
        int v = 0, k;
        for (k = 0; k < 4; ++k) {
            char c = buf[i + k];
            if (c >= 'A' && c <= 'Z') v = (v << 6) | (c - 'A');
            else if (c >= 'a' && c <= 'z') v = (v << 6) | (c - 'a' + 26);
            else if (c >= '0' && c <= '9') v = (v << 6) | (c - '0' + 52);
            else if (c == '+') v = (v << 6) | 62;
            else if (c == '/') v = (v << 6) | 63;
            else if (c == '=') v = (v << 6);
        }
        out[j++] = (v >> 16) & 0xFF;
        if (buf[i + 2] != '=') out[j++] = (v >> 8) & 0xFF;
        if (buf[i + 3] != '=') out[j++] = v & 0xFF;
    }
    *outlen = j;
    return out;
}

// Main: tossl::pgp::key::generate
int PgpKeyGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int bits = 2048, armor = 0;
    const char *userid = "User <user@example.com>";
    const char *type = "rsa";
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-bits") == 0) {
            Tcl_GetIntFromObj(interp, objv[i+1], &bits);
        } else if (strcmp(opt, "-userid") == 0) {
            userid = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-armor") == 0) {
            Tcl_GetIntFromObj(interp, objv[i+1], &armor);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (strcmp(type, "rsa") != 0) {
        Tcl_SetResult(interp, "Only RSA supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
    // Generate RSA key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_PKEY_CTX_free(ctx);
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "OpenSSL: failed to get RSA", TCL_STATIC);
        return TCL_ERROR;
    }
    // Build OpenPGP v4 public key packet (RFC 4880 §5.5.2)
    unsigned char pkt[2048];
    int pos = 0;
    // Packet header: new format, tag 6 (public key)
    pkt[pos++] = 0xC0 | 6; // 0b110xxxxx, tag 6
    // Length: will fill later
    int len_pos = pos; pos += 2;
    // Version
    pkt[pos++] = 4;
    // Timestamp (now)
    uint32_t now = (uint32_t)time(NULL);
    write_uint32(pkt + pos, now); pos += 4;
    // Algorithm (1 = RSA)
    pkt[pos++] = 1;
    // n (modulus)
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);
    pos += write_mpi(pkt + pos, n);
    pos += write_mpi(pkt + pos, e);
    // Fill length
    int pktlen = pos - (len_pos + 2);
    write_uint16(pkt + len_pos, pktlen);
    // User ID packet (tag 13)
    int uid_pos = pos;
    pkt[pos++] = 0xCD; // 0b11001101, tag 13
    int uidlen = strlen(userid);
    write_uint16(pkt + pos, uidlen);
    pos += 2;
    memcpy(pkt + pos, userid, uidlen);
    pos += uidlen;
    // --- Self-signature packet (tag 2) ---
    // Canonicalize public key and user ID for signature
    // (RFC 4880 §5.2.4, §5.2.1)
    unsigned char sigbuf[2048];
    int sigpos = 0;
    // 1. Hash public key packet (without header)
    sigbuf[sigpos++] = 0x99;
    int pklen = (uid_pos - 3); // skip tag+len
    write_uint16(sigbuf + sigpos, pklen); sigpos += 2;
    memcpy(sigbuf + sigpos, pkt + 3, pklen); sigpos += pklen;
    // 2. Hash user ID packet (without header)
    sigbuf[sigpos++] = 0xB4;
    write_uint32(sigbuf + sigpos, uidlen); sigpos += 4;
    memcpy(sigbuf + sigpos, userid, uidlen); sigpos += uidlen;
    // 3. Prepare signature subpackets (minimal)
    unsigned char hashed[32];
    int hashedlen = 0;
    // Subpacket: signature creation time (type 2, 5 bytes)
    hashed[hashedlen++] = 5; // length
    hashed[hashedlen++] = 2; // type
    now = (uint32_t)time(NULL);
    write_uint32(hashed + hashedlen, now); hashedlen += 4;
    // 4. Build signature data
    unsigned char sigpkt[2048];
    int spos = 0;
    sigpkt[spos++] = 0xC2; // tag 2, new format
    int lenpos = spos; spos += 2;
    sigpkt[spos++] = 4; // version
    sigpkt[spos++] = 0x13; // type: positive certification
    sigpkt[spos++] = 1; // pubkey algo: RSA
    sigpkt[spos++] = 2; // hash: SHA1
    // Hashed subpacket length
    write_uint16(sigpkt + spos, hashedlen); spos += 2;
    memcpy(sigpkt + spos, hashed, hashedlen); spos += hashedlen;
    // Unhashed subpacket length (0)
    write_uint16(sigpkt + spos, 0); spos += 2;
    // 5. Hash for signature
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, sigbuf, sigpos);
    SHA1_Update(&sha_ctx, sigpkt + 3, spos - 3); // version..unhashed
    unsigned char trailer[6] = {4, 0xFF, 0,0,0,0};
    uint32_t trailerlen = spos - 3;
    write_uint32(trailer + 2, trailerlen);
    SHA1_Update(&sha_ctx, trailer, 6);
    SHA1_Final(hash, &sha_ctx);
    // 6. Sign hash with RSA
    unsigned char sigval[256];
    unsigned int siglen = sizeof(sigval);
    if (!RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sigval, &siglen, rsa)) {
        Tcl_SetResult(interp, "RSA_sign failed", TCL_STATIC);
        EVP_PKEY_free(pkey);
        return TCL_ERROR;
    }
    // 7. Signature MPIs (one MPI for RSA)
    unsigned char sigmpi[258];
    int mpilen = write_mpi(sigmpi, BN_bin2bn(sigval, siglen, NULL));
    // 8. Add left 2 bytes of hash
    sigpkt[spos++] = hash[0];
    sigpkt[spos++] = hash[1];
    memcpy(sigpkt + spos, sigmpi, mpilen); spos += mpilen;
    // Fill length
    int sigpktlen = spos - (lenpos + 2);
    write_uint16(sigpkt + lenpos, sigpktlen);
    // 9. Append signature packet to pkt
    memcpy(pkt + pos, sigpkt, spos); pos += spos;
    // Output (as before)
    if (armor) {
        char *arm = armor_block(pkt, pos, "PGP PUBLIC KEY BLOCK");
        Tcl_SetResult(interp, arm, TCL_VOLATILE);
        free(arm);
    } else {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(pkt, pos));
    }
    EVP_PKEY_free(pkey);
    return TCL_OK;
}

// Stub: Export an OpenPGP key
int PgpKeyExportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Usage: tossl::pgp::key::export dict ?-armor 1?
    int armor = 0;
    if (objc < 2 || objc > 4) {
        Tcl_SetResult(interp, "Usage: tossl::pgp::key::export dict ?-armor 1?", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *dict = objv[1];
    if (objc == 4) {
        const char *opt = Tcl_GetString(objv[2]);
        if (strcmp(opt, "-armor") == 0) {
            Tcl_GetIntFromObj(interp, objv[3], &armor);
        }
    }
    Tcl_Obj *typeObj, *bitsObj, *useridObj, *nObj, *eObj, *dObj, *pObj, *qObj, *uObj;
    int has_secret =
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("d", -1), &dObj) == TCL_OK && dObj &&
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("p", -1), &pObj) == TCL_OK && pObj &&
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("q", -1), &qObj) == TCL_OK && qObj &&
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("u", -1), &uObj) == TCL_OK && uObj;
    if (Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("type", -1), &typeObj) != TCL_OK || !typeObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("bits", -1), &bitsObj) != TCL_OK || !bitsObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("userid", -1), &useridObj) != TCL_OK || !useridObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("n", -1), &nObj) != TCL_OK || !nObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("e", -1), &eObj) != TCL_OK || !eObj) {
        Tcl_SetResult(interp, "Missing key fields in dict (need n/e)", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *type = Tcl_GetString(typeObj);
    int bits; Tcl_GetIntFromObj(interp, bitsObj, &bits);
    const char *userid = Tcl_GetString(useridObj);
    const char *n_hex = Tcl_GetString(nObj);
    const char *e_hex = Tcl_GetString(eObj);
    if (has_secret) {
        // Use local n2, e2 for secret key reconstruction
        BIGNUM *n2 = NULL, *e2 = NULL, *d = NULL, *p = NULL, *q = NULL, *u = NULL;
        BN_hex2bn(&n2, n_hex);
        BN_hex2bn(&e2, e_hex);
        BN_hex2bn(&d, Tcl_GetString(dObj));
        BN_hex2bn(&p, Tcl_GetString(pObj));
        BN_hex2bn(&q, Tcl_GetString(qObj));
        BN_hex2bn(&u, Tcl_GetString(uObj));
        RSA *rsa = RSA_new();
        RSA_set0_key(rsa, n2, e2, d); // n2, e2, d now owned by rsa
        RSA_set0_factors(rsa, p, q); // p, q now owned by rsa
        RSA_set0_crt_params(rsa, NULL, u, NULL); // u now owned by rsa
        // Build public key packet
        unsigned char pkt[2048];
        int pos = 0;
        pkt[pos++] = 0xC0 | 6;
        int len_pos = pos; pos += 2;
        pkt[pos++] = 4;
        uint32_t now = (uint32_t)time(NULL);
        write_uint32(pkt + pos, now); pos += 4;
        pkt[pos++] = 1;
        pos += write_mpi(pkt + pos, n2);
        pos += write_mpi(pkt + pos, e2);
        int pktlen = pos - (len_pos + 2);
        write_uint16(pkt + len_pos, pktlen);
        // User ID packet
        int uid_pos = pos;
        pkt[pos++] = 0xCD;
        int uidlen = strlen(userid);
        write_uint16(pkt + pos, uidlen); pos += 2;
        memcpy(pkt + pos, userid, uidlen); pos += uidlen;
        // --- Self-signature packet (tag 2) ---
        unsigned char sigbuf[2048];
        int sigpos = 0;
        sigbuf[sigpos++] = 0x99;
        int pklen = (uid_pos - 3);
        write_uint16(sigbuf + sigpos, pklen); sigpos += 2;
        memcpy(sigbuf + sigpos, pkt + 3, pklen); sigpos += pklen;
        sigbuf[sigpos++] = 0xB4;
        write_uint32(sigbuf + sigpos, uidlen); sigpos += 4;
        memcpy(sigbuf + sigpos, userid, uidlen); sigpos += uidlen;
        unsigned char hashed[32];
        int hashedlen = 0;
        hashed[hashedlen++] = 5;
        hashed[hashedlen++] = 2;
        now = (uint32_t)time(NULL);
        write_uint32(hashed + hashedlen, now); hashedlen += 4;
        unsigned char sigpkt[2048];
        int spos = 0;
        sigpkt[spos++] = 0xC2;
        int lenpos = spos; spos += 2;
        sigpkt[spos++] = 4;
        sigpkt[spos++] = 0x13;
        sigpkt[spos++] = 1;
        sigpkt[spos++] = 2;
        write_uint16(sigpkt + spos, hashedlen); spos += 2;
        memcpy(sigpkt + spos, hashed, hashedlen); spos += hashedlen;
        write_uint16(sigpkt + spos, 0); spos += 2;
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA_CTX sha_ctx;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, sigbuf, sigpos);
        SHA1_Update(&sha_ctx, sigpkt + 3, spos - 3);
        unsigned char trailer[6] = {4, 0xFF, 0,0,0,0};
        uint32_t trailerlen = spos - 3;
        write_uint32(trailer + 2, trailerlen);
        SHA1_Update(&sha_ctx, trailer, 6);
        SHA1_Final(hash, &sha_ctx);
        unsigned char sigval[256];
        unsigned int siglen = sizeof(sigval);
        if (!RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sigval, &siglen, rsa)) {
            Tcl_SetResult(interp, "RSA_sign failed", TCL_STATIC);
            RSA_free(rsa);
            return TCL_ERROR;
        }
        unsigned char sigmpi[258];
        int mpilen = write_mpi(sigmpi, BN_bin2bn(sigval, siglen, NULL));
        sigpkt[spos++] = hash[0];
        sigpkt[spos++] = hash[1];
        memcpy(sigpkt + spos, sigmpi, mpilen); spos += mpilen;
        int sigpktlen = spos - (lenpos + 2);
        write_uint16(sigpkt + lenpos, sigpktlen);
        memcpy(pkt + pos, sigpkt, spos); pos += spos;
        if (armor) {
            char *arm = armor_block(pkt, pos, "PGP PUBLIC KEY BLOCK");
            Tcl_SetResult(interp, arm, TCL_VOLATILE);
            free(arm);
        } else {
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(pkt, pos));
        }
        RSA_free(rsa);
        return TCL_OK;
    } else {
        // Dummy signature branch: declare and use n, e here
        BIGNUM *n = NULL, *e = NULL;
        BN_hex2bn(&n, n_hex);
        BN_hex2bn(&e, e_hex);
        // Build public key packet
        unsigned char pkt[2048];
        int pos = 0;
        pkt[pos++] = 0xC0 | 6;
        int len_pos = pos; pos += 2;
        pkt[pos++] = 4;
        uint32_t now = (uint32_t)time(NULL);
        write_uint32(pkt + pos, now); pos += 4;
        pkt[pos++] = 1;
        pos += write_mpi(pkt + pos, n);
        pos += write_mpi(pkt + pos, e);
        int pktlen = pos - (len_pos + 2);
        write_uint16(pkt + len_pos, pktlen);
        // User ID packet
        int uid_pos = pos;
        pkt[pos++] = 0xCD;
        int uidlen = strlen(userid);
        write_uint16(pkt + pos, uidlen); pos += 2;
        memcpy(pkt + pos, userid, uidlen); pos += uidlen;
        // --- Self-signature packet (tag 2) ---
        unsigned char sigpkt[2048];
        int spos = 0;
        sigpkt[spos++] = 0xC2; // tag 2, new format
        int lenpos = spos; spos += 2;
        sigpkt[spos++] = 4; // version
        sigpkt[spos++] = 0x13; // type: positive certification
        sigpkt[spos++] = 1; // pubkey algo: RSA
        sigpkt[spos++] = 2; // hash: SHA1
        // Hashed subpacket: creation time
        unsigned char hashed[32];
        int hashedlen = 0;
        hashed[hashedlen++] = 5; // length
        hashed[hashedlen++] = 2; // type
        uint32_t sig_now = (uint32_t)time(NULL);
        write_uint32(hashed + hashedlen, sig_now); hashedlen += 4;
        write_uint16(sigpkt + spos, hashedlen); spos += 2;
        memcpy(sigpkt + spos, hashed, hashedlen); spos += hashedlen;
        write_uint16(sigpkt + spos, 0); spos += 2; // unhashed subpacket length
        // Hash for signature (dummy)
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};
        sigpkt[spos++] = hash[0];
        sigpkt[spos++] = hash[1];
        // Dummy signature MPI (1 byte)
        sigpkt[spos++] = 0; sigpkt[spos++] = 1; sigpkt[spos++] = 1;
        int sigpktlen = spos - (lenpos + 2);
        write_uint16(sigpkt + lenpos, sigpktlen);
        memcpy(pkt + pos, sigpkt, spos); pos += spos;
        // Output as before
        if (armor) {
            char *arm = armor_block(pkt, pos, "PGP PUBLIC KEY BLOCK");
            Tcl_SetResult(interp, arm, TCL_VOLATILE);
            free(arm);
        } else {
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(pkt, pos));
        }
        BN_free(n); BN_free(e);
        return TCL_OK;
    }
}

// Stub: Import an OpenPGP key
int PgpKeyImportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Usage: tossl::pgp::key::import keyblock
    if (objc != 2) {
        Tcl_SetResult(interp, "Usage: tossl::pgp::key::import keyblock", TCL_STATIC);
        return TCL_ERROR;
    }
    // Use parse for now (dict-based import)
    return PgpKeyParseCmd(cd, interp, objc, objv);
}

// Stub: Parse an OpenPGP key
int PgpKeyParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_SetResult(interp, "Usage: tossl::pgp::key::parse keyblock", TCL_STATIC);
        return TCL_ERROR;
    }
    int len;
    unsigned char *buf = NULL;
    const char *in = Tcl_GetStringFromObj(objv[1], &len);
    if (strstr(in, "-----BEGIN") != NULL) {
        buf = dearmor(in, &len);
        if (!buf) {
            Tcl_SetResult(interp, "Invalid ASCII armor", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        buf = (unsigned char *)in;
    }
    int i = 0;
    int type = 0, bits = 0;
    char userid[256] = "";
    Tcl_Obj *n_hex = NULL, *e_hex = NULL;
    while (i < len) {
        if (i + 3 > len) break;
        unsigned char tag = buf[i++];
        int pktlen = (buf[i] << 8) | buf[i + 1];
        i += 2;
        if (i + pktlen > len) break;
        if ((tag & 0x3F) == 6) { // public key
            if (pktlen < 6) continue;
            int ver = buf[i++];
            i += 4; // skip time
            int algo = buf[i++];
            if (algo == 1) type = 1; // RSA
            // n (modulus)
            int nbits = (buf[i] << 8) | buf[i + 1];
            bits = nbits;
            int nbytes = (nbits + 7) / 8;
            BIGNUM *n = BN_bin2bn(buf + i + 2, nbytes, NULL);
            n_hex = Tcl_NewStringObj(BN_bn2hex(n), -1);
            i += 2 + nbytes;
            // e (exponent)
            int ebits = (buf[i] << 8) | buf[i + 1];
            int ebytes = (ebits + 7) / 8;
            BIGNUM *e = BN_bin2bn(buf + i + 2, ebytes, NULL);
            e_hex = Tcl_NewStringObj(BN_bn2hex(e), -1);
            i += 2 + ebytes;
            BN_free(n); BN_free(e);
            i += pktlen - (6 + 2 + nbytes + 2 + ebytes); // skip rest
        } else if ((tag & 0x3F) == 13) { // user ID
            if (pktlen > 255) pktlen = 255;
            int uidlen = pktlen;
            memcpy(userid, buf + i, uidlen);
            userid[uidlen] = 0;
            i += uidlen;
        } else {
            i += pktlen;
        }
    }
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj(type == 1 ? "rsa" : "unknown", -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("userid", -1), Tcl_NewStringObj(userid, -1));
    if (n_hex && e_hex) {
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("n", -1), n_hex);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("e", -1), e_hex);
    }
    Tcl_SetObjResult(interp, dict);
    if (buf != (unsigned char *)in) free(buf);
    return TCL_OK;
}

// Secret key generation (stub)
int PgpKeyGenerateSecretCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int bits = 2048, armor = 0;
    const char *userid = "User <user@example.com>";
    const char *type = "rsa";
    const char *passphrase = NULL;
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-type") == 0) {
            type = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-bits") == 0) {
            Tcl_GetIntFromObj(interp, objv[i+1], &bits);
        } else if (strcmp(opt, "-userid") == 0) {
            userid = Tcl_GetString(objv[i+1]);
        } else if (strcmp(opt, "-armor") == 0) {
            Tcl_GetIntFromObj(interp, objv[i+1], &armor);
        } else if (strcmp(opt, "-passphrase") == 0) {
            passphrase = Tcl_GetString(objv[i+1]);
        } else {
            Tcl_SetResult(interp, "Unknown option", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    if (strcmp(type, "rsa") != 0) {
        Tcl_SetResult(interp, "Only RSA supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
    // Generate RSA key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        Tcl_SetResult(interp, "OpenSSL: key generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_PKEY_CTX_free(ctx);
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "OpenSSL: failed to get RSA", TCL_STATIC);
        return TCL_ERROR;
    }
    // Build OpenPGP v4 secret key packet (RFC 4880 §5.5.3)
    unsigned char pkt[4096];
    int pos = 0;
    // Packet header: new format, tag 5 (secret key)
    pkt[pos++] = 0xC0 | 5; // 0b110xxxxx, tag 5
    int len_pos = pos; pos += 1; // Will update length later
    // Version
    pkt[pos++] = 4;
    // Timestamp (now)
    uint32_t now = (uint32_t)time(NULL);
    write_uint32(pkt + pos, now); pos += 4;
    // Algorithm (1 = RSA)
    pkt[pos++] = 1;
    // n (modulus), e (exponent)
    const BIGNUM *n, *e, *d, *p, *q, *u;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &d, &u, NULL);
    pos += write_mpi(pkt + pos, n);
    pos += write_mpi(pkt + pos, e);
    // Secret key fields: d, p, q, u
    // Secret-key encryption (RFC 4880 §5.5.3):
    int s2k_type = 0; // 0 = unencrypted, 254/255 = encrypted
    if (passphrase && strlen(passphrase) > 0) {
        s2k_type = 254; // S2K with symmetric encryption (AES-128)
        pkt[pos++] = 0x09; // Symmetric algo: AES-128
        pkt[pos++] = s2k_type;
        pkt[pos++] = 3; // S2K: iterated+salted
        // Salt (8 bytes)
        unsigned char salt[8];
        RAND_bytes(salt, 8);
        memcpy(pkt + pos, salt, 8); pos += 8;
        pkt[pos++] = 96; // S2K count (RFC 4880: 65536 iterations)
        // Derive key
        unsigned char key[16];
        // S2K: hash passphrase+salt, iterated
        PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, 8, 65536, EVP_sha1(), 16, key);
        // Encrypt secret fields (d, p, q, u)
        unsigned char sec[2048];
        int secpos = 0;
        secpos += write_mpi(sec + secpos, d);
        secpos += write_mpi(sec + secpos, p);
        secpos += write_mpi(sec + secpos, q);
        secpos += write_mpi(sec + secpos, u);
        // SHA1 checksum
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(sec, secpos, hash);
        memcpy(sec + secpos, hash, 20); secpos += 20;
        // Encrypt with AES-128-CFB (no IV)
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        int outlen = 0;
        EVP_EncryptInit_ex(ectx, EVP_aes_128_cfb128(), NULL, key, NULL);
        EVP_EncryptUpdate(ectx, pkt + pos, &outlen, sec, secpos);
        pos += outlen;
        EVP_CIPHER_CTX_free(ectx);
    } else {
        pkt[pos++] = 0; // No encryption
        // Secret fields (d, p, q, u)
        pos += write_mpi(pkt + pos, d);
        pos += write_mpi(pkt + pos, p);
        pos += write_mpi(pkt + pos, q);
        pos += write_mpi(pkt + pos, u);
        // SHA1 checksum
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(pkt + pos - (BN_num_bytes(d) + BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(u)), BN_num_bytes(d) + BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(u), hash);
        memcpy(pkt + pos, hash, 20); pos += 20;
    }
    // Fill length using new-format packet header encoding
    int pktlen = pos - (len_pos + 1);
    if (pktlen < 192) {
        pkt[len_pos] = pktlen;
    } else if (pktlen < 8384) {
        pkt[len_pos] = ((pktlen - 192) >> 8) + 192;
        // Shift everything after len_pos+1 by 1 byte
        memmove(pkt + len_pos + 2, pkt + len_pos + 1, pos - (len_pos + 1));
        pkt[len_pos + 1] = (pktlen - 192) & 0xFF;
        pos++;
    } else {
        pkt[len_pos] = 0xFF;
        // Shift everything after len_pos+1 by 4 bytes
        memmove(pkt + len_pos + 5, pkt + len_pos + 1, pos - (len_pos + 1));
        write_uint32(pkt + len_pos + 1, pktlen);
        pos += 4;
    }
    // User ID packet (tag 13)
    int uid_pos = pos;
    pkt[pos++] = 0xCD; // 0b11001101, tag 13
    int uidlen = strlen(userid);
    write_uint16(pkt + pos, uidlen); pos += 2;
    memcpy(pkt + pos, userid, uidlen); pos += uidlen;
    // TODO: Add self-signature packet (see public key code)
    // Output
    if (armor) {
        char *arm = armor_block(pkt, pos, "PGP PRIVATE KEY BLOCK");
        Tcl_SetResult(interp, arm, TCL_VOLATILE);
        free(arm);
    } else {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(pkt, pos));
    }
    EVP_PKEY_free(pkey);
    return TCL_OK;
}
// Secret key import (stub)
int PgpKeyImportSecretCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Usage: tossl::pgp::key::import_secret keyblock ?-passphrase pw?
    const char *passphrase = NULL;
    if (objc < 2 || objc > 4) {
        Tcl_SetResult(interp, "Usage: tossl::pgp::key::import_secret keyblock ?-passphrase pw?", TCL_STATIC);
        return TCL_ERROR;
    }
    if (objc == 4) {
        const char *opt = Tcl_GetString(objv[2]);
        if (strcmp(opt, "-passphrase") == 0) {
            passphrase = Tcl_GetString(objv[3]);
        }
    }
    int len;
    unsigned char *buf = NULL;
    const char *in = Tcl_GetStringFromObj(objv[1], &len);
    if (strstr(in, "-----BEGIN") != NULL) {
        buf = dearmor(in, &len);
        if (!buf) {
            Tcl_SetResult(interp, "Invalid ASCII armor", TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        buf = (unsigned char *)in;
    }
    int i = 0;
    Tcl_Obj *dict = Tcl_NewDictObj();
    int type = 0, bits = 0;
    char userid[256] = "";
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *u = NULL;
    while (i < len) {
        if (i + 3 > len) break;
        unsigned char tag = buf[i++];
        int pktlen = (buf[i] << 8) | buf[i + 1];
        i += 2;
        if (i + pktlen > len) break;
        if ((tag & 0x3F) == 5) { // secret key
            int ver = buf[i++];
            i += 4; // skip time
            int algo = buf[i++];
            if (algo == 1) type = 1; // RSA
            // n (modulus)
            int nbits = (buf[i] << 8) | buf[i + 1];
            bits = nbits;
            int nbytes = (nbits + 7) / 8;
            n = BN_bin2bn(buf + i + 2, nbytes, NULL);
            i += 2 + nbytes;
            // e (exponent)
            int ebits = (buf[i] << 8) | buf[i + 1];
            int ebytes = (ebits + 7) / 8;
            e = BN_bin2bn(buf + i + 2, ebytes, NULL);
            i += 2 + ebytes;
            // Secret key encryption type
            int enc = buf[i++];
            if (enc == 0) {
                // Unencrypted: d, p, q, u
                int dbits = (buf[i] << 8) | buf[i + 1];
                int dbytes = (dbits + 7) / 8;
                d = BN_bin2bn(buf + i + 2, dbytes, NULL);
                i += 2 + dbytes;
                int pbits = (buf[i] << 8) | buf[i + 1];
                int pbytes = (pbits + 7) / 8;
                p = BN_bin2bn(buf + i + 2, pbytes, NULL);
                i += 2 + pbytes;
                int qbits = (buf[i] << 8) | buf[i + 1];
                int qbytes = (qbits + 7) / 8;
                q = BN_bin2bn(buf + i + 2, qbytes, NULL);
                i += 2 + qbytes;
                int ubits = (buf[i] << 8) | (buf[i + 1]);
                int ubytes = (ubits + 7) / 8;
                u = BN_bin2bn(buf + i + 2, ubytes, NULL);
                i += 2 + ubytes;
                i += 20; // skip SHA1 checksum
            } else {
                // Encrypted: parse S2K, decrypt
                int symalg = enc;
                int s2k_type = buf[i++];
                int s2k_mode = buf[i++];
                unsigned char salt[8];
                memcpy(salt, buf + i, 8); i += 8;
                int s2k_count = buf[i++];
                int enclen = pktlen - (i - 3);
                unsigned char *encsec = buf + i;
                unsigned char key[16];
                if (!passphrase) {
                    Tcl_SetResult(interp, "Passphrase required for encrypted secret key", TCL_STATIC);
                    if (buf != (unsigned char *)in) free(buf);
                    return TCL_ERROR;
                }
                PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, 8, 65536, EVP_sha1(), 16, key);
                unsigned char sec[2048];
                int seclen = enclen;
                EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
                int outlen = 0;
                EVP_DecryptInit_ex(ectx, EVP_aes_128_cfb128(), NULL, key, NULL);
                EVP_DecryptUpdate(ectx, sec, &outlen, encsec, enclen);
                EVP_CIPHER_CTX_free(ectx);
                int si = 0;
                int dbits = (sec[si] << 8) | sec[si + 1];
                int dbytes = (dbits + 7) / 8;
                d = BN_bin2bn(sec + si + 2, dbytes, NULL);
                si += 2 + dbytes;
                int pbits = (sec[si] << 8) | sec[si + 1];
                int pbytes = (pbits + 7) / 8;
                p = BN_bin2bn(sec + si + 2, pbytes, NULL);
                si += 2 + pbytes;
                int qbits = (sec[si] << 8) | sec[si + 1];
                int qbytes = (qbits + 7) / 8;
                q = BN_bin2bn(sec + si + 2, qbytes, NULL);
                si += 2 + qbytes;
                int ubits = (sec[si] << 8) | sec[si + 1];
                int ubytes = (ubits + 7) / 8;
                u = BN_bin2bn(sec + si + 2, ubytes, NULL);
                si += 2 + ubytes;
                // skip SHA1 checksum
            }
        } else if ((tag & 0x3F) == 13) { // user ID
            if (pktlen > 255) pktlen = 255;
            int uidlen = pktlen;
            memcpy(userid, buf + i, uidlen);
            userid[uidlen] = 0;
            i += uidlen;
        } else {
            i += pktlen;
        }
    }
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewStringObj(type == 1 ? "rsa" : "unknown", -1));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("bits", -1), Tcl_NewIntObj(bits));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("userid", -1), Tcl_NewStringObj(userid, -1));
    if (n && e && d && p && q && u) {
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("n", -1), Tcl_NewStringObj(BN_bn2hex(n), -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("e", -1), Tcl_NewStringObj(BN_bn2hex(e), -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("d", -1), Tcl_NewStringObj(BN_bn2hex(d), -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("p", -1), Tcl_NewStringObj(BN_bn2hex(p), -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("q", -1), Tcl_NewStringObj(BN_bn2hex(q), -1));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("u", -1), Tcl_NewStringObj(BN_bn2hex(u), -1));
    }
    Tcl_SetObjResult(interp, dict);
    if (n) BN_free(n); if (e) BN_free(e); if (d) BN_free(d); if (p) BN_free(p); if (q) BN_free(q); if (u) BN_free(u);
    if (buf != (unsigned char *)in) free(buf);
    return TCL_OK;
}
// Secret key export (stub)
int PgpKeyExportSecretCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Usage: tossl::pgp::key::export_secret dict ?-armor 1? ?-passphrase pw?
    int armor = 0;
    const char *passphrase = NULL;
    if (objc < 2 || objc > 6) {
        Tcl_SetResult(interp, "Usage: tossl::pgp::key::export_secret dict ?-armor 1? ?-passphrase pw?", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_Obj *dict = objv[1];
    for (int i = 2; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-armor") == 0) {
            Tcl_GetIntFromObj(interp, objv[i+1], &armor);
        } else if (strcmp(opt, "-passphrase") == 0) {
            passphrase = Tcl_GetString(objv[i+1]);
        }
    }
    Tcl_Obj *typeObj, *bitsObj, *useridObj, *nObj, *eObj, *dObj, *pObj, *qObj, *uObj;
    if (Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("type", -1), &typeObj) != TCL_OK || !typeObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("bits", -1), &bitsObj) != TCL_OK || !bitsObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("userid", -1), &useridObj) != TCL_OK || !useridObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("n", -1), &nObj) != TCL_OK || !nObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("e", -1), &eObj) != TCL_OK || !eObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("d", -1), &dObj) != TCL_OK || !dObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("p", -1), &pObj) != TCL_OK || !pObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("q", -1), &qObj) != TCL_OK || !qObj ||
        Tcl_DictObjGet(interp, dict, Tcl_NewStringObj("u", -1), &uObj) != TCL_OK || !uObj) {
        Tcl_SetResult(interp, "Missing key fields in dict (need n/e/d/p/q/u)", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *type = Tcl_GetString(typeObj);
    int bits; Tcl_GetIntFromObj(interp, bitsObj, &bits);
    const char *userid = Tcl_GetString(useridObj);
    const char *n_hex = Tcl_GetString(nObj);
    const char *e_hex = Tcl_GetString(eObj);
    const char *d_hex = Tcl_GetString(dObj);
    const char *p_hex = Tcl_GetString(pObj);
    const char *q_hex = Tcl_GetString(qObj);
    const char *u_hex = Tcl_GetString(uObj);
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *u = NULL;
    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&q, q_hex);
    BN_hex2bn(&u, u_hex);
    unsigned char pkt[4096];
    int pos = 0;
    pkt[pos++] = 0xC0 | 5;
    int len_pos = pos; pos += 2;
    pkt[pos++] = 4;
    uint32_t now = (uint32_t)time(NULL);
    write_uint32(pkt + pos, now); pos += 4;
    pkt[pos++] = 1;
    pos += write_mpi(pkt + pos, n);
    pos += write_mpi(pkt + pos, e);
    int s2k_type = 0;
    if (passphrase && strlen(passphrase) > 0) {
        s2k_type = 254;
        pkt[pos++] = 0x09;
        pkt[pos++] = s2k_type;
        pkt[pos++] = 3;
        unsigned char salt[8];
        RAND_bytes(salt, 8);
        memcpy(pkt + pos, salt, 8); pos += 8;
        pkt[pos++] = 96;
        unsigned char key[16];
        PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, 8, 65536, EVP_sha1(), 16, key);
        unsigned char sec[2048];
        int secpos = 0;
        secpos += write_mpi(sec + secpos, d);
        secpos += write_mpi(sec + secpos, p);
        secpos += write_mpi(sec + secpos, q);
        secpos += write_mpi(sec + secpos, u);
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(sec, secpos, hash);
        memcpy(sec + secpos, hash, 20); secpos += 20;
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        int outlen = 0;
        EVP_EncryptInit_ex(ectx, EVP_aes_128_cfb128(), NULL, key, NULL);
        EVP_EncryptUpdate(ectx, pkt + pos, &outlen, sec, secpos);
        pos += outlen;
        EVP_CIPHER_CTX_free(ectx);
    } else {
        pkt[pos++] = 0;
        pos += write_mpi(pkt + pos, d);
        pos += write_mpi(pkt + pos, p);
        pos += write_mpi(pkt + pos, q);
        pos += write_mpi(pkt + pos, u);
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(pkt + pos - (BN_num_bytes(d) + BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(u)), BN_num_bytes(d) + BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(u), hash);
        memcpy(pkt + pos, hash, 20); pos += 20;
    }
    int pktlen = pos - (len_pos + 2);
    write_uint16(pkt + len_pos, pktlen);
    int uid_pos = pos;
    pkt[pos++] = 0xCD;
    int uidlen = strlen(userid);
    write_uint16(pkt + pos, uidlen); pos += 2;
    memcpy(pkt + pos, userid, uidlen); pos += uidlen;
    if (armor) {
        char *arm = armor_block(pkt, pos, "PGP PRIVATE KEY BLOCK");
        Tcl_SetResult(interp, arm, TCL_VOLATILE);
        free(arm);
    } else {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(pkt, pos));
    }
    BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q); BN_free(u);
    return TCL_OK;
}

// RFC 4880 OpenPGP Message Format Support
// Note: Packet types, signature types, and compression algorithms are now defined in header files

// Forward declarations
static int parse_signature_packet(Tcl_Interp *interp, const unsigned char *data, int datalen, Tcl_Obj **result);

// Helper: Parse OpenPGP packet header
static int parse_packet_header(const unsigned char *data, int datalen, int *tag, int *len, int *consumed) {
    if (datalen < 2) return 0;
    int new_format = (data[0] & 0xC0) == 0xC0;
    *consumed = 1;
    if (new_format) {
        *tag = data[0] & 0x3F;
        unsigned char first_len = data[1];
        if (first_len < 192) {
            *len = first_len;
            *consumed = 2;
        } else if (first_len >= 192 && first_len <= 223) {
            if (datalen < 3) return 0;
            int val = ((first_len - 192) << 8) + (unsigned char)data[2] + 192;
            *len = val;
            *consumed = 3;
        } else if (first_len == 255) {
            if (datalen < 6) return 0;
            *len = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
            *consumed = 6;
        } else {
            // Partial body lengths not supported
            return 0;
        }
    } else {
        *tag = (data[0] >> 2) & 0x0F;
        int len_type = data[0] & 0x03;
        if (len_type == 0) {
            if (datalen < 2) return 0;
            *len = data[1];
            *consumed = 2;
        } else if (len_type == 1) {
            if (datalen < 3) return 0;
            *len = (data[1] << 8) | data[2];
            *consumed = 3;
        } else if (len_type == 2) {
            if (datalen < 5) return 0;
            *len = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
            *consumed = 5;
        } else {
            return 0;
        }
    }
    fprintf(stderr, "parse_packet_header: tag=%d len=%d consumed=%d\n", *tag, *len, *consumed);
    return 1;
}

// Helper: Create OpenPGP packet header
static int create_packet_header(unsigned char *buf, int tag, int len) {
    int pos = 0;
    buf[pos++] = 0xC0 | tag;
    if (len < 192) {
        buf[pos++] = len;
    } else if (len < 8384) {
        int val = len - 192;
        buf[pos++] = (val / 256) + 192;
        buf[pos++] = val % 256;
    } else {
        buf[pos++] = 0xFF;
        buf[pos++] = (len >> 24) & 0xFF;
        buf[pos++] = (len >> 16) & 0xFF;
        buf[pos++] = (len >> 8) & 0xFF;
        buf[pos++] = len & 0xFF;
    }
    return pos;
}

// Helper: Parse literal data packet (RFC 4880 §5.9)
static int parse_literal_data(Tcl_Interp *interp, const unsigned char *data, int datalen, Tcl_Obj **result) {
    if (datalen < 4) return 0;
    
    int format = data[0];
    int filename_len = data[1];
    int filename_pos = 2;
    
    if (filename_len > 0) {
        if (datalen < filename_pos + filename_len + 4) return 0;
        filename_pos += filename_len;
    }
    
    // Parse timestamp (4 bytes)
    uint32_t timestamp = (data[filename_pos] << 24) | (data[filename_pos + 1] << 16) |
                        (data[filename_pos + 2] << 8) | data[filename_pos + 3];
    int data_pos = filename_pos + 4;
    
    // Create result dict
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_Obj *format_obj = Tcl_NewIntObj(format);
    Tcl_Obj *timestamp_obj = Tcl_NewIntObj(timestamp);
    Tcl_Obj *data_obj = Tcl_NewByteArrayObj(data + data_pos, datalen - data_pos);
    
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("format", -1), format_obj);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("timestamp", -1), timestamp_obj);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("data", -1), data_obj);
    
    if (filename_len > 0) {
        Tcl_Obj *filename_obj = Tcl_NewStringObj((char*)data + 2, filename_len);
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("filename", -1), filename_obj);
    }
    
    *result = dict;
    return 1;
}

// Helper: Create literal data packet (RFC 4880 §5.9)
static int create_literal_data(unsigned char *buf, const unsigned char *data, int datalen, 
                              const char *filename, int format) {
    int pos = 0;
    
    // Packet header
    pos += create_packet_header(buf, PGP_PKT_LITERAL, 0); // Will update length later
    int len_pos = pos - 1;
    
    // Format
    buf[pos++] = format;
    
    // Filename
    int filename_len = filename ? strlen(filename) : 0;
    buf[pos++] = filename_len;
    if (filename_len > 0) {
        memcpy(buf + pos, filename, filename_len);
        pos += filename_len;
    }
    
    // Timestamp (4 bytes)
    uint32_t timestamp = (uint32_t)time(NULL);
    write_uint32(buf + pos, timestamp);
    pos += 4;
    
    // Data
    memcpy(buf + pos, data, datalen);
    pos += datalen;
    
    // Update packet length
    int packet_len = pos - (len_pos + 1);
    if (packet_len < 192) {
        buf[len_pos] = packet_len;
    } else if (packet_len < 8384) {
        buf[len_pos] = ((packet_len - 192) >> 8) + 192;
        buf[len_pos + 1] = (packet_len - 192) & 0xFF;
    } else {
        buf[len_pos] = 0xFF;
        write_uint32(buf + len_pos + 1, packet_len);
    }
    
    return pos;
}

// Helper: Parse compressed data packet (RFC 4880 §5.6)
static int parse_compressed_data(Tcl_Interp *interp, const unsigned char *data, int datalen, Tcl_Obj **result) {
    if (datalen < 1) return 0;
    
    int algorithm = data[0];
    int data_pos = 1;
    
    // Create result dict
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_Obj *algorithm_obj = Tcl_NewIntObj(algorithm);
    Tcl_Obj *data_obj = Tcl_NewByteArrayObj(data + data_pos, datalen - data_pos);
    
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("algorithm", -1), algorithm_obj);
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("data", -1), data_obj);
    
    *result = dict;
    return 1;
}

// Helper: Create compressed data packet (RFC 4880 §5.6)
static int create_compressed_data(unsigned char *buf, const unsigned char *data, int datalen, int algorithm) {
    int pos = 0;
    
    // Packet header
    pos += create_packet_header(buf, PGP_PKT_COMPRESSED, 0); // Will update length later
    int len_pos = pos - 1;
    
    // Algorithm
    buf[pos++] = algorithm;
    
    // Compressed data (for now, just copy data - compression will be added later)
    memcpy(buf + pos, data, datalen);
    pos += datalen;
    
    // Update packet length
    int packet_len = pos - (len_pos + 1);
    if (packet_len < 192) {
        buf[len_pos] = packet_len;
    } else if (packet_len < 8384) {
        buf[len_pos] = ((packet_len - 192) >> 8) + 192;
        buf[len_pos + 1] = (packet_len - 192) & 0xFF;
    } else {
        buf[len_pos] = 0xFF;
        write_uint32(buf + len_pos + 1, packet_len);
    }
    
    return pos;
}

// Main: tossl::pgp::message::parse
int PgpMessageParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "message_data");
        return TCL_ERROR;
    }
    
    int datalen;
    const unsigned char *data = Tcl_GetByteArrayFromObj(objv[1], &datalen);
    
    Tcl_Obj *packets = Tcl_NewListObj(0, NULL);
    int pos = 0;
    
    while (pos < datalen) {
        int tag, len, consumed;
        if (!parse_packet_header(data + pos, datalen - pos, &tag, &len, &consumed)) {
            Tcl_SetResult(interp, "Invalid packet header", TCL_STATIC);
            return TCL_ERROR;
        }
        
        pos += consumed;
        if (pos + len > datalen) {
            Tcl_SetResult(interp, "Packet data truncated", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // Parse packet based on tag
        Tcl_Obj *packet_dict = Tcl_NewDictObj();
        Tcl_Obj *tag_obj = Tcl_NewIntObj(tag);
        Tcl_DictObjPut(interp, packet_dict, Tcl_NewStringObj("tag", -1), tag_obj);
        
        Tcl_Obj *packet_data = NULL;
        int parse_result = 0;
        
        switch (tag) {
            case PGP_PKT_LITERAL:
                parse_result = parse_literal_data(interp, data + pos, len, &packet_data);
                break;
            case PGP_PKT_COMPRESSED:
                parse_result = parse_compressed_data(interp, data + pos, len, &packet_data);
                break;
            case PGP_PKT_SIGNATURE:
                parse_result = parse_signature_packet(interp, data + pos, len, &packet_data);
                break;
            default:
                // For unknown packets, just store raw data
                packet_data = Tcl_NewByteArrayObj(data + pos, len);
                parse_result = 1;
                break;
        }
        
        if (!parse_result) {
            Tcl_SetResult(interp, "Failed to parse packet", TCL_STATIC);
            return TCL_ERROR;
        }
        
        Tcl_DictObjPut(interp, packet_dict, Tcl_NewStringObj("data", -1), packet_data);
        Tcl_ListObjAppendElement(interp, packets, packet_dict);
        
        pos += len;
    }
    
    Tcl_SetObjResult(interp, packets);
    return TCL_OK;
}

// Main: tossl::pgp::message::create_literal
int PgpMessageCreateLiteralCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3 || objc > 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "data ?filename? ?format?");
        return TCL_ERROR;
    }
    
    int datalen;
    const unsigned char *data = Tcl_GetByteArrayFromObj(objv[1], &datalen);
    
    const char *filename = NULL;
    int format = 0x62; // 'b' for binary
    
    if (objc > 3) {
        filename = Tcl_GetString(objv[2]);
    }
    if (objc > 4) {
        const char *format_str = Tcl_GetString(objv[3]);
        if (strlen(format_str) == 1) {
            format = format_str[0];
        }
    }
    
    unsigned char *buf = malloc(datalen + 1024); // Extra space for headers
    int len = create_literal_data(buf, data, datalen, filename, format);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(buf, len);
    free(buf);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Main: tossl::pgp::message::create_compressed
int PgpMessageCreateCompressedCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "data algorithm");
        return TCL_ERROR;
    }
    
    int datalen;
    const unsigned char *data = Tcl_GetByteArrayFromObj(objv[1], &datalen);
    
    int algorithm;
    if (Tcl_GetIntFromObj(interp, objv[2], &algorithm) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // For now, only support uncompressed
    if (algorithm != 0) { // PGP_COMP_UNCOMPRESSED
        Tcl_SetResult(interp, "Only uncompressed algorithm supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
    
    unsigned char *buf = malloc(datalen + 1024); // Extra space for headers
    int len = create_compressed_data(buf, data, datalen, algorithm);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(buf, len);
    free(buf);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Helper: Parse OpenPGP signature packet (RFC 4880 §5.2)
static int parse_signature_packet(Tcl_Interp *interp, const unsigned char *data, int datalen, Tcl_Obj **result) {
    if (datalen < 4) return 0;
    
    int pos = 0;
    int version = data[pos++];
    int sig_type = data[pos++];
    int pubkey_algo = data[pos++];
    int hash_algo = data[pos++];
    
    if (version != 3 && version != 4) {
        Tcl_SetResult(interp, "Unsupported signature version", TCL_STATIC);
        return 0;
    }
    
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("version", -1), Tcl_NewIntObj(version));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("type", -1), Tcl_NewIntObj(sig_type));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("pubkey_algo", -1), Tcl_NewIntObj(pubkey_algo));
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("hash_algo", -1), Tcl_NewIntObj(hash_algo));
    
    if (version == 3) {
        // V3 signature: timestamp, keyid, pubkey_algo, hash_algo, signature
        if (datalen < pos + 8) return 0;
        uint32_t timestamp = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        uint64_t keyid = 0;
        for (int i = 0; i < 8; i++) {
            keyid = (keyid << 8) | data[pos++];
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("timestamp", -1), Tcl_NewIntObj(timestamp));
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("keyid", -1), Tcl_NewWideIntObj(keyid));
    } else {
        // V4 signature: hashed subpackets, unhashed subpackets, hash, signature
        if (datalen < pos + 4) return 0;
        uint16_t hashed_len = (data[pos] << 8) | data[pos+1];
        pos += 2;
        if (pos + hashed_len > datalen) return 0;
        
        // Parse hashed subpackets
        Tcl_Obj *hashed_subpackets = Tcl_NewListObj(0, NULL);
        int hashed_pos = pos;
        int hashed_end = pos + hashed_len;
        while (hashed_pos < hashed_end) {
            if (hashed_pos + 1 > hashed_end) break;
            int subpkt_len = data[hashed_pos++];
            if (hashed_pos + subpkt_len > hashed_end) break;
            int subpkt_type = data[hashed_pos++];
            subpkt_len--;
            
            Tcl_Obj *subpkt = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, subpkt, Tcl_NewStringObj("type", -1), Tcl_NewIntObj(subpkt_type));
            Tcl_DictObjPut(interp, subpkt, Tcl_NewStringObj("data", -1), 
                           Tcl_NewByteArrayObj(data + hashed_pos, subpkt_len));
            Tcl_ListObjAppendElement(interp, hashed_subpackets, subpkt);
            hashed_pos += subpkt_len;
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("hashed_subpackets", -1), hashed_subpackets);
        pos += hashed_len;
        
        if (pos + 2 > datalen) return 0;
        uint16_t unhashed_len = (data[pos] << 8) | data[pos+1];
        pos += 2;
        if (pos + unhashed_len > datalen) return 0;
        
        // Parse unhashed subpackets (similar to hashed)
        Tcl_Obj *unhashed_subpackets = Tcl_NewListObj(0, NULL);
        int unhashed_pos = pos;
        int unhashed_end = pos + unhashed_len;
        while (unhashed_pos < unhashed_end) {
            if (unhashed_pos + 1 > unhashed_end) break;
            int subpkt_len = data[unhashed_pos++];
            if (unhashed_pos + subpkt_len > unhashed_end) break;
            int subpkt_type = data[unhashed_pos++];
            subpkt_len--;
            
            Tcl_Obj *subpkt = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, subpkt, Tcl_NewStringObj("type", -1), Tcl_NewIntObj(subpkt_type));
            Tcl_DictObjPut(interp, subpkt, Tcl_NewStringObj("data", -1), 
                           Tcl_NewByteArrayObj(data + unhashed_pos, subpkt_len));
            Tcl_ListObjAppendElement(interp, unhashed_subpackets, subpkt);
            unhashed_pos += subpkt_len;
        }
        Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("unhashed_subpackets", -1), unhashed_subpackets);
        pos += unhashed_len;
    }
    
    // Hash prefix (2 bytes)
    if (pos + 2 > datalen) return 0;
    unsigned char hash_prefix[2] = {data[pos], data[pos+1]};
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("hash_prefix", -1), 
                   Tcl_NewByteArrayObj(hash_prefix, 2));
    pos += 2;
    
    // Signature MPIs
    Tcl_Obj *signature_mpis = Tcl_NewListObj(0, NULL);
    while (pos < datalen) {
        if (pos + 2 > datalen) break;
        uint16_t mpi_len = (data[pos] << 8) | data[pos+1];
        pos += 2;
        if (pos + mpi_len > datalen) break;
        
        Tcl_ListObjAppendElement(interp, signature_mpis, 
                                Tcl_NewByteArrayObj(data + pos, mpi_len));
        pos += mpi_len;
    }
    Tcl_DictObjPut(interp, dict, Tcl_NewStringObj("signature_mpis", -1), signature_mpis);
    
    *result = dict;
    return 1;
}

// Helper: Create OpenPGP signature packet (RFC 4880 §5.2)
static int create_signature_packet(unsigned char *buf, int sig_type, int pubkey_algo, int hash_algo,
                                 const unsigned char *hashed_data, int hashed_len,
                                 const unsigned char *signature_mpi, int mpi_len,
                                 const unsigned char *hash_prefix) {
    // Write body to temp buffer
    unsigned char body[2048];
    int pos = 0;
    body[pos++] = 4; // version
    body[pos++] = sig_type;
    body[pos++] = pubkey_algo;
    body[pos++] = hash_algo;
    // Hashed subpackets (minimal: creation time)
    unsigned char hashed_subpackets[32];
    int hashed_subpkt_len = 0;
    hashed_subpackets[hashed_subpkt_len++] = 5; // length
    hashed_subpackets[hashed_subpkt_len++] = 2; // type: signature creation time
    uint32_t now = (uint32_t)time(NULL);
    write_uint32(hashed_subpackets + hashed_subpkt_len, now);
    hashed_subpkt_len += 4;
    write_uint16(body + pos, hashed_subpkt_len);
    pos += 2;
    memcpy(body + pos, hashed_subpackets, hashed_subpkt_len);
    pos += hashed_subpkt_len;
    // Unhashed subpackets (empty)
    write_uint16(body + pos, 0);
    pos += 2;
    // Hash prefix
    if (hash_prefix) {
        body[pos++] = hash_prefix[0];
        body[pos++] = hash_prefix[1];
    } else {
        body[pos++] = 0;
        body[pos++] = 0;
    }
    // Signature MPI
    write_uint16(body + pos, mpi_len);
    pos += 2;
    memcpy(body + pos, signature_mpi, mpi_len);
    pos += mpi_len;
    int body_len = pos;
    // Write header
    int header_len = create_packet_header(buf, PGP_PKT_SIGNATURE, body_len);
    // Copy body after header
    memcpy(buf + header_len, body, body_len);
    // Debug: print header and body info
    fprintf(stderr, "create_signature_packet: header_len=%d body_len=%d\n", header_len, body_len); fflush(stderr);
    fprintf(stderr, "create_signature_packet: header bytes: ");
    for (int i = 0; i < header_len; ++i) fprintf(stderr, "%02x ", buf[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "create_signature_packet: body starts at pos=%d\n", header_len); fflush(stderr);
    fprintf(stderr, "create_signature_packet: first 4 body bytes: %02x %02x %02x %02x\n", buf[header_len], buf[header_len+1], buf[header_len+2], buf[header_len+3]);
    return header_len + body_len;
}

// Helper: Extract private key components from PGP key
static int extract_pgp_private_key(const unsigned char *pgp_data, int pgp_len, 
                                  BIGNUM **n, BIGNUM **e, BIGNUM **d, BIGNUM **p, BIGNUM **q, BIGNUM **u) {
    int pos = 0;
    int tag, len, consumed;
    if (!parse_packet_header(pgp_data, pgp_len, &tag, &len, &consumed)) {
        fprintf(stderr, "extract_pgp_private_key: failed to parse packet header\n"); fflush(stderr);
        return 0;
    }
    fprintf(stderr, "extract_pgp_private_key: tag=%d len=%d consumed=%d\n", tag, len, consumed); fflush(stderr);
    if (tag != 5) { // Secret key packet
        fprintf(stderr, "extract_pgp_private_key: not a secret key packet (tag=%d)\n", tag); fflush(stderr);
        return 0;
    }
    pos += consumed;
    if (pos + len > pgp_len) {
        fprintf(stderr, "extract_pgp_private_key: pos+len=%d > pgp_len=%d\n", pos+len, pgp_len); fflush(stderr);
        return 0;
    }
    int version = pgp_data[pos++];
    fprintf(stderr, "extract_pgp_private_key: version=%d\n", version); fflush(stderr);
    if (version != 4) {
        fprintf(stderr, "extract_pgp_private_key: unsupported version %d\n", version); fflush(stderr);
        return 0;
    }
    pos += 4; // Timestamp
    int algo = pgp_data[pos++];
    fprintf(stderr, "extract_pgp_private_key: algo=%d\n", algo); fflush(stderr);
    if (algo != 1) {
        fprintf(stderr, "extract_pgp_private_key: unsupported algo %d\n", algo); fflush(stderr);
        return 0;
    }
    int mpi_pos = pos;
    // n (modulus)
    if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: n field truncated\n"); fflush(stderr); return 0; }
    uint16_t n_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
    int n_len = (n_bits + 7) / 8;
    mpi_pos += 2;
    if (mpi_pos + n_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: n_len=%d truncated\n", n_len); fflush(stderr); return 0; }
    *n = BN_bin2bn(pgp_data + mpi_pos, n_len, NULL);
    fprintf(stderr, "extract_pgp_private_key: n_bits=%d n_len=%d\n", n_bits, n_len); fflush(stderr);
    mpi_pos += n_len;
    // e (exponent)
    if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: e field truncated\n"); fflush(stderr); return 0; }
    uint16_t e_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
    int e_len = (e_bits + 7) / 8;
    mpi_pos += 2;
    if (mpi_pos + e_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: e_len=%d truncated\n", e_len); fflush(stderr); return 0; }
    *e = BN_bin2bn(pgp_data + mpi_pos, e_len, NULL);
    fprintf(stderr, "extract_pgp_private_key: e_bits=%d e_len=%d\n", e_bits, e_len); fflush(stderr);
    mpi_pos += e_len;
    int s2k_type = pgp_data[mpi_pos++];
    fprintf(stderr, "extract_pgp_private_key: s2k_type=%d\n", s2k_type); fflush(stderr);
    if (s2k_type == 0) {
        // d (private exponent)
        if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: d field truncated\n"); fflush(stderr); return 0; }
        uint16_t d_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
        int d_len = (d_bits + 7) / 8;
        mpi_pos += 2;
        if (mpi_pos + d_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: d_len=%d truncated\n", d_len); fflush(stderr); return 0; }
        *d = BN_bin2bn(pgp_data + mpi_pos, d_len, NULL);
        fprintf(stderr, "extract_pgp_private_key: d_bits=%d d_len=%d\n", d_bits, d_len); fflush(stderr);
        mpi_pos += d_len;
        // p (prime 1)
        if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: p field truncated\n"); fflush(stderr); return 0; }
        uint16_t p_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
        int p_len = (p_bits + 7) / 8;
        mpi_pos += 2;
        if (mpi_pos + p_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: p_len=%d truncated\n", p_len); fflush(stderr); return 0; }
        *p = BN_bin2bn(pgp_data + mpi_pos, p_len, NULL);
        fprintf(stderr, "extract_pgp_private_key: p_bits=%d p_len=%d\n", p_bits, p_len); fflush(stderr);
        mpi_pos += p_len;
        // q (prime 2)
        if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: q field truncated\n"); fflush(stderr); return 0; }
        uint16_t q_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
        int q_len = (q_bits + 7) / 8;
        mpi_pos += 2;
        if (mpi_pos + q_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: q_len=%d truncated\n", q_len); fflush(stderr); return 0; }
        *q = BN_bin2bn(pgp_data + mpi_pos, q_len, NULL);
        fprintf(stderr, "extract_pgp_private_key: q_bits=%d q_len=%d\n", q_bits, q_len); fflush(stderr);
        mpi_pos += q_len;
        // u (CRT coefficient)
        if (mpi_pos + 2 > pgp_len) { fprintf(stderr, "extract_pgp_private_key: u field truncated\n"); fflush(stderr); return 0; }
        uint16_t u_bits = (pgp_data[mpi_pos] << 8) | pgp_data[mpi_pos + 1];
        int u_len = (u_bits + 7) / 8;
        mpi_pos += 2;
        if (mpi_pos + u_len > pgp_len) { fprintf(stderr, "extract_pgp_private_key: u_len=%d truncated\n", u_len); fflush(stderr); return 0; }
        *u = BN_bin2bn(pgp_data + mpi_pos, u_len, NULL);
        fprintf(stderr, "extract_pgp_private_key: u_bits=%d u_len=%d\n", u_bits, u_len); fflush(stderr);
        mpi_pos += u_len;
    } else {
        fprintf(stderr, "extract_pgp_private_key: encrypted secret key not supported\n"); fflush(stderr);
        return 0;
    }
    return 1;
}

// Main: tossl::pgp::signature::create
int PgpSignatureCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "private_key data sig_type ?hash_algo?");
        return TCL_ERROR;
    }
    
    int keylen;
    const unsigned char *key_data = Tcl_GetByteArrayFromObj(objv[1], &keylen);
    int datalen;
    const unsigned char *data = Tcl_GetByteArrayFromObj(objv[2], &datalen);
    int sig_type;
    if (Tcl_GetIntFromObj(interp, objv[3], &sig_type) != TCL_OK) {
        return TCL_ERROR;
    }
    
    int hash_algo = 2; // SHA1 default
    if (objc > 4) {
        if (Tcl_GetIntFromObj(interp, objv[4], &hash_algo) != TCL_OK) {
            return TCL_ERROR;
        }
    }
    
    // Extract private key components from PGP key
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *u = NULL;
    if (!extract_pgp_private_key(key_data, keylen, &n, &e, &d, &p, &q, &u)) {
        Tcl_SetResult(interp, "Failed to extract private key from PGP key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create RSA key from components
    RSA *rsa = RSA_new();
    if (!rsa) {
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q); BN_free(u);
        Tcl_SetResult(interp, "Failed to create RSA key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, NULL, u, NULL);
    
    // Create EVP_PKEY from RSA
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        if (pkey) EVP_PKEY_free(pkey);
        RSA_free(rsa);
        Tcl_SetResult(interp, "Failed to create EVP_PKEY", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Determine public key algorithm
    int pubkey_algo = 1; // RSA default
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        pubkey_algo = 1; // RSA
    } else if (EVP_PKEY_id(pkey) == EVP_PKEY_DSA) {
        pubkey_algo = 17; // DSA
    } else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
        pubkey_algo = 19; // ECDSA
    } else {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Unsupported key type for OpenPGP", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get hash algorithm
    const EVP_MD *md = NULL;
    switch (hash_algo) {
        case 1: md = EVP_md5(); break;
        case 2: md = EVP_sha1(); break;
        case 8: md = EVP_sha256(); break;
        case 9: md = EVP_sha384(); break;
        case 10: md = EVP_sha512(); break;
        case 11: md = EVP_sha224(); break;
        default:
            EVP_PKEY_free(pkey);
            Tcl_SetResult(interp, "Unsupported hash algorithm", TCL_STATIC);
            return TCL_ERROR;
    }
    
    // Create signature data to hash (RFC 4880 §5.2.4)
    unsigned char sig_data[4096];
    int sig_data_len = 0;
    
    // Support for detached signatures
    int detached = 0;
    for (int i = 5; i < objc; ++i) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-detached") == 0) {
            detached = 1;
        }
    }

    if (sig_type == PGP_SIG_BINARY) {
        sig_data[sig_data_len++] = 0x88; // signature of binary document
        write_uint32(sig_data + sig_data_len, datalen);
        sig_data_len += 4;
        memcpy(sig_data + sig_data_len, data, datalen);
        sig_data_len += datalen;
    } else if (sig_type == 1 /* PGP_SIG_CANONICAL_TEXT_DOCUMENT */) {
        // Canonicalize line endings to CRLF
        unsigned char *canon = malloc(datalen * 2); // worst case: all LF -> CRLF
        int canon_len = 0;
        for (int i = 0; i < datalen; ++i) {
            if (data[i] == '\r') {
                canon[canon_len++] = '\r';
            } else if (data[i] == '\n') {
                if (i == 0 || data[i-1] != '\r') {
                    canon[canon_len++] = '\r';
                }
                canon[canon_len++] = '\n';
            } else {
                canon[canon_len++] = data[i];
            }
        }
        sig_data[sig_data_len++] = 0x88; // signature of text document
        write_uint32(sig_data + sig_data_len, canon_len);
        sig_data_len += 4;
        memcpy(sig_data + sig_data_len, canon, canon_len);
        sig_data_len += canon_len;
        free(canon);
    } else {
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Only binary and canonical text signatures supported for now", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Hash the signature data
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md_type = EVP_sha1();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!mdctx || !EVP_DigestInit_ex(mdctx, md_type, NULL) ||
        !EVP_DigestUpdate(mdctx, sig_data, sig_data_len) ||
        !EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Hash calculation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX_free(mdctx);
    
    // Sign the hash
    unsigned char signature[EVP_PKEY_size(pkey)];
    size_t sig_len = sizeof(signature);
    EVP_MD_CTX *sigctx = EVP_MD_CTX_new();
    if (!sigctx || EVP_DigestSignInit(sigctx, NULL, md, NULL, pkey) <= 0 ||
        EVP_DigestSign(sigctx, signature, &sig_len, hash, hash_len) <= 0) {
        if (sigctx) EVP_MD_CTX_free(sigctx);
        EVP_PKEY_free(pkey);
        Tcl_SetResult(interp, "Signature creation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    EVP_MD_CTX_free(sigctx);
    EVP_PKEY_free(pkey);
    
    // Create signature packet
    unsigned char *buf = malloc(4096);
    int packet_len = create_signature_packet(buf, sig_type, pubkey_algo, hash_algo,
                                           sig_data, sig_data_len, signature, sig_len, hash);
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(buf, packet_len);
    free(buf);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Helper: Extract public key components from PGP key (public or private)
static int extract_pgp_public_key(const unsigned char *pgp_data, int pgp_len, 
                                 BIGNUM **n, BIGNUM **e) {
    // Initialize pointers to NULL for safety
    *n = NULL;
    *e = NULL;
    
    int pos = 0;
    int tag, len, consumed;
    
    // Parse packet header
    if (!parse_packet_header(pgp_data, pgp_len, &tag, &len, &consumed)) {
        fprintf(stderr, "extract_pgp_public_key: failed to parse packet header\n"); fflush(stderr);
        return 0;
    }
    
    fprintf(stderr, "extract_pgp_public_key: tag=%d len=%d consumed=%d\n", tag, len, consumed); fflush(stderr);
    
    // Check if it's a public or private key packet
    if (tag != 6 && tag != 5) {
        fprintf(stderr, "extract_pgp_public_key: not a key packet (tag=%d)\n", tag); fflush(stderr);
        return 0;
    }
    
    pos += consumed;
    
    // Check version
    int version = pgp_data[pos++];
    fprintf(stderr, "extract_pgp_public_key: version=%d\n", version); fflush(stderr);
    if (version != 4) {
        fprintf(stderr, "extract_pgp_public_key: unsupported version %d\n", version); fflush(stderr);
        return 0;
    }
    
    // Skip timestamp (4 bytes)
    pos += 4;
    
    // Check algorithm
    int algo = pgp_data[pos++];
    fprintf(stderr, "extract_pgp_public_key: algo=%d\n", algo); fflush(stderr);
    if (algo != 1) { // RSA
        fprintf(stderr, "extract_pgp_public_key: unsupported algo %d\n", algo); fflush(stderr);
        return 0;
    }
    
    // Parse n (modulus)
    if (pos + 2 > pgp_len) {
        fprintf(stderr, "extract_pgp_public_key: n field truncated\n"); fflush(stderr);
        return 0;
    }
    
    uint16_t n_bits = (pgp_data[pos] << 8) | pgp_data[pos + 1];
    int n_len = (n_bits + 7) / 8;
    pos += 2;
    
    fprintf(stderr, "extract_pgp_public_key: n_bits=%d n_len=%d\n", n_bits, n_len); fflush(stderr);
    
    if (pos + n_len > pgp_len) {
        fprintf(stderr, "extract_pgp_public_key: n data truncated\n"); fflush(stderr);
        return 0;
    }
    
    *n = BN_bin2bn(pgp_data + pos, n_len, NULL);
    if (*n == NULL) {
        fprintf(stderr, "extract_pgp_public_key: BN_bin2bn failed for n\n"); fflush(stderr);
        return 0;
    }
    
    pos += n_len;
    
    // Parse e (exponent)
    if (pos + 2 > pgp_len) {
        fprintf(stderr, "extract_pgp_public_key: e field truncated\n"); fflush(stderr);
        BN_free(*n);
        *n = NULL;
        return 0;
    }
    
    uint16_t e_bits = (pgp_data[pos] << 8) | pgp_data[pos + 1];
    int e_len = (e_bits + 7) / 8;
    pos += 2;
    
    fprintf(stderr, "extract_pgp_public_key: e_bits=%d e_len=%d\n", e_bits, e_len); fflush(stderr);
    
    if (pos + e_len > pgp_len) {
        fprintf(stderr, "extract_pgp_public_key: e data truncated\n"); fflush(stderr);
        BN_free(*n);
        *n = NULL;
        return 0;
    }
    
    *e = BN_bin2bn(pgp_data + pos, e_len, NULL);
    if (*e == NULL) {
        fprintf(stderr, "extract_pgp_public_key: BN_bin2bn failed for e\n"); fflush(stderr);
        BN_free(*n);
        *n = NULL;
        return 0;
    }
    
    fprintf(stderr, "extract_pgp_public_key: successfully extracted public key components\n"); fflush(stderr);
    return 1;
}

// Main: tossl::pgp::signature::verify

static int PgpSignatureVerifyCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "public_key data signature");
        return TCL_ERROR;
    }

    int keylen, datalen, siglen;
    unsigned char *key = Tcl_GetByteArrayFromObj(objv[1], &keylen);
    unsigned char *data = Tcl_GetByteArrayFromObj(objv[2], &datalen);
    unsigned char *sig = Tcl_GetByteArrayFromObj(objv[3], &siglen);

    // Parse the key packet
    pgp_packet_t key_pkt;
    pgp_error_t err = pgp_packet_parse_header(key, keylen, &key_pkt);
    if (err != PGP_OK) {
        pgp_set_error(interp, err, "Failed to parse key packet");
        return TCL_ERROR;
    }

    // Initialize crypto context
    pgp_crypto_ctx_t ctx;
    err = pgp_crypto_init(&ctx);
    if (err != PGP_OK) {
        pgp_set_error(interp, err, "Failed to initialize crypto context");
        return TCL_ERROR;
    }

    // Extract public key
    EVP_PKEY *pkey = NULL;
    const unsigned char *key_ptr = key;
    pkey = d2i_PUBKEY(NULL, &key_ptr, keylen);
    if (!pkey) {
        pgp_crypto_cleanup(&ctx);
        pgp_set_error(interp, PGP_ERR_INVALID_KEY, "Failed to parse public key");
        return TCL_ERROR;
    }

    // Set up the key in the crypto context
    err = pgp_crypto_set_key(&ctx, pkey, RSA_PKCS1_PADDING);
    if (err != PGP_OK) {
        EVP_PKEY_free(pkey);
        pgp_crypto_cleanup(&ctx);
        pgp_set_error(interp, err, "Failed to set up key");
        return TCL_ERROR;
    }

    // Parse the signature packet
    pgp_packet_t sig_pkt;
    err = pgp_packet_parse_header(sig, siglen, &sig_pkt);
    if (err != PGP_OK) {
        EVP_PKEY_free(pkey);
        pgp_crypto_cleanup(&ctx);
        pgp_set_error(interp, err, "Failed to parse signature packet");
        return TCL_ERROR;
    }

    if (sig_pkt.tag != PGP_PKT_SIGNATURE) {
        EVP_PKEY_free(pkey);
        pgp_crypto_cleanup(&ctx);
        pgp_set_error(interp, PGP_ERR_INVALID_PACKET, "Not a signature packet");
        return TCL_ERROR;
    }

    // Parse the signature
    pgp_signature_t sig_data;
    err = pgp_signature_parse(sig_pkt.body, sig_pkt.length, &sig_data);
    if (err != PGP_OK) {
        EVP_PKEY_free(pkey);
        pgp_crypto_cleanup(&ctx);
        pgp_set_error(interp, err, "Failed to parse signature data");
        return TCL_ERROR;
    }

    // Verify the signature
    err = pgp_signature_verify(&ctx, data, datalen, &sig_data);

    // Clean up
    pgp_signature_free(&sig_data);
    EVP_PKEY_free(pkey);
    pgp_crypto_cleanup(&ctx);

    if (err != PGP_OK) {
        pgp_set_error(interp, err, "Signature verification failed");
        return TCL_ERROR;
    }

    // Success!
    Tcl_SetResult(interp, "1", TCL_STATIC);
    return TCL_OK;
}

// Main: tossl::pgp::signature::parse
int PgpSignatureParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "signature_data");
        return TCL_ERROR;
    }
    
    int siglen;
    const unsigned char *signature = Tcl_GetByteArrayFromObj(objv[1], &siglen);
    
    // Parse packet header first
    int tag, len, consumed;
    if (!parse_packet_header(signature, siglen, &tag, &len, &consumed)) {
        Tcl_SetResult(interp, "Invalid packet header", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (tag != PGP_PKT_SIGNATURE) {
        Tcl_SetResult(interp, "Not a signature packet", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (consumed + len > siglen) {
        Tcl_SetResult(interp, "Packet data truncated", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse signature packet body
    Tcl_Obj *sig_dict = NULL;
    if (!parse_signature_packet(interp, signature + consumed, len, &sig_dict)) {
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, sig_dict);
    return TCL_OK;
}

// Registration function for tossl_pgp.c
int Tossl_Pgp_Init(Tcl_Interp *interp) {
    // Add debug output
    Tcl_SetResult(interp, "PGP initialization started", TCL_STATIC);
    
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::generate", PgpKeyGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::export",   PgpKeyExportCmd,   NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::import",   PgpKeyImportCmd,   NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::parse",    PgpKeyParseCmd,    NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::generate_secret", PgpKeyGenerateSecretCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::import_secret",   PgpKeyImportSecretCmd,   NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::key::export_secret",   PgpKeyExportSecretCmd,   NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::message::parse", PgpMessageParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::message::create_literal", PgpMessageCreateLiteralCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::message::create_compressed", PgpMessageCreateCompressedCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::signature::create", PgpSignatureCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::signature::verify", PgpSignatureVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pgp::signature::parse", PgpSignatureParseCmd, NULL, NULL);
    
    // Clear the result
    Tcl_ResetResult(interp);
    return TCL_OK;
} 
