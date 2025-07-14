#ifndef TOSSL_PGP_SIGNATURE_H
#define TOSSL_PGP_SIGNATURE_H

#include "tossl_pgp_error.h"
#include "tossl_pgp_crypto.h"
#include "tossl_pgp_packet.h"

// Signature types (RFC 4880 §5.2.1)
typedef enum {
    PGP_SIG_BINARY = 0x00,
    PGP_SIG_TEXT = 0x01,
    PGP_SIG_STANDALONE = 0x02,
    PGP_SIG_GENERIC_CERT = 0x10,
    PGP_SIG_PERSONA_CERT = 0x11,
    PGP_SIG_CASUAL_CERT = 0x12,
    PGP_SIG_POSITIVE_CERT = 0x13,
    PGP_SIG_SUBKEY_BIND = 0x18,
    PGP_SIG_PRIMARY_KEY_BIND = 0x19,
    PGP_SIG_DIRECT_KEY = 0x1F,
    PGP_SIG_KEY_REVOKE = 0x20,
    PGP_SIG_SUBKEY_REVOKE = 0x28,
    PGP_SIG_CERT_REVOKE = 0x30,
    PGP_SIG_TIMESTAMP = 0x40,
    PGP_SIG_3PARTY_CONFIRM = 0x50
} pgp_sig_type_t;

// Signature subpacket types (RFC 4880 §5.2.3.1)
typedef enum {
    PGP_SIG_SUBPKT_CREATION_TIME = 2,
    PGP_SIG_SUBPKT_EXPIRATION_TIME = 3,
    PGP_SIG_SUBPKT_EXPORTABLE = 4,
    PGP_SIG_SUBPKT_TRUST = 5,
    PGP_SIG_SUBPKT_REGEXP = 6,
    PGP_SIG_SUBPKT_REVOCABLE = 7,
    PGP_SIG_SUBPKT_KEY_EXPIRE = 9,
    PGP_SIG_SUBPKT_PLACEHOLDER = 10,
    PGP_SIG_SUBPKT_PREF_SYM = 11,
    PGP_SIG_SUBPKT_REVOKE_KEY = 12,
    PGP_SIG_SUBPKT_ISSUER = 16,
    PGP_SIG_SUBPKT_NOTATION = 20,
    PGP_SIG_SUBPKT_PREF_HASH = 21,
    PGP_SIG_SUBPKT_PREF_COMP = 22,
    PGP_SIG_SUBPKT_KS_FLAGS = 23,
    PGP_SIG_SUBPKT_PREF_KS = 24,
    PGP_SIG_SUBPKT_PRIMARY_UID = 25,
    PGP_SIG_SUBPKT_POLICY = 26,
    PGP_SIG_SUBPKT_KEY_FLAGS = 27,
    PGP_SIG_SUBPKT_SIGNERS_UID = 28,
    PGP_SIG_SUBPKT_REASON = 29,
    PGP_SIG_SUBPKT_FEATURES = 30,
    PGP_SIG_SUBPKT_TARGET = 31,
    PGP_SIG_SUBPKT_EMBEDDED = 32
} pgp_sig_subpkt_type_t;

// Signature packet
typedef struct {
    uint8_t version;
    pgp_sig_type_t type;
    pgp_pubkey_algo_t pubkey_algo;
    pgp_hash_algo_t hash_algo;
    uint16_t hashed_subpkt_len;
    uint16_t unhashed_subpkt_len;
    unsigned char hash_prefix[2];
    unsigned char *signature;
    size_t signature_len;
    time_t creation_time;
    uint32_t key_id;
    unsigned char issuer[8];
} pgp_signature_t;

// Parse signature packet
pgp_error_t pgp_signature_parse(const unsigned char *data, size_t len, pgp_signature_t *sig);

// Create signature packet
pgp_error_t pgp_signature_create(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len,
                                pgp_sig_type_t type, unsigned char *sig_pkt, size_t *sig_len);

// Verify signature
pgp_error_t pgp_signature_verify(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len,
                                const pgp_signature_t *sig);

// Canonicalize text data per RFC 4880
pgp_error_t pgp_signature_canonicalize_text(const unsigned char *data, size_t len,
                                          unsigned char **canon_data, size_t *canon_len);

// Free signature structure
void pgp_signature_free(pgp_signature_t *sig);

#endif /* TOSSL_PGP_SIGNATURE_H */
