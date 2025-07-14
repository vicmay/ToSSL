#ifndef TOSSL_PGP_PACKET_H
#define TOSSL_PGP_PACKET_H

#include <stdint.h>
#include "tossl_pgp_error.h"

// OpenPGP packet types (RFC 4880 §4.3)
typedef enum {
    PGP_PKT_RESERVED = 0,
    PGP_PKT_PUBKEY_ENC_SESSION = 1,
    PGP_PKT_SIGNATURE = 2,
    PGP_PKT_SYMKEY_ENC_SESSION = 3,
    PGP_PKT_ONEPASS_SIG = 4,
    PGP_PKT_SECRET_KEY = 5,
    PGP_PKT_PUBLIC_KEY = 6,
    PGP_PKT_SECRET_SUBKEY = 7,
    PGP_PKT_COMPRESSED = 8,
    PGP_PKT_ENCRYPTED = 9,
    PGP_PKT_MARKER = 10,
    PGP_PKT_LITERAL = 11,
    PGP_PKT_TRUST = 12,
    PGP_PKT_USER_ID = 13,
    PGP_PKT_PUBLIC_SUBKEY = 14,
    PGP_PKT_USER_ATTR = 17,
    PGP_PKT_SYM_ENC_INT_PRO = 18,
    PGP_PKT_MOD_DETECT_CODE = 19
} pgp_packet_tag_t;

// OpenPGP packet header
typedef struct {
    pgp_packet_tag_t tag;
    uint32_t length;
    uint32_t header_len;
    const unsigned char *body;
} pgp_packet_t;

// Parse OpenPGP packet header
pgp_error_t pgp_packet_parse_header(const unsigned char *data, size_t len, pgp_packet_t *pkt);

// Create OpenPGP packet header
pgp_error_t pgp_packet_create_header(unsigned char *buf, size_t buf_len, size_t *written,
                                   pgp_packet_tag_t tag, uint32_t body_len);

// Parse packet length field
pgp_error_t pgp_packet_parse_length(const unsigned char *data, size_t len,
                                   uint32_t *length, uint32_t *length_len);

// Write packet length field
pgp_error_t pgp_packet_write_length(unsigned char *buf, size_t buf_len, size_t *written,
                                   uint32_t length);

// Get human-readable packet tag name
const char *pgp_packet_tag_name(pgp_packet_tag_t tag);

#endif /* TOSSL_PGP_PACKET_H */
