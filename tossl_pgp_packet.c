#include "tossl_pgp_packet.h"
#include <string.h>

pgp_error_t pgp_packet_parse_header(const unsigned char *data, size_t len, pgp_packet_t *pkt) {
    if (!data || !pkt || len < 2)
        return PGP_ERR_INVALID_PACKET;

    memset(pkt, 0, sizeof(pgp_packet_t));
    
    unsigned char c = data[0];
    if (!(c & 0x80))  // Not a PGP packet
        return PGP_ERR_INVALID_PACKET;
    
    size_t pos = 1;
    if (c & 0x40) {  // New format
        pkt->tag = (c & 0x3F);
        pgp_error_t err = pgp_packet_parse_length(data + pos, len - pos,
                                                &pkt->length, &pkt->header_len);
        if (err != PGP_OK)
            return err;
        pkt->header_len += pos;
    } else {  // Old format
        pkt->tag = (c >> 2) & 0x0F;
        int length_type = c & 0x03;
        
        switch (length_type) {
            case 0:  // One octet length
                if (len < 2) return PGP_ERR_INVALID_PACKET;
                pkt->length = data[pos];
                pkt->header_len = 2;
                break;
                
            case 1:  // Two octet length
                if (len < 3) return PGP_ERR_INVALID_PACKET;
                pkt->length = (data[pos] << 8) | data[pos + 1];
                pkt->header_len = 3;
                break;
                
            case 2:  // Four octet length
                if (len < 5) return PGP_ERR_INVALID_PACKET;
                pkt->length = ((uint32_t)data[pos] << 24) |
                            ((uint32_t)data[pos + 1] << 16) |
                            ((uint32_t)data[pos + 2] << 8) |
                            data[pos + 3];
                pkt->header_len = 5;
                break;
                
            case 3:  // Indeterminate length - not supported
                return PGP_ERR_INVALID_FORMAT;
        }
    }
    
    if (pkt->length > len - pkt->header_len)
        return PGP_ERR_INVALID_PACKET;
    
    pkt->body = data + pkt->header_len;
    return PGP_OK;
}

pgp_error_t pgp_packet_create_header(unsigned char *buf, size_t buf_len, size_t *written,
                                   pgp_packet_tag_t tag, uint32_t body_len) {
    if (!buf || !written || buf_len < 6)  // Minimum space needed for max header
        return PGP_ERR_BUFFER_TOO_SMALL;
    
    *written = 0;
    
    // Use new format packet header
    buf[0] = 0x80 | 0x40 | (tag & 0x3F);
    (*written)++;
    
    // Write length
    pgp_error_t err = pgp_packet_write_length(buf + 1, buf_len - 1,
                                            written, body_len);
    if (err != PGP_OK)
        return err;
    
    (*written)++;  // Account for tag byte
    return PGP_OK;
}

pgp_error_t pgp_packet_parse_length(const unsigned char *data, size_t len,
                                  uint32_t *length, uint32_t *length_len) {
    if (!data || !length || !length_len || len < 1)
        return PGP_ERR_INVALID_PACKET;
    
    unsigned char c = data[0];
    
    if (c < 192) {  // One octet length
        *length = c;
        *length_len = 1;
    }
    else if (c < 224) {  // Two octet length
        if (len < 2) return PGP_ERR_INVALID_PACKET;
        *length = ((c - 192) << 8) + data[1] + 192;
        *length_len = 2;
    }
    else if (c == 255) {  // Five octet length
        if (len < 5) return PGP_ERR_INVALID_PACKET;
        *length = ((uint32_t)data[1] << 24) |
                 ((uint32_t)data[2] << 16) |
                 ((uint32_t)data[3] << 8) |
                 data[4];
        *length_len = 5;
    }
    else {  // Partial body lengths not supported
        return PGP_ERR_INVALID_FORMAT;
    }
    
    return PGP_OK;
}

pgp_error_t pgp_packet_write_length(unsigned char *buf, size_t buf_len, size_t *written,
                                  uint32_t length) {
    if (!buf || !written || buf_len < 5)  // Need space for max length encoding
        return PGP_ERR_BUFFER_TOO_SMALL;
    
    *written = 0;
    
    if (length < 192) {  // One octet length
        if (buf_len < 1) return PGP_ERR_BUFFER_TOO_SMALL;
        buf[0] = length;
        *written = 1;
    }
    else if (length < 8384) {  // Two octet length
        if (buf_len < 2) return PGP_ERR_BUFFER_TOO_SMALL;
        length -= 192;
        buf[0] = ((length >> 8) & 0xFF) + 192;
        buf[1] = length & 0xFF;
        *written = 2;
    }
    else {  // Five octet length
        if (buf_len < 5) return PGP_ERR_BUFFER_TOO_SMALL;
        buf[0] = 255;
        buf[1] = (length >> 24) & 0xFF;
        buf[2] = (length >> 16) & 0xFF;
        buf[3] = (length >> 8) & 0xFF;
        buf[4] = length & 0xFF;
        *written = 5;
    }
    
    return PGP_OK;
}

const char *pgp_packet_tag_name(pgp_packet_tag_t tag) {
    switch (tag) {
        case PGP_PKT_RESERVED: return "Reserved";
        case PGP_PKT_PUBKEY_ENC_SESSION: return "Public-Key Encrypted Session Key";
        case PGP_PKT_SIGNATURE: return "Signature";
        case PGP_PKT_SYMKEY_ENC_SESSION: return "Symmetric-Key Encrypted Session Key";
        case PGP_PKT_ONEPASS_SIG: return "One-Pass Signature";
        case PGP_PKT_SECRET_KEY: return "Secret Key";
        case PGP_PKT_PUBLIC_KEY: return "Public Key";
        case PGP_PKT_SECRET_SUBKEY: return "Secret Subkey";
        case PGP_PKT_COMPRESSED: return "Compressed Data";
        case PGP_PKT_ENCRYPTED: return "Symmetrically Encrypted Data";
        case PGP_PKT_MARKER: return "Marker";
        case PGP_PKT_LITERAL: return "Literal Data";
        case PGP_PKT_TRUST: return "Trust";
        case PGP_PKT_USER_ID: return "User ID";
        case PGP_PKT_PUBLIC_SUBKEY: return "Public Subkey";
        case PGP_PKT_USER_ATTR: return "User Attribute";
        case PGP_PKT_SYM_ENC_INT_PRO: return "Sym. Encrypted and Integrity Protected Data";
        case PGP_PKT_MOD_DETECT_CODE: return "Modification Detection Code";
        default: return "Unknown";
    }
}
