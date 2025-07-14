#include "tossl_pgp_signature.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

static pgp_error_t parse_subpackets(const unsigned char *data, size_t len,
                                  pgp_signature_t *sig, int hashed);

pgp_error_t pgp_signature_parse(const unsigned char *data, size_t len, pgp_signature_t *sig) {
    if (!data || !sig || len < 7)
        return PGP_ERR_INVALID_PACKET;
    
    memset(sig, 0, sizeof(pgp_signature_t));
    
    size_t pos = 0;
    sig->version = data[pos++];
    
    if (sig->version != 4)
        return PGP_ERR_INVALID_FORMAT;
    
    sig->type = data[pos++];
    sig->pubkey_algo = data[pos++];
    sig->hash_algo = data[pos++];
    
    // Hashed subpackets
    sig->hashed_subpkt_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    if (pos + sig->hashed_subpkt_len > len)
        return PGP_ERR_INVALID_PACKET;
    
    pgp_error_t err = parse_subpackets(data + pos, sig->hashed_subpkt_len, sig, 1);
    if (err != PGP_OK)
        return err;
    
    pos += sig->hashed_subpkt_len;
    
    // Unhashed subpackets
    if (pos + 2 > len)
        return PGP_ERR_INVALID_PACKET;
    
    sig->unhashed_subpkt_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    if (pos + sig->unhashed_subpkt_len > len)
        return PGP_ERR_INVALID_PACKET;
    
    err = parse_subpackets(data + pos, sig->unhashed_subpkt_len, sig, 0);
    if (err != PGP_OK)
        return err;
    
    pos += sig->unhashed_subpkt_len;
    
    // Hash prefix
    if (pos + 2 > len)
        return PGP_ERR_INVALID_PACKET;
    
    memcpy(sig->hash_prefix, data + pos, 2);
    pos += 2;
    
    // Signature MPIs
    size_t remaining = len - pos;
    sig->signature = OPENSSL_malloc(remaining);
    if (!sig->signature)
        return PGP_ERR_MEMORY;
    
    memcpy(sig->signature, data + pos, remaining);
    sig->signature_len = remaining;
    
    return PGP_OK;
}

static pgp_error_t parse_subpackets(const unsigned char *data, size_t len,
                                  pgp_signature_t *sig, int hashed) {
    size_t pos = 0;
    
    while (pos < len) {
        if (pos + 1 > len)
            return PGP_ERR_INVALID_PACKET;
        
        uint32_t subpkt_len;
        uint32_t len_size;
        
        pgp_error_t err = pgp_packet_parse_length(data + pos, len - pos,
                                                &subpkt_len, &len_size);
        if (err != PGP_OK)
            return err;
        
        pos += len_size;
        
        if (pos + subpkt_len > len)
            return PGP_ERR_INVALID_PACKET;
        
        uint8_t type = data[pos++];
        subpkt_len--; // Account for type byte
        
        switch (type) {
            case PGP_SIG_SUBPKT_CREATION_TIME:
                if (subpkt_len != 4)
                    return PGP_ERR_INVALID_FORMAT;
                sig->creation_time = ((uint32_t)data[pos] << 24) |
                                   ((uint32_t)data[pos + 1] << 16) |
                                   ((uint32_t)data[pos + 2] << 8) |
                                   data[pos + 3];
                break;
                
            case PGP_SIG_SUBPKT_ISSUER:
                if (subpkt_len != 8)
                    return PGP_ERR_INVALID_FORMAT;
                memcpy(sig->issuer, data + pos, 8);
                break;
                
            // Add other subpacket types as needed
        }
        
        pos += subpkt_len;
    }
    
    return PGP_OK;
}

pgp_error_t pgp_signature_create(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len,
                                pgp_sig_type_t type, unsigned char *sig_pkt, size_t *sig_len) {
    if (!ctx || !data || !sig_pkt || !sig_len)
        return PGP_ERR_INTERNAL;
    
    // Header
    unsigned char header[6] = {
        0x04,           // Version
        type,           // Signature type
        PGP_PUBKEY_RSA, // Public key algorithm
        PGP_HASH_SHA256 // Hash algorithm
    };
    
    // Create hashed subpackets
    unsigned char hashed_subpkts[6];
    uint32_t now = (uint32_t)time(NULL);
    hashed_subpkts[0] = 5;    // Length including type
    hashed_subpkts[1] = PGP_SIG_SUBPKT_CREATION_TIME;
    hashed_subpkts[2] = (now >> 24) & 0xFF;
    hashed_subpkts[3] = (now >> 16) & 0xFF;
    hashed_subpkts[4] = (now >> 8) & 0xFF;
    hashed_subpkts[5] = now & 0xFF;
    
    uint16_t hashed_len = sizeof(hashed_subpkts);
    header[4] = (hashed_len >> 8) & 0xFF;
    header[5] = hashed_len & 0xFF;
    
    // Hash the data
    pgp_error_t err = pgp_crypto_hash_update(ctx, header, sizeof(header));
    if (err != PGP_OK)
        return err;
    
    err = pgp_crypto_hash_update(ctx, hashed_subpkts, hashed_len);
    if (err != PGP_OK)
        return err;
    
    // Hash the data
    if (type == PGP_SIG_TEXT) {
        unsigned char *canon_data;
        size_t canon_len;
        err = pgp_signature_canonicalize_text(data, len, &canon_data, &canon_len);
        if (err != PGP_OK)
            return err;
        
        err = pgp_crypto_hash_update(ctx, canon_data, canon_len);
        OPENSSL_free(canon_data);
        if (err != PGP_OK)
            return err;
    } else {
        err = pgp_crypto_hash_update(ctx, data, len);
        if (err != PGP_OK)
            return err;
    }
    
    // Get the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    err = pgp_crypto_hash_final(ctx, hash, &hash_len);
    if (err != PGP_OK)
        return err;
    
    // Create the signature
    unsigned char *sig = OPENSSL_malloc(EVP_PKEY_size(ctx->pkey));
    if (!sig)
        return PGP_ERR_MEMORY;
    
    size_t sig_mpi_len;
    err = pgp_crypto_sign(ctx, hash, hash_len, sig, &sig_mpi_len);
    if (err != PGP_OK) {
        OPENSSL_free(sig);
        return err;
    }
    
    // Build the packet
    size_t packet_len = sizeof(header) + hashed_len + 2 + 2 + sig_mpi_len;
    size_t header_written;
    err = pgp_packet_create_header(sig_pkt, *sig_len, &header_written,
                                 PGP_PKT_SIGNATURE, packet_len);
    if (err != PGP_OK) {
        OPENSSL_free(sig);
        return err;
    }
    
    size_t pos = header_written;
    
    // Write signature packet contents
    memcpy(sig_pkt + pos, header, sizeof(header));
    pos += sizeof(header);
    
    memcpy(sig_pkt + pos, hashed_subpkts, hashed_len);
    pos += hashed_len;
    
    // No unhashed subpackets
    sig_pkt[pos++] = 0;
    sig_pkt[pos++] = 0;
    
    // Hash prefix
    sig_pkt[pos++] = hash[0];
    sig_pkt[pos++] = hash[1];
    
    // Write signature MPI
    memcpy(sig_pkt + pos, sig, sig_mpi_len);
    pos += sig_mpi_len;
    
    *sig_len = pos;
    OPENSSL_free(sig);
    
    return PGP_OK;
}

pgp_error_t pgp_signature_verify(pgp_crypto_ctx_t *ctx, const unsigned char *data, size_t len,
                                const pgp_signature_t *sig) {
    if (!ctx || !data || !sig)
        return PGP_ERR_INTERNAL;
    
    // Set up hash algorithm
    pgp_error_t err = pgp_crypto_set_hash(ctx, sig->hash_algo);
    if (err != PGP_OK)
        return err;
    
    // Hash the signature fields
    unsigned char header[6] = {
        sig->version,
        sig->type,
        sig->pubkey_algo,
        sig->hash_algo,
        (sig->hashed_subpkt_len >> 8) & 0xFF,
        sig->hashed_subpkt_len & 0xFF
    };
    
    err = pgp_crypto_hash_update(ctx, header, sizeof(header));
    if (err != PGP_OK)
        return err;
    
    // Hash the data
    if (sig->type == PGP_SIG_TEXT) {
        unsigned char *canon_data;
        size_t canon_len;
        err = pgp_signature_canonicalize_text(data, len, &canon_data, &canon_len);
        if (err != PGP_OK)
            return err;
        
        err = pgp_crypto_hash_update(ctx, canon_data, canon_len);
        OPENSSL_free(canon_data);
        if (err != PGP_OK)
            return err;
    } else {
        err = pgp_crypto_hash_update(ctx, data, len);
        if (err != PGP_OK)
            return err;
    }
    
    // Get the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    err = pgp_crypto_hash_final(ctx, hash, &hash_len);
    if (err != PGP_OK)
        return err;
    
    // Compare hash prefix
    if (memcmp(sig->hash_prefix, hash, 2) != 0)
        return PGP_ERR_VERIFY_FAILED;
    
    // Verify the signature
    return pgp_crypto_verify(ctx, hash, hash_len, sig->signature, sig->signature_len);
}

pgp_error_t pgp_signature_canonicalize_text(const unsigned char *data, size_t len,
                                          unsigned char **canon_data, size_t *canon_len) {
    if (!data || !canon_data || !canon_len)
        return PGP_ERR_INTERNAL;
    
    // Allocate maximum possible size (2x input for CRLF)
    *canon_data = OPENSSL_malloc(len * 2);
    if (!*canon_data)
        return PGP_ERR_MEMORY;
    
    size_t out_pos = 0;
    int last_was_cr = 0;
    
    // Process each byte
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        
        if (c == '\r') {
            (*canon_data)[out_pos++] = '\r';
            (*canon_data)[out_pos++] = '\n';
            last_was_cr = 1;
        }
        else if (c == '\n') {
            if (!last_was_cr) {
                (*canon_data)[out_pos++] = '\r';
                (*canon_data)[out_pos++] = '\n';
            }
            last_was_cr = 0;
        }
        else {
            (*canon_data)[out_pos++] = c;
            last_was_cr = 0;
        }
    }
    
    // Ensure text ends with CRLF
    if (out_pos == 0 || (*canon_data)[out_pos - 1] != '\n') {
        (*canon_data)[out_pos++] = '\r';
        (*canon_data)[out_pos++] = '\n';
    }
    else if (out_pos == 1 || (*canon_data)[out_pos - 2] != '\r') {
        memmove(*canon_data + out_pos - 1, *canon_data + out_pos - 2, 1);
        (*canon_data)[out_pos - 2] = '\r';
        (*canon_data)[out_pos - 1] = '\n';
    }
    
    *canon_len = out_pos;
    return PGP_OK;
}

void pgp_signature_free(pgp_signature_t *sig) {
    if (!sig) return;
    
    if (sig->signature) {
        secure_memzero(sig->signature, sig->signature_len);
        OPENSSL_free(sig->signature);
    }
    
    memset(sig, 0, sizeof(pgp_signature_t));
}
