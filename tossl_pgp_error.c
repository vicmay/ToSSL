#include "tossl_pgp_error.h"
#include <string.h>
#include <openssl/crypto.h>

const char* pgp_strerror(pgp_error_t err) {
    switch (err) {
        case PGP_OK:
            return "Success";
        case PGP_ERR_MEMORY:
            return "Memory allocation failed";
        case PGP_ERR_INVALID_PACKET:
            return "Invalid OpenPGP packet";
        case PGP_ERR_UNSUPPORTED_ALGORITHM:
            return "Unsupported algorithm";
        case PGP_ERR_INVALID_KEY:
            return "Invalid key";
        case PGP_ERR_INVALID_SIGNATURE:
            return "Invalid signature";
        case PGP_ERR_VERIFY_FAILED:
            return "Signature verification failed";
        case PGP_ERR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case PGP_ERR_INVALID_FORMAT:
            return "Invalid format";
        case PGP_ERR_CRYPTO_FAILED:
            return "Cryptographic operation failed";
        case PGP_ERR_INTERNAL:
            return "Internal error";
        default:
            return "Unknown error";
    }
}

void pgp_set_error(Tcl_Interp *interp, pgp_error_t err, const char *details) {
    if (!interp) return;
    
    const char *base_msg = pgp_strerror(err);
    if (details) {
        Tcl_SetResult(interp, (char *)details, TCL_VOLATILE);
        Tcl_AppendResult(interp, ": ", base_msg, NULL);
    } else {
        Tcl_SetResult(interp, (char *)base_msg, TCL_VOLATILE);
    }
}

void secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL) return;
    OPENSSL_cleanse(ptr, len);
}
