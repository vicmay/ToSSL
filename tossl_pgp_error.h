#ifndef TOSSL_PGP_ERROR_H
#define TOSSL_PGP_ERROR_H

#include <tcl.h>

// Error codes for OpenPGP operations
typedef enum {
    PGP_OK = 0,
    PGP_ERR_MEMORY = -1,
    PGP_ERR_INVALID_PACKET = -2,
    PGP_ERR_UNSUPPORTED_ALGORITHM = -3,
    PGP_ERR_INVALID_KEY = -4,
    PGP_ERR_INVALID_SIGNATURE = -5,
    PGP_ERR_VERIFY_FAILED = -6,
    PGP_ERR_BUFFER_TOO_SMALL = -7,
    PGP_ERR_INVALID_FORMAT = -8,
    PGP_ERR_CRYPTO_FAILED = -9,
    PGP_ERR_INTERNAL = -10
} pgp_error_t;

// Convert PGP error to Tcl error message
const char* pgp_strerror(pgp_error_t err);

// Set Tcl error result with detailed error info
void pgp_set_error(Tcl_Interp *interp, pgp_error_t err, const char *details);

// Secure memory wiping
void secure_memzero(void *ptr, size_t len);

#endif /* TOSSL_PGP_ERROR_H */
