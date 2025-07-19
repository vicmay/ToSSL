# ::tossl::x25519::derive

## Overview

The `::tossl::x25519::derive` command performs X25519 key agreement (ECDH) using a private key and a peer's public key. The result is a shared secret. This command uses the modern OpenSSL API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
tossl::x25519::derive <private_key_pem> <public_key_pem>
```

- `<private_key_pem>`: X25519 private key in PEM format
- `<public_key_pem>`: X25519 public key in PEM format

## Description

Performs X25519 key agreement (ECDH) using the provided private and public keys. The output is a shared secret as a Tcl byte array. This is suitable for use in cryptographic protocols, secure messaging, and key exchange.

- Both keys must be valid X25519 keys in PEM format.
- The shared secret is a 32-byte value (for X25519).
- Compatible with OpenSSL 3.x and the OpenSSL CLI.

## Output

Returns the shared secret as a Tcl byte array.

## Examples

```tcl
# Generate two key pairs
set priv1 [tossl::x25519::generate]
set priv2 [tossl::x25519::generate]

# Extract public keys
set pub1 [tossl::key::getpub -key $priv1]
set pub2 [tossl::key::getpub -key $priv2]

# Derive shared secrets
set secret1 [tossl::x25519::derive $priv1 $pub2]
set secret2 [tossl::x25519::derive $priv2 $pub1]

# The shared secrets should match
puts [string equal $secret1 $secret2]  ;# Output: 1

# Derive with self (should succeed, but not recommended for real protocols)
set secret_self [tossl::x25519::derive $priv1 $pub1]
puts [string length $secret_self]  ;# Output: 32
```

## Error Handling

- Throws an error for missing/invalid arguments or malformed input
- Throws an error if the keys are not valid X25519 keys
- Throws an error if the key agreement fails

## OpenSSL Compatibility

- Uses the EVP_PKEY API for robust, future-proof key agreement
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always validate all input data and keys
- Test round-trip key agreement for interoperability
- Never use the shared secret directly as an encryption key; use a KDF (e.g., HKDF) to derive keys for encryption

## Related Commands

- `::tossl::x25519::generate` - Generate X25519 key pair
- `::tossl::x448::derive` - X448 key agreement
- `::tossl::key::getpub` - Extract public key from private key 