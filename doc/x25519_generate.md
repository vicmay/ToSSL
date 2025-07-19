# ::tossl::x25519::generate

## Overview

The `::tossl::x25519::generate` command generates a new X25519 private key in PEM format. This command uses the modern OpenSSL API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
tossl::x25519::generate
```

## Description

Generates a new X25519 private key and returns it in PEM format. The key can be used for X25519 key agreement (ECDH) and is suitable for secure messaging, key exchange, and cryptographic protocols.

- The output is a PEM-encoded private key (string).
- The key is compatible with OpenSSL 3.x and the OpenSSL CLI.
- Use `::tossl::key::getpub` to extract the public key from the private key.

## Output

Returns the X25519 private key in PEM format (string).

## Examples

```tcl
# Generate a new X25519 private key
set priv [tossl::x25519::generate]
puts $priv

# Extract the public key
set pub [tossl::key::getpub -key $priv]
puts $pub

# Use the key for key agreement
set priv2 [tossl::x25519::generate]
set pub2 [tossl::key::getpub -key $priv2]
set secret [tossl::x25519::derive $priv $pub2]
puts [binary encode hex $secret]
```

## Error Handling

- Throws an error if extra arguments are provided
- Throws an error if key generation fails

## OpenSSL Compatibility

- Uses the EVP_PKEY API for robust, future-proof key generation
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always store private keys securely
- Use the generated key only for X25519 key agreement
- Extract the public key using `::tossl::key::getpub` for sharing

## Related Commands

- `::tossl::x25519::derive` - X25519 key agreement
- `::tossl::key::getpub` - Extract public key from private key
- `::tossl::x448::generate` - X448 key generation 