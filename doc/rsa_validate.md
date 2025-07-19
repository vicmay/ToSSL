# ::tossl::rsa::validate

Validate an RSA key (public or private).

## Overview

`::tossl::rsa::validate` checks whether the provided RSA key (in PEM format) is valid and well-formed. It works for both public and private keys, and returns a boolean result.

## Syntax

```
tossl::rsa::validate -key <pem>
```

- `-key <pem>`: The RSA key in PEM format (public or private).

## Example

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set valid_priv [tossl::rsa::validate -key $priv]
set valid_pub [tossl::rsa::validate -key $pub]
puts "Private key valid: $valid_priv"
puts "Public key valid: $valid_pub"
```

## Return Value

- Returns `1` (true) if the key is valid.
- Returns `0` (false) if the key is invalid (but parseable as RSA).
- Returns an error if the key cannot be parsed or is not an RSA key.

## Error Handling

- Returns an error if the key is not a valid RSA key.
- Returns an error if the key cannot be parsed (e.g., truncated or corrupted).
- Returns an error if the key is not an RSA key (e.g., EC or DSA key).

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material securely and clear sensitive data from memory when possible.
- Validation checks the mathematical properties of the key but does not verify authenticity.

## Best Practices

- Always check the return value before using a key in cryptographic operations.
- Validate input keys before use.
- Do not expose private key material or sensitive data in logs or outputs.
- Use this command as part of key management workflows.

## Validation Details

The command performs the following checks:

### For Private Keys
- Verifies that the key components (n, e, d, p, q) are mathematically consistent
- Checks that the private exponent d is valid
- Validates the Chinese Remainder Theorem (CRT) parameters if present

### For Public Keys
- Verifies that the public key components (n, e) are mathematically consistent
- Checks that the public exponent e is valid
- Validates the key size and format

## See Also
- `tossl::key::generate`
- `tossl::rsa::sign`
- `tossl::rsa::verify`
- `tossl::rsa::components`
- `tossl::dsa::validate`
- `tossl::ec::validate` 