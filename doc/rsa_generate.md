# ::tossl::rsa::generate

Generate an RSA key pair.

## Overview

`::tossl::rsa::generate` creates a new RSA key pair using cryptographically secure random number generation. It returns both the private and public keys in PEM format.

## Syntax

```
tossl::rsa::generate ?-bits <bits>?
```

- `-bits <bits>`: (Optional) Key size in bits (default: 2048).

## Example

```tcl
# Generate RSA key pair with default 2048 bits
set keys [tossl::rsa::generate]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Generate RSA key pair with 3072 bits
set keys [tossl::rsa::generate -bits 3072]
set priv [dict get $keys private]
set pub [dict get $keys public]
```

## Return Value

Returns a dictionary containing:

- `private` - The RSA private key in PEM format
- `public` - The RSA public key in PEM format

## Supported Key Sizes

- `1024` - 1024 bits (deprecated, not recommended for new applications)
- `2048` - 2048 bits (default, recommended minimum)
- `3072` - 3072 bits (recommended for high security)
- `4096` - 4096 bits (high security, slower operations)

## Error Handling

- Returns an error if the bit size is invalid or too small.
- Returns an error if the key generation fails.
- Returns an error if memory allocation fails.

## Security Considerations

- **Key Size**: Use at least 2048 bits for new applications. 1024-bit keys are considered insecure.
- **Random Number Generation**: The command uses OpenSSL's cryptographically secure random number generator.
- **Key Storage**: Store private keys securely and never expose them in logs or outputs.
- **Key Validation**: Always validate generated keys before use in production.

## Best Practices

- Use 2048 bits or larger for new applications.
- Validate generated keys using `tossl::rsa::validate`.
- Store private keys securely with appropriate access controls.
- Use the generated keys with other RSA commands for encryption, decryption, signing, and verification.
- Do not expose private key material in logs or error messages.

## Key Validation

After generating keys, validate them to ensure they are properly formed:

```tcl
set keys [tossl::rsa::generate -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Validate the keys
set valid_priv [tossl::rsa::validate -key $priv]
set valid_pub [tossl::rsa::validate -key $pub]

if {$valid_priv && $valid_pub} {
    puts "Keys are valid"
} else {
    puts "Keys are invalid"
}
```

## Key Functionality Testing

Test the generated keys with encryption and signing operations:

```tcl
set keys [tossl::rsa::generate -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Test encryption/decryption
set data "Hello, RSA!"
set ciphertext [tossl::rsa::encrypt -key $pub -data $data -padding oaep]
set decrypted [tossl::rsa::decrypt -key $priv -data $ciphertext -padding oaep]

# Test signing/verification
set signature [tossl::rsa::sign -key $priv -data $data -alg sha256]
set verified [tossl::rsa::verify -key $pub -data $data -sig $signature -alg sha256]
```

## Performance Considerations

- Larger key sizes provide better security but slower operations.
- 2048-bit keys offer a good balance of security and performance.
- Key generation time increases with key size.
- Consider the intended use case when choosing key size.

## See Also
- `tossl::rsa::validate`
- `tossl::rsa::encrypt`
- `tossl::rsa::decrypt`
- `tossl::rsa::sign`
- `tossl::rsa::verify`
- `tossl::rsa::components`
- `tossl::key::generate` 