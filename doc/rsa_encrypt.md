# ::tossl::rsa::encrypt

Encrypt data using an RSA public key.

## Overview

`::tossl::rsa::encrypt` encrypts data using the specified RSA public key. It supports both PKCS1 v1.5 and OAEP padding schemes.

## Syntax

```
tossl::rsa::encrypt -key <pem> -data <data> ?-padding <pkcs1|oaep>?
```

- `-key <pem>`: The RSA public key in PEM format.
- `-data <data>`: The data to encrypt (string or byte array).
- `-padding <pkcs1|oaep>`: (Optional) Padding scheme (default: pkcs1).

## Example

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set pub [dict get $keys public]
set priv [dict get $keys private]
set plaintext "Hello, RSA!"
set ciphertext [tossl::rsa::encrypt -key $pub -data $plaintext -padding oaep]
set decrypted [tossl::rsa::decrypt -key $priv -data $ciphertext -padding oaep]
puts "Decrypted: $decrypted"
```

## Return Value

- Returns the ciphertext as a Tcl byte array.
- Returns an error if the key or data is missing or invalid.

## Supported Padding Schemes

- `pkcs1` - PKCS#1 v1.5 padding (default)
- `oaep` - Optimal Asymmetric Encryption Padding (recommended)

## Error Handling

- Returns an error if the key is not a valid RSA public key.
- Returns an error if the data is missing or invalid.
- Returns an error if the padding scheme is invalid.

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material and ciphertext securely.
- OAEP padding is recommended for new applications.
- Do not encrypt large data directly; use hybrid encryption (e.g., encrypt a symmetric key with RSA, then use symmetric encryption for the data).

## Best Practices

- Always check for errors when encrypting data.
- Validate input keys and data before use.
- Do not expose sensitive key material or ciphertext in logs or outputs.
- Use OAEP padding for new applications when possible.
- Use hybrid encryption for large data.

## See Also
- `tossl::rsa::decrypt`
- `tossl::key::generate` 