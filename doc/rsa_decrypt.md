# ::tossl::rsa::decrypt

Decrypt data using an RSA private key.

## Overview

`::tossl::rsa::decrypt` decrypts data that was previously encrypted using an RSA public key. It supports both PKCS1 v1.5 and OAEP padding schemes.

## Syntax

```
tossl::rsa::decrypt -key <pem> -data <data> ?-padding <pkcs1|oaep>?
```

- `-key <pem>`: The RSA private key in PEM format.
- `-data <data>`: The encrypted data to decrypt (byte array).
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

- Returns the decrypted data as a Tcl byte array.
- Returns an error if the key or data is missing or invalid.

## Supported Padding Schemes

- `pkcs1` - PKCS#1 v1.5 padding (default)
- `oaep` - Optimal Asymmetric Encryption Padding (recommended)

## Error Handling

- Returns an error if the key is not a valid RSA private key.
- Returns an error if the encrypted data is missing or invalid.
- Returns an error if the padding scheme is invalid.
- Returns an error if the padding scheme doesn't match the one used for encryption.
- Returns an error if the encrypted data is corrupted or was encrypted with a different key.

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material and decrypted data securely.
- The padding scheme must match the one used for encryption.
- Do not expose sensitive decrypted data in logs or outputs.
- Use OAEP padding for new applications when possible.

## Best Practices

- Always check for errors when decrypting data.
- Validate input keys and encrypted data before use.
- Do not expose sensitive key material or decrypted data in logs or outputs.
- Use the same padding scheme that was used for encryption.
- Use hybrid encryption for large data (encrypt a symmetric key with RSA, then use symmetric encryption for the data).

## Common Use Cases

### Hybrid Encryption
```tcl
# Encrypt a symmetric key with RSA
set aes_key [tossl::rand::key -len 32]
set wrapped_key [tossl::rsa::encrypt -key $pub -data $aes_key -padding oaep]

# Encrypt data with AES
set iv [tossl::rand::iv -len 16]
set encrypted_data [tossl::encrypt -alg aes-256-cbc -key $aes_key -iv $iv $data]

# Decrypt the symmetric key
set decrypted_key [tossl::rsa::decrypt -key $priv -data $wrapped_key -padding oaep]

# Decrypt the data
set decrypted_data [tossl::decrypt -alg aes-256-cbc -key $decrypted_key -iv $iv $encrypted_data]
```

### Key Exchange
```tcl
# Generate a session key
set session_key [tossl::rand::key -len 32]

# Encrypt with recipient's public key
set encrypted_key [tossl::rsa::encrypt -key $recipient_pub -data $session_key -padding oaep]

# Recipient decrypts with their private key
set decrypted_key [tossl::rsa::decrypt -key $recipient_priv -data $encrypted_key -padding oaep]
```

## See Also
- `tossl::rsa::encrypt`
- `tossl::key::generate`
- `tossl::rand::key`
- `tossl::encrypt`
- `tossl::decrypt` 