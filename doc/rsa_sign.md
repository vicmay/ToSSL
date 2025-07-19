# ::tossl::rsa::sign

Sign data using an RSA private key.

## Overview

`::tossl::rsa::sign` creates an RSA signature for the given data using the specified private key. It supports specifying the digest algorithm and padding scheme.

## Syntax

```
tossl::rsa::sign -key <pem> -data <data> ?-alg <digest>? ?-padding <pkcs1|pss>?
```

- `-key <pem>`: The RSA private key in PEM format.
- `-data <data>`: The data to sign (string or byte array).
- `-alg <digest>`: (Optional) Digest algorithm (default: sha256).
- `-padding <pkcs1|pss>`: (Optional) Padding scheme (default: pkcs1).

## Example

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set data "The quick brown fox jumps over the lazy dog"
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256]
puts "Signature: $sig"
```

## Return Value

- Returns the signature as a Tcl byte array.
- Returns an error if the key or data is missing or invalid.

## Supported Digest Algorithms

- `sha1` - SHA-1 (deprecated, use SHA-2 family)
- `sha224` - SHA-224
- `sha256` - SHA-256 (default, recommended)
- `sha384` - SHA-384
- `sha512` - SHA-512
- `md5` - MD5 (deprecated, insecure)

## Supported Padding Schemes

- `pkcs1` - PKCS#1 v1.5 padding (default)
- `pss` - Probabilistic Signature Scheme (PSS) padding

## Error Handling

- Returns an error if the key is not a valid RSA private key.
- Returns an error if the data is missing or invalid.
- Returns an error if the digest algorithm is unknown.
- Returns an error if the padding scheme is invalid.

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material and signatures securely.
- Use strong digest algorithms (e.g., sha256 or better).
- PSS padding provides better security than PKCS#1 v1.5 padding.
- Avoid using deprecated algorithms like MD5 or SHA-1.

## Best Practices

- Always check for errors when signing data.
- Validate input keys and data before use.
- Do not expose private key material or sensitive data in logs or outputs.
- Use PSS padding for new applications when possible.
- Ensure the same digest algorithm and padding scheme are used for both signing and verification.

## See Also
- `tossl::rsa::verify`
- `tossl::key::generate`
- `tossl::rsa::validate` 