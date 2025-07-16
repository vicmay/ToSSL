# ::tossl::dsa::verify

Verify a DSA signature using a public key.

## Overview

`::tossl::dsa::verify` checks whether a DSA signature is valid for the given data and public key. It supports specifying the digest algorithm.

## Syntax

```
tossl::dsa::verify -key <pem> -data <data> -sig <signature> ?-alg <digest>?
```

- `-key <pem>`: The DSA public key in PEM format.
- `-data <data>`: The data that was signed (string or byte array).
- `-sig <signature>`: The signature to verify (byte array).
- `-alg <digest>`: (Optional) Digest algorithm (default: sha256).

## Example

```tcl
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "The quick brown fox jumps over the lazy dog"
set sig [tossl::dsa::sign -key $priv -data $data -alg sha256]
set ok [tossl::dsa::verify -key $pub -data $data -sig $sig -alg sha256]
puts "Signature valid: $ok"
```

## Return Value

- Returns `1` (true) if the signature is valid.
- Returns `0` (false) if the signature is invalid.
- Returns an error if the key, data, or signature is missing or invalid.

## Error Handling

- Returns an error if the key is not a valid DSA public key.
- Returns an error if the signature or data is missing or invalid.
- Returns an error if the digest algorithm is unknown.

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material and signatures securely.
- Use strong digest algorithms (e.g., sha256 or better).

## Best Practices

- Always check the return value before trusting a signature.
- Validate input keys and data before use.
- Do not expose sensitive data in logs or outputs.

## See Also
- `tossl::dsa::sign`
- `tossl::key::generate`
- `tossl::dsa::validate` 