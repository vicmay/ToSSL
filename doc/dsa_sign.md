# ::tossl::dsa::sign

Sign data using a DSA private key.

## Overview

`::tossl::dsa::sign` creates a DSA signature for the given data using the specified private key. It supports specifying the digest algorithm.

## Syntax

```
tossl::dsa::sign -key <pem> -data <data> ?-alg <digest>?
```

- `-key <pem>`: The DSA private key in PEM format.
- `-data <data>`: The data to sign (string or byte array).
- `-alg <digest>`: (Optional) Digest algorithm (default: sha256).

## Example

```tcl
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set data "The quick brown fox jumps over the lazy dog"
set sig [tossl::dsa::sign -key $priv -data $data -alg sha256]
puts "Signature: $sig"
```

## Return Value

- Returns the signature as a Tcl byte array.
- Returns an error if the key or data is missing or invalid.

## Error Handling

- Returns an error if the key is not a valid DSA private key.
- Returns an error if the data is missing or invalid.
- Returns an error if the digest algorithm is unknown.

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material and signatures securely.
- Use strong digest algorithms (e.g., sha256 or better).

## Best Practices

- Always check for errors when signing data.
- Validate input keys and data before use.
- Do not expose private key material or sensitive data in logs or outputs.

## See Also
- `tossl::dsa::verify`
- `tossl::key::generate`
- `tossl::dsa::validate` 