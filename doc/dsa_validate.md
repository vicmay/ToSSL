# ::tossl::dsa::validate

Validate a DSA key (public or private).

## Overview

`::tossl::dsa::validate` checks whether the provided DSA key (in PEM format) is valid and well-formed. It works for both public and private keys, and returns a boolean result.

## Syntax

```
tossl::dsa::validate -key <pem>
```

- `-key <pem>`: The DSA key in PEM format (public or private).

## Example

```tcl
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set valid_priv [tossl::dsa::validate -key $priv]
set valid_pub [tossl::dsa::validate -key $pub]
puts "Private key valid: $valid_priv"
puts "Public key valid: $valid_pub"
```

## Return Value

- Returns `1` (true) if the key is valid.
- Returns `0` (false) if the key is invalid (but parseable as DSA).
- Returns an error if the key cannot be parsed or is not a DSA key.

## Error Handling

- Returns an error if the key is not a valid DSA key.
- Returns an error if the key cannot be parsed (e.g., truncated or corrupted).

## Security Considerations

- Only use keys generated or obtained from trusted sources.
- Handle all key material securely and clear sensitive data from memory when possible.

## Best Practices

- Always check the return value before using a key in cryptographic operations.
- Validate input keys before use.
- Do not expose private key material or sensitive data in logs or outputs.

## See Also
- `tossl::key::generate`
- `tossl::dsa::sign`
- `tossl::dsa::verify` 