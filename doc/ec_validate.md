# ::tossl::ec::validate

Validate an elliptic curve (EC) key (public or private).

## Overview

`::tossl::ec::validate` checks whether the provided EC key (in PEM format) is valid and well-formed. It works for both public and private keys, and returns a boolean result.

## Syntax

```
tossl::ec::validate <key>
```

- `<key>`: The EC key in PEM format (public or private).

## Example

```tcl
set curve prime256v1
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set pub [dict get $keys public]
set valid_priv [tossl::ec::validate $priv]
set valid_pub [tossl::ec::validate $pub]
puts "Private key valid: $valid_priv"
puts "Public key valid: $valid_pub"
```

## Return Value

- Returns `1` (true) if the key is valid.
- Returns `0` (false) if the key is invalid (but parseable as EC).
- Returns an error if the key cannot be parsed or is not an EC key.

## Error Handling

- Returns an error if the key is not a valid EC key.
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
- `tossl::ec::components`
- `tossl::ec::point_add` 