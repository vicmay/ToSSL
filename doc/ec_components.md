# ::tossl::ec::components

Extract curve, public, and (if available) private components from an EC key.

## Overview

`::tossl::ec::components` parses an EC key (public or private) and returns its components as a Tcl dictionary. This is useful for inspecting keys, extracting the curve name, and obtaining the public and private values in hexadecimal form.

## Syntax

```
tossl::ec::components <key>
```

- `<key>`: The EC key in PEM format (public or private).

## Example

```tcl
set curve prime256v1
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set pub [dict get $keys public]
set comps_priv [tossl::ec::components $priv]
set comps_pub [tossl::ec::components $pub]
puts "Private key components: $comps_priv"
puts "Public key components: $comps_pub"
```

## Returned Dictionary

- `curve`: The name of the elliptic curve (e.g., `prime256v1`).
- `public`: The public key point in hexadecimal (uncompressed form).
- `private`: The private key value in hexadecimal (only present if input is a private key).

## Error Handling

- Returns an error if the key is not a valid EC key.
- Returns an error if the key cannot be parsed.

## Security Considerations

- Do not expose private key material in logs or outputs.
- Only use keys generated or obtained from trusted sources.
- Handle all key material securely and clear sensitive data from memory when possible.

## Best Practices

- Always check for the presence of required fields in the returned dictionary.
- Use this command for inspection and debugging, not for cryptographic operations.
- Validate input keys before use.

## See Also
- `tossl::key::generate`
- `tossl::ec::point_multiply`
- `tossl::ec::point_add` 