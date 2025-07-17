# ::tossl::key::analyze

## Overview

The `::tossl::key::analyze` command inspects a PEM or DER encoded cryptographic key (private or public) and returns a dictionary describing its type, size, and other properties. This is useful for auditing, validation, and automation in cryptographic workflows.

## Syntax

```tcl
::tossl::key::analyze <key_pem_or_der>
```

- `<key_pem_or_der>`: The PEM or DER encoded key (private or public).

## Returns

A Tcl dict with the following fields:
- `type`: Key type (`rsa`, `dsa`, `ec`, or `unknown`)
- `kind`: `private` or `public`
- `bits`: Key size in bits (integer)
- `curve`: (for EC keys) Curve name (string)

## Examples

### Analyze RSA Key

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set info_priv [tossl::key::analyze $priv]
set info_pub [tossl::key::analyze $pub]
puts "Private: $info_priv"
puts "Public: $info_pub"
```

### Analyze EC Key

```tcl
set keys [tossl::key::generate -type ec -curve prime256v1]
set priv [dict get $keys private]
set pub [dict get $keys public]
set info_priv [tossl::key::analyze $priv]
set info_pub [tossl::key::analyze $pub]
puts "EC Private: $info_priv"
puts "EC Public: $info_pub"
```

### Analyze DSA Key (if supported)

```tcl
set keys [tossl::key::generate -type dsa -bits 1024]
set priv [dict get $keys private]
set pub [dict get $keys public]
set info_priv [tossl::key::analyze $priv]
set info_pub [tossl::key::analyze $pub]
puts "DSA Private: $info_priv"
puts "DSA Public: $info_pub"
```

### Error Handling

```tcl
# Invalid key data
if {[catch {tossl::key::analyze "not a key"} err]} {
    puts "Error: $err"
}

# Empty string
if {[catch {tossl::key::analyze ""} err]} {
    puts "Error: $err"
}
```

## Error Handling

- Returns an error if the key cannot be parsed.
- Returns an error if the wrong number of arguments is provided.

## Security Considerations

- Do not expose private key material in logs or error messages.
- Use this command to validate key properties before use in cryptographic operations.

## Best Practices

- Always check the `type` and `bits` fields to ensure key strength and compatibility.
- For EC keys, verify the `curve` matches your security requirements.
- Use in conjunction with `::tossl::key::generate`, `::tossl::key::write`, and other key management commands.

## Related Commands

- `::tossl::key::generate` — Generate a new key pair
- `::tossl::key::write` — Serialize a key to PEM or DER
- `::tossl::key::convert` — Convert key formats
- `::tossl::key::fingerprint` — Compute a key fingerprint

## Troubleshooting

- **Error: Failed to parse key**: Ensure the input is a valid PEM or DER encoded key.
- **Unknown key type**: The key may use an unsupported algorithm or be malformed. 