# ::tossl::key::convert

## Overview

The `::tossl::key::convert` command converts cryptographic keys between PEM and DER formats, and between private and public key types. This is useful for interoperability, storage, and transport of keys in different environments.

## Syntax

```tcl
::tossl::key::convert -key <key> -from <pem|der> -to <pem|der> -type <private|public>
```

- `-key <key>`: The key data (PEM or DER, private or public)
- `-from <pem|der>`: Input format
- `-to <pem|der>`: Output format
- `-type <private|public>`: Key type

**Note:** DER keys are handled as Tcl byte array objects, not strings. Always use binary-safe operations when working with DER or PKCS8 data.

## Returns

The converted key in the specified output format as a string (PEM) or byte array (DER).

## Examples

### Convert PEM to DER

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set der [tossl::key::convert -key $priv -from pem -to der -type private]
puts "DER length: [string length $der]"
```

### Convert DER to PEM

```tcl
set pem [tossl::key::convert -key $der -from der -to pem -type private]
puts $pem
```

### Convert Public Key

```tcl
set pub [dict get $keys public]
set der_pub [tossl::key::convert -key $pub -from pem -to der -type public]
set pem_pub [tossl::key::convert -key $der_pub -from der -to pem -type public]
puts $pem_pub
```

### Error Handling

```tcl
# Invalid key data
if {[catch {tossl::key::convert -key "not a key" -from pem -to der -type private} err]} {
    puts "Error: $err"
}

# Unknown format or type
if {[catch {tossl::key::convert -key $priv -from foo -to der -type private} err]} {
    puts "Error: $err"
}
```

## Error Handling

- Returns an error if the key cannot be parsed or converted.
- Returns an error if the format or type is unknown.
- Returns an error if required arguments are missing or too many arguments are provided.

## Security Considerations

- Do not expose private key material in logs or error messages.
- Use secure storage and transport for private keys.

## Best Practices

- Always use byte array objects for DER/PKCS8 data.
- Validate key type and format before conversion.
- Handle errors gracefully and securely.

## Related Commands

- `::tossl::key::generate` — Generate a new key pair
- `::tossl::key::analyze` — Inspect key properties
- `::tossl::key::write` — Serialize a key
- `::tossl::key::fingerprint` — Compute a key fingerprint

## Troubleshooting

- **Error: Failed to parse key**: Ensure the input is a valid PEM or DER encoded key.
- **Error: Unknown format or type**: Use supported values for `-from`, `-to`, and `-type`. 