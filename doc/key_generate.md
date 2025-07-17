# ::tossl::key::generate

## Overview

The `::tossl::key::generate` command creates a new cryptographic key pair. It supports RSA, DSA, and EC (Elliptic Curve) keys. The result is a dictionary containing the private and public keys in PEM format, and metadata fields.

## Syntax

```tcl
::tossl::key::generate ?-type <rsa|dsa|ec>? ?-bits <n>? ?-curve <curve>?
```
- `-type <rsa|dsa|ec>`: Key type (default: rsa)
- `-bits <n>`: Key size in bits (default: 2048 for RSA/DSA)
- `-curve <curve>`: EC curve name (default: prime256v1)
- Returns: Tcl dict with keys `private`, `public`, `type`, `bits`, and for EC, `curve`.

## Examples

### Generate RSA Key (default)
```tcl
set keys [tossl::key::generate]
set priv [dict get $keys private]
set pub [dict get $keys public]
```

### Generate RSA Key (3072 bits)
```tcl
set keys [tossl::key::generate -type rsa -bits 3072]
```

### Generate EC Key (default curve)
```tcl
set keys [tossl::key::generate -type ec]
```

### Generate EC Key (custom curve)
```tcl
set keys [tossl::key::generate -type ec -curve secp384r1]
```

### Generate DSA Key (if supported)
```tcl
if {[catch {set keys [tossl::key::generate -type dsa -bits 1024]} err]} {
    puts "DSA not supported: $err"
} else {
    set priv [dict get $keys private]
    set pub [dict get $keys public]
}
```

### Error Handling
```tcl
if {[catch {tossl::key::generate -type foo} err]} {
    puts "Error: $err"
}
```

## Error Handling
- Returns an error if the type is not supported.
- Returns an error if the bit size is invalid or too small.
- Returns an error if the curve is not supported (for EC).

## Security Considerations
- Always protect private key material.
- Use strong key sizes (2048+ bits for RSA/DSA, recommended curves for EC).
- Do not expose private keys in logs or error messages. 