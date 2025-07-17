# ::tossl::key::getpub

## Overview

The `::tossl::key::getpub` command extracts the public key from a given private key (PEM or DER format). It supports RSA, EC, and DSA keys. The result is the public key in PEM format.

## Syntax

```tcl
::tossl::key::getpub <private_key_data>
```
- `<private_key_data>`: The private key content as a string or byte array (PEM or DER).
- Returns: The corresponding public key in PEM format.

## Examples

### Extract RSA Public Key
```tcl
set keys [tossl::key::generate rsa 2048]
set priv [dict get $keys private]
set pub [tossl::key::getpub $priv]
puts "Public Key: $pub"
```

### Extract EC Public Key
```tcl
set keys [tossl::key::generate ec prime256v1]
set priv [dict get $keys private]
set pub [tossl::key::getpub $priv]
puts "EC Public Key: $pub"
```

### Error Handling
```tcl
if {[catch {tossl::key::getpub "not a key"} err]} {
    puts "Error: $err"
}
```

## Error Handling
- Returns an error if the key cannot be parsed or is not a valid private key.
- Returns an error if the wrong number of arguments is provided.

## Security Considerations
- Do not expose private key material in logs or error messages.
- Only use this command with trusted key material. 