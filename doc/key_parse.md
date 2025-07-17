# ::tossl::key::parse

Parse a PEM or DER encoded key and return its type and properties.

## Syntax

    tossl::key::parse <pem|der>

- `<pem|der>`: The key data, as a PEM string or DER byte array (private or public)

## Description

Parses a key (private or public) in PEM or DER format and returns a Tcl dict describing its type, kind (private/public), bit length, and for EC keys, the curve name. Supports RSA, EC, and DSA keys as available from the OpenSSL default provider.

## Output

Returns a Tcl dict with the following keys:
- `type`: Key type (`rsa`, `ec`, `dsa`, or `unknown`)
- `kind`: `private` or `public`
- `bits`: Key size in bits
- `curve`: (for EC keys) the curve name

## Examples

```tcl
set rsa [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $rsa private]
set pub [dict get $rsa public]

# Parse private PEM
set info [tossl::key::parse $priv]
# Parse public PEM
set info [tossl::key::parse $pub]
# Parse private DER
set priv_der [tossl::key::write -key $priv -format der -type private]
set info [tossl::key::parse $priv_der]
# Parse public DER
set pub_der [tossl::key::write -key $pub -format der -type public]
set info [tossl::key::parse $pub_der]
```

## Error Handling

- Returns an error if the key cannot be parsed or is not supported.
- Returns an error for corrupted or invalid input.

## Security Notes

- Only default provider algorithms are supported (RSA, EC, DSA, etc. as available).
- No legacy/old-style key formats are supported.
- Always protect private key material. 