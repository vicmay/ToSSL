# ::tossl::x509::modify

## Overview

The `::tossl::x509::modify` command modifies an existing X.509 certificate by adding or removing extensions. This is useful for updating certificate metadata such as Subject Alternative Names (SAN) or other X.509 extensions.

## Syntax

```tcl
::tossl::x509::modify -cert <pem> -add_extension <oid> <value> <critical> ?-remove_extension <oid>?
```

- `-cert <pem>`: PEM-encoded X.509 certificate to modify (required)
- `-add_extension <oid> <value> <critical>`: Add an extension by OID (e.g., `subjectAltName`), value (e.g., `DNS:example.com`), and critical flag (`0` or `1`) (required)
- `-remove_extension <oid>`: (Optional) Remove an extension by OID (e.g., `subjectAltName`)

## Returns

A PEM-encoded X.509 certificate string with the requested modifications.

## Examples

### Add a Subject Alternative Name (SAN)
```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365]
set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:example.com" 0]
puts $mod_cert
```

### Add a critical extension
```tcl
set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:critical.example.com" 1]
puts $mod_cert
```

### Remove an extension
```tcl
set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:remove.example.com" 0 -remove_extension subjectAltName]
puts $mod_cert
```

## Error Handling
- Returns an error if required options are missing or invalid
- Returns an error if the certificate is not valid PEM
- Returns an error if the OID is unknown or invalid
- Returns an error if unknown options are provided

## Security Considerations
- Only modify certificates you trust and control
- Do not add untrusted or malicious extensions
- Ensure the modified certificate is validated before use

## Best Practices
- Always validate the modified certificate with `::tossl::x509::parse` and `::tossl::x509::validate`
- Use standard OIDs and values for extensions
- Set the critical flag appropriately for your use case

## Related Commands
- `::tossl::x509::create` — Create a new X.509 certificate
- `::tossl::x509::parse` — Parse certificate information
- `::tossl::x509::validate` — Validate certificate chain
- `::tossl::x509::verify` — Verify certificate signature
- `::tossl::csr::modify` — Modify a certificate signing request

## Troubleshooting
- **Error: failed to parse certificate**: Ensure the certificate is valid PEM
- **Error: unknown extension OID**: Use a valid OID (e.g., `subjectAltName`)
- **Error: missing required option**: Ensure all required options are provided
- **Error: unknown option**: Check for typos in option names 