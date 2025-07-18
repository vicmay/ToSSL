# ::tossl::x509::create

## Overview

The `::tossl::x509::create` command creates and signs an X.509 certificate. It supports self-signed and CA-signed certificates, Subject Alternative Names (SAN), and key usage extensions.

## Syntax

```tcl
::tossl::x509::create -subject <dn> -issuer <dn> -pubkey <pem> -privkey <pem> -days <n> ?-san {dns1 dns2 ...}? ?-keyusage {usage1 usage2 ...}?
```

- `-subject <dn>`: Subject common name (CN) for the certificate (required)
- `-issuer <dn>`: Issuer common name (CN) (required; for self-signed, use same as subject)
- `-pubkey <pem>`: Public key in PEM format (required)
- `-privkey <pem>`: Private key in PEM format (required; for CA-signed, use CA's private key)
- `-days <n>`: Validity period in days (required)
- `-san {dns1 dns2 ...}`: (Optional) Subject Alternative Names (DNS names, IPs)
- `-keyusage {usage1 usage2 ...}`: (Optional) Key usage extensions (see below)

## Returns

A PEM-encoded X.509 certificate as a string.

## Examples

### Self-signed Certificate
```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365]
puts $cert
```

### Certificate with SAN
```tcl
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -san {example.com www.example.com 127.0.0.1}]
puts $cert
```

### Certificate with Key Usage
```tcl
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -keyusage {digitalSignature keyEncipherment}]
puts $cert
```

### CA-signed Certificate
```tcl
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_priv [dict get $ca_keys private]
set ca_pub [dict get $ca_keys public]
set ca_cert [tossl::x509::create -subject "Test CA" -issuer "Test CA" -pubkey $ca_pub -privkey $ca_priv -days 3650]
set user_cert [tossl::x509::create -subject "User" -issuer "Test CA" -pubkey $pub -privkey $ca_priv -days 365]
puts $user_cert
```

## Key Usage Values
- digitalSignature
- nonRepudiation
- keyEncipherment
- dataEncipherment
- keyAgreement
- keyCertSign
- cRLSign
- encipherOnly
- decipherOnly

## Error Handling
- Returns an error if required options are missing or invalid
- Returns an error if keys are not valid PEM or do not match
- Returns an error if days is not a positive integer
- Returns an error if unknown options are provided

## Security Considerations
- Always use strong keys (2048+ bits for RSA)
- Protect private keys and never expose them
- Use appropriate key usage and SAN values for your use case
- For CA-signed certificates, ensure the CA private key is kept secure

## Best Practices
- Use unique serial numbers for production certificates (this implementation uses 1 by default)
- Validate generated certificates with `::tossl::x509::parse` and `::tossl::x509::validate`
- Use in conjunction with `::tossl::key::generate`, `::tossl::ca::generate`, and `::tossl::ca::sign` for full PKI workflows

## Related Commands
- `::tossl::x509::parse` — Parse certificate information
- `::tossl::x509::validate` — Validate certificate chain
- `::tossl::x509::verify` — Verify certificate signature
- `::tossl::ca::generate` — Generate CA certificate
- `::tossl::ca::sign` — Sign certificates with a CA
- `::tossl::csr::create` — Create certificate signing requests

## Troubleshooting
- **Error: failed to parse key(s)**: Ensure the keys are valid PEM and match the certificate type
- **Error: certificate signing failed**: Check that the private key matches the issuer and is valid
- **Error: missing required option**: Ensure all required options are provided
- **Error: unknown option**: Check for typos in option names 