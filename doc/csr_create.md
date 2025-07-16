# ::tossl::csr::create

## Overview

`::tossl::csr::create` generates a Certificate Signing Request (CSR) using a subject, public key, and private key. Optionally, Subject Alternative Names (SANs) and key usage extensions can be included.

## Syntax

```
::tossl::csr::create -subject <dn> -pubkey <pem> -privkey <pem> ?-san {dns1 dns2 ...}? ?-keyusage {usage1 usage2 ...}?
```

- `-subject <dn>`: Subject distinguished name (e.g., `CN=example.com`)
- `-pubkey <pem>`: Public key in PEM format
- `-privkey <pem>`: Private key in PEM format (must match public key)
- `-san {dns1 dns2 ...}`: (Optional) Subject Alternative Names
- `-keyusage {usage1 usage2 ...}`: (Optional) Key usage extensions

## Examples

```
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]
set csr [tossl::csr::create -subject "CN=example.com" -pubkey $pubkey -privkey $privkey]
puts "CSR: $csr"

# With SAN and key usage
set csr2 [tossl::csr::create -subject "CN=alt.example.com" -pubkey $pubkey -privkey $privkey -san {alt.example.com www.alt.example.com} -keyusage {digitalSignature keyEncipherment}]
puts "CSR2: $csr2"
```

## Error Handling

- Errors if required arguments are missing or invalid
- Errors if the keys are not valid PEM or do not match
- Errors if the subject is not in a supported format

## Security Considerations

- Always use strong keys (2048+ bits for RSA)
- Ensure the private key is kept secure and never shared
- Validate the CSR before submitting to a CA 