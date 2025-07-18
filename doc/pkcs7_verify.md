# ::tossl::pkcs7::verify

## Overview

The `::tossl::pkcs7::verify` command verifies a PKCS#7 (CMS) signature (attached or detached) using the provided CA certificate. This command uses the modern OpenSSL CMS API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
::tossl::pkcs7::verify -ca ca_cert pkcs7_signature data
```

## Parameters

- **-ca ca_cert**: PEM CA certificate (string)
- **pkcs7_signature**: PKCS#7/CMS signature (DER or PEM, as a Tcl byte array)
- **data**: Data to verify (byte array or string)

## Returns

- `1` if the signature is valid
- `0` if the signature is invalid

## Examples

### Attached Signature

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set data "signed data"
set sig [tossl::pkcs7::sign -data $data -key $key -cert $cert]
set valid [tossl::pkcs7::verify -ca $cert $sig $data]
puts $valid  ;# Output: 1
```

### Detached Signature

```tcl
set sig [tossl::pkcs7::sign -data $data -key $key -cert $cert -detached 1]
set valid [tossl::pkcs7::verify -ca $cert $sig $data]
puts $valid  ;# Output: 1
```

## Error Handling

- Returns `0` for invalid signatures
- Throws an error for missing/invalid arguments or malformed input

## OpenSSL Compatibility

- Uses the CMS API (`CMS_verify`) for robust, future-proof verification
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always use the CMS-based commands for new code
- Validate all input data and certificates
- Test round-trip sign/verify for interoperability 