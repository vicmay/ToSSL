# ::tossl::pkcs7::sign

## Overview

The `::tossl::pkcs7::sign` command creates a PKCS#7 (CMS) signature (attached or detached) using the provided certificate and private key. This command uses the modern OpenSSL CMS API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
::tossl::pkcs7::sign -data data -key key -cert cert ?-detached 0|1?
```

## Parameters

- **-data data**: Data to sign (byte array or string)
- **-key key**: PEM private key (string)
- **-cert cert**: PEM certificate (string)
- **-detached 0|1**: 1 for detached signature, 0 for attached (default: 0)

## Returns

- PKCS#7/CMS signature (DER, as a Tcl byte array)

## Examples

### Attached Signature

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set data "signed data"
set sig [tossl::pkcs7::sign -data $data -key $key -cert $cert]
```

### Detached Signature

```tcl
set sig [tossl::pkcs7::sign -data $data -key $key -cert $cert -detached 1]
```

### Round-trip Verification

```tcl
set valid [tossl::pkcs7::verify -ca $cert $sig $data]
puts $valid  ;# Output: 1
```

## Error Handling

- Throws an error for missing/invalid arguments or malformed input

## OpenSSL Compatibility

- Uses the CMS API (`CMS_sign`) for robust, future-proof signatures
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always use the CMS-based commands for new code
- Validate all input data, keys, and certificates
- Test round-trip sign/verify for interoperability 