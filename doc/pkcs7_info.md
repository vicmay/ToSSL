# ::tossl::pkcs7::info

## Overview

The `::tossl::pkcs7::info` command extracts and returns structural information about a PKCS#7 (CMS) data structure. This command is useful for analyzing PKCS#7/CMS messages without performing cryptographic operations, allowing you to inspect the type, signers, recipients, and encryption algorithms used in the structure.

**Note:** As of OpenSSL 3.x, the recommended API for PKCS7-style envelopes is the CMS API (`CMS_encrypt`, `CMS_decrypt`). The TOSSL implementation uses CMS for all envelope operations, ensuring compatibility with OpenSSL CLI and modern cryptographic standards. Legacy PKCS7 APIs are deprecated and not recommended for new code.

## Syntax

```tcl
::tossl::pkcs7::info pkcs7_data
```

## Parameters

- **pkcs7_data** (required): The PKCS#7 or CMS envelope data (DER or PEM, as a Tcl byte array)

## Examples

### Extracting Info from an Encrypted Envelope

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set data "test123"
set encrypted [tossl::pkcs7::encrypt -data $data -cert $cert]
set info [tossl::pkcs7::info $encrypted]
puts $info
# Output: type pkcs7-envelopedData num_recipients 1 cipher AES-256-CBC
```

### Round-trip Decrypt

```tcl
set decrypted [tossl::pkcs7::decrypt $encrypted $key]
puts $decrypted  ;# Output: test123
```

## Error Handling

- If the input is not a valid PKCS7/CMS envelope, an error is thrown.
- If the envelope is encrypted and the key is incorrect, decryption will fail.

## Security Considerations

- Always validate the source of PKCS7/CMS data before processing.
- Use only strong ciphers and keys (default is AES-256-CBC).
- The CMS API is robust and maintained; avoid legacy PKCS7 APIs for new code.

## Best Practices

- Use the CMS-based commands for all new envelope operations.
- Test round-trip compatibility with OpenSSL CLI if interoperability is required.
- Store and transmit PKCS7/CMS data as binary (DER) for maximum compatibility. 