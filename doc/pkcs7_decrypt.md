# ::tossl::pkcs7::decrypt

## Overview

The `::tossl::pkcs7::decrypt` command decrypts a PKCS#7 (CMS) encrypted envelope using the provided private key. This command uses the modern OpenSSL CMS API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
::tossl::pkcs7::decrypt envelope private_key
```

## Parameters

- **envelope**: PKCS#7/CMS envelope (DER, as a Tcl byte array)
- **private_key**: PEM private key (string)

## Returns

- Decrypted data (byte array)

## Examples

### Single Recipient

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set data "secret message"
set encrypted [tossl::pkcs7::encrypt -data $data -cert $cert]
set decrypted [tossl::pkcs7::decrypt $encrypted $key]
puts $decrypted  ;# Output: secret message
```

### Multi-Recipient

```tcl
set encrypted [tossl::pkcs7::encrypt -data $data -cert $cert1 -cert $cert2]
set decrypted1 [tossl::pkcs7::decrypt $encrypted $key1]
set decrypted2 [tossl::pkcs7::decrypt $encrypted $key2]
puts $decrypted1  ;# Output: secret message
puts $decrypted2  ;# Output: secret message
```

## Error Handling

- Throws an error for missing/invalid arguments or malformed input

## OpenSSL Compatibility

- Uses the CMS API (`CMS_decrypt`) for robust, future-proof decryption
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always use the CMS-based commands for new code
- Validate all input data and keys
- Test round-trip encrypt/decrypt for interoperability 