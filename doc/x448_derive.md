# ::tossl::x448::derive

## Overview

The `::tossl::x448::derive` command performs X448 key agreement (ECDH) using a private key and a peer's public key. The result is a shared secret. This command uses the modern OpenSSL API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
::tossl::x448::derive private_key public_key
```

## Parameters

- **private_key**: X448 private key (PEM string)
- **public_key**: X448 public key (PEM string)

## Returns

- Shared secret (byte array)

## Examples

```tcl
set priv1 [tossl::x448::generate]
set priv2 [tossl::x448::generate]
set pub1 [exec openssl pkey -in /dev/stdin -pubout <<< $priv1]
set pub2 [exec openssl pkey -in /dev/stdin -pubout <<< $priv2]
set secret1 [tossl::x448::derive $priv1 $pub2]
set secret2 [tossl::x448::derive $priv2 $pub1]
puts [string equal $secret1 $secret2]  ;# Output: 1 (shared secret matches)
```

## Error Handling

- Throws an error for missing/invalid arguments or malformed input

## OpenSSL Compatibility

- Uses the EVP_PKEY API for robust, future-proof key agreement
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always use the CMS-based commands for new code
- Validate all input data and keys
- Test round-trip key agreement for interoperability 