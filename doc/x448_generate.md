# ::tossl::x448::generate

## Overview

The `::tossl::x448::generate` command generates a new X448 private key (for key agreement). The key is returned in PEM format. This command uses the modern OpenSSL API and is compatible with OpenSSL 3.x and the OpenSSL CLI.

## Syntax

```tcl
::tossl::x448::generate
```

## Parameters

- (none)

## Returns

- X448 private key (PEM string)

## Examples

```tcl
set priv [tossl::x448::generate]
puts $priv
```

## Error Handling

- Throws an error if key generation fails

## OpenSSL Compatibility

- Uses the EVP_PKEY API for robust, future-proof key generation
- Fully compatible with OpenSSL 3.x and the OpenSSL CLI

## Best Practices

- Always use the CMS-based commands for new code
- Validate all input data and keys
- Test round-trip key agreement for interoperability 