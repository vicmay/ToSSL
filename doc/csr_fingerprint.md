# ::tossl::csr::fingerprint

## Overview

`::tossl::csr::fingerprint` computes a cryptographic fingerprint (hash) of a Certificate Signing Request (CSR). This is useful for verifying the integrity or identity of a CSR, or for referencing it in logs or databases.

## Syntax

```
::tossl::csr::fingerprint <csr> ?-digest <algorithm>?
```

- `<csr>`: The CSR in PEM or DER format (as returned by `tossl::csr::create`).
- `-digest <algorithm>`: (Optional) The hash algorithm to use (e.g., `sha256`, `sha1`). Default is `sha256`.

## Examples

```
set key [tossl::key::generate -type rsa -bits 2048]
set csr [tossl::csr::create -key $key -subject "/CN=Test User"]
set fp [tossl::csr::fingerprint $csr]
puts "CSR fingerprint: $fp"

# Specify digest algorithm
set fp2 [tossl::csr::fingerprint $csr -digest sha1]
puts "CSR fingerprint (SHA1): $fp2"
```

## Error Handling

- If the CSR is invalid or cannot be parsed, an error is thrown.
- If the digest algorithm is not supported, an error is thrown.
- If required arguments are missing, an error is thrown.

## Security Considerations

- Use a strong hash algorithm (e.g., `sha256` or better) for fingerprinting.
- Do not rely on fingerprints for authentication; use them only for integrity or reference.
- Ensure the CSR is obtained from a trusted source before fingerprinting. 