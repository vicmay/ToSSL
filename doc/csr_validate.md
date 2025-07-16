# ::tossl::csr::validate

## Overview

`::tossl::csr::validate` checks the structure and signature of a Certificate Signing Request (CSR). Returns 1 if valid, 0 or error if invalid.

## Syntax

```
::tossl::csr::validate <csr>
```

- `<csr>`: The CSR in PEM format (as returned by `tossl::csr::create`).

## Examples

```
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set csr [tossl::csr::create -key $privkey -subject "CN=example.com"]
set valid [tossl::csr::validate $csr]
puts "CSR valid? $valid"
```

## Error Handling

- Returns 0 or throws error if the CSR is invalid or the signature does not verify
- Throws error if the input is not a valid PEM CSR

## Security Considerations

- Always validate CSRs before using or signing them
- Do not trust CSRs from untrusted sources without validation 