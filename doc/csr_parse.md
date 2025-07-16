# ::tossl::csr::parse

## Overview

`::tossl::csr::parse` extracts information from a Certificate Signing Request (CSR), returning a dictionary with subject, key type, extensions, and other fields.

## Syntax

```
::tossl::csr::parse <csr>
```

- `<csr>`: The CSR in PEM format (as returned by `tossl::csr::create`).

## Examples

```
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set subject [dict create CN example.com O ExampleOrg]
set extensions [list [dict create oid subjectAltName value {DNS:example.com,DNS:www.example.com} critical 0]]
set csr [tossl::csr::create -key $privkey -subject $subject -extensions $extensions]
set info [tossl::csr::parse $csr]
puts "Subject: [dict get $info subject]"
puts "Key type: [dict get $info key_type]"
puts "Extensions: [dict get $info extensions]"
```

## Error Handling

- Throws error if the CSR is invalid or cannot be parsed
- Throws error if the input is not a valid PEM CSR

## Security Considerations

- Always parse and inspect CSRs before using or signing them
- Do not trust CSRs from untrusted sources without validation 