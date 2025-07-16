# ::tossl::csr::modify

**Modify a Certificate Signing Request (CSR) by adding or changing extensions.**

## Syntax

```tcl
::tossl::csr::modify -csr <pem> -addext <extension>
```

- `-csr <pem>`: PEM-encoded CSR to modify
- `-addext <extension>`: Extension to add (e.g., "subjectAltName=DNS:example.com")

## Returns
Modified PEM-encoded CSR.

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if CSR is invalid or not supported in this build.

## Security Considerations

- Only modify CSRs you trust.
- Ensure extensions are valid and appropriate for your use case.

## See Also
- [csr::parse](csr_parse.md)
- [csr::create](csr_create.md) 