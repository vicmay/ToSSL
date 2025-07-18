# ::tossl::x509::fingerprint

## Overview

The `::tossl::x509::fingerprint` command computes a cryptographic fingerprint (hash) of an X.509 certificate using a specified digest algorithm. This is useful for certificate identification, trust anchors, certificate pinning, and audit logging.

## Syntax

```tcl
::tossl::x509::fingerprint <certificate> <digest>
```

- `<certificate>`: PEM-encoded X.509 certificate (required)
- `<digest>`: Digest algorithm name (required). Supported: `sha256`, `sha1`, `sha512`, `md5`, etc.

## Returns

A hex-encoded string representing the fingerprint of the certificate.

## Examples

### Basic Usage

```tcl
;# Generate a test certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set cert [tossl::x509::create [dict get $keys private] "/CN=Test" 365]

;# Get SHA256 fingerprint
set fp [tossl::x509::fingerprint $cert sha256]
puts "Certificate fingerprint: $fp"
```

### Different Digest Algorithms

```tcl
;# SHA256 fingerprint (recommended)
set fp_sha256 [tossl::x509::fingerprint $cert sha256]
puts "SHA256: $fp_sha256"

;# SHA1 fingerprint (legacy)
set fp_sha1 [tossl::x509::fingerprint $cert sha1]
puts "SHA1: $fp_sha1"

;# SHA512 fingerprint (high security)
set fp_sha512 [tossl::x509::fingerprint $cert sha512]
puts "SHA512: $fp_sha512"
```

### Certificate Pinning

```tcl
;# Store expected fingerprint
set expected_fp "a1b2c3d4e5f6..."

;# Verify certificate matches expected fingerprint
set actual_fp [tossl::x509::fingerprint $cert sha256]
if {$actual_fp eq $expected_fp} {
    puts "Certificate fingerprint matches"
} else {
    puts "Certificate fingerprint mismatch!"
}
```

### Audit Logging

```tcl
;# Log certificate fingerprint for audit purposes
set fp [tossl::x509::fingerprint $cert sha256]
set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
puts "\[$timestamp\] Certificate processed: $fp"
```

### Error Handling

```tcl
;# Invalid certificate
if {[catch {tossl::x509::fingerprint "not a certificate" sha256} err]} {
    puts "Error: $err"
}

;# Unknown digest algorithm
if {[catch {tossl::x509::fingerprint $cert notadigest} err]} {
    puts "Error: $err"
}

;# Missing arguments
if {[catch {tossl::x509::fingerprint $cert} err]} {
    puts "Error: $err"
}
```

## Error Handling

- Returns an error if the certificate cannot be parsed or is not a valid X.509 certificate.
- Returns an error if the digest algorithm is unknown or not supported.
- Returns an error if required arguments are missing or too many arguments are provided.
- Returns an error if the certificate is in an unsupported format (e.g., DER instead of PEM).

## Security Considerations

- Use strong digest algorithms (e.g., `sha256` or `sha512`) for fingerprinting.
- SHA1 and MD5 are considered cryptographically weak and should be avoided for security-critical applications.
- Fingerprints are deterministic - the same certificate will always produce the same fingerprint with the same algorithm.
- Do not rely on fingerprints alone for authentication; use them in conjunction with a secure trust model.
- Certificate fingerprints are useful for certificate pinning but should be updated when certificates are renewed.

## Best Practices

- Always verify the fingerprint length matches the expected digest output:
  - SHA256: 64 characters
  - SHA1: 40 characters  
  - SHA512: 128 characters
  - MD5: 32 characters
- Use fingerprints for certificate pinning, trust anchors, and audit logs.
- Store fingerprints securely and update them when certificates are renewed.
- Use in conjunction with `::tossl::x509::parse`, `::tossl::x509::validate`, and other certificate validation commands.

## Related Commands

- `::tossl::x509::parse` — Parse certificate information
- `::tossl::x509::validate` — Validate certificate chain
- `::tossl::x509::verify` — Verify certificate signature
- `::tossl::key::fingerprint` — Compute key fingerprint
- `::tossl::csr::fingerprint` — Compute CSR fingerprint

## Troubleshooting

- **Error: Failed to parse certificate**: Ensure the input is a valid PEM-encoded X.509 certificate.
- **Error: Invalid digest algorithm**: Use a supported digest (e.g., `sha256`, `sha1`, `sha512`, `md5`).
- **Error: Failed to calculate fingerprint**: The certificate may be corrupted or in an unsupported format.
- **Unexpected fingerprint length**: Verify the digest algorithm is correct and the certificate is valid.

## Implementation Notes

- The command uses OpenSSL's `X509_digest()` function to compute the fingerprint.
- The fingerprint is calculated over the entire certificate structure, not just the public key.
- The output is always in lowercase hexadecimal format.
- The command only accepts PEM-encoded certificates; DER format is not supported. 