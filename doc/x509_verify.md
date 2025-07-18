# ::tossl::x509::verify

## Overview

The `::tossl::x509::verify` command verifies that an X.509 certificate is signed by a specified CA (Certificate Authority) certificate. This is a fundamental operation in PKI (Public Key Infrastructure) for establishing trust in digital certificates.

## Syntax

```tcl
::tossl::x509::verify <certificate> <ca_certificate>
```

- `<certificate>`: PEM-encoded X.509 certificate to verify (required)
- `<ca_certificate>`: PEM-encoded CA certificate that should have signed the certificate (required)

## Return Value

- Returns `1` (true) if the certificate is valid and properly signed by the CA certificate
- Returns `0` (false) if the certificate is invalid, not signed by the CA, or verification fails
- Returns an error if the certificates cannot be parsed or other errors occur

## Examples

### Basic Certificate Verification

```tcl
;# Generate a self-signed certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

set cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
          -pubkey $pub -privkey $priv -days 365]

;# Verify the certificate against itself (self-signed)
set result [tossl::x509::verify $cert $cert]
if {$result} {
    puts "Certificate is valid"
} else {
    puts "Certificate verification failed"
}
```

### Certificate Chain Verification

```tcl
;# Create a CA certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_priv [dict get $ca_keys private]
set ca_pub [dict get $ca_keys public]

set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
             -pubkey $ca_pub -privkey $ca_priv -days 365]

;# Create a certificate signed by the CA
set cert_keys [tossl::key::generate -type rsa -bits 2048]
set cert_pub [dict get $cert_keys public]

set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" \
          -pubkey $cert_pub -privkey $ca_priv -days 365]

;# Verify the certificate against the CA
set valid [tossl::x509::verify $cert $ca_cert]
puts "Certificate valid: $valid"
```

### Verifying Different Key Types

```tcl
;# EC certificate verification
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_priv [dict get $ec_keys private]
set ec_pub [dict get $ec_keys public]

set ec_cert [tossl::x509::create -subject "CN=Test EC" -issuer "CN=Test EC" \
             -pubkey $ec_pub -privkey $ec_priv -days 365]

set ec_valid [tossl::x509::verify $ec_cert $ec_cert]
puts "EC certificate valid: $ec_valid"

;# DSA certificate verification
set dsa_keys [tossl::key::generate -type dsa -bits 2048]
set dsa_priv [dict get $dsa_keys private]
set dsa_pub [dict get $dsa_keys public]

set dsa_cert [tossl::x509::create -subject "CN=Test DSA" -issuer "CN=Test DSA" \
              -pubkey $dsa_pub -privkey $dsa_priv -days 365]

set dsa_valid [tossl::x509::verify $dsa_cert $dsa_cert]
puts "DSA certificate valid: $dsa_valid"
```

### Error Handling

```tcl
;# Handle invalid certificates
if {[catch {
    tossl::x509::verify "invalid certificate" "invalid ca"
} result]} {
    puts "Error: $result"
}

;# Handle missing arguments
if {[catch {
    tossl::x509::verify "some certificate"
} result]} {
    puts "Error: $result"
}

;# Handle wrong CA
set keys1 [tossl::key::generate -type rsa -bits 2048]
set keys2 [tossl::key::generate -type rsa -bits 2048]

set cert [tossl::x509::create -subject "CN=Test" -issuer "CN=CA1" \
          -pubkey [dict get $keys1 public] -privkey [dict get $keys1 private] -days 365]

set wrong_ca [tossl::x509::create -subject "CN=CA2" -issuer "CN=CA2" \
              -pubkey [dict get $keys2 public] -privkey [dict get $keys2 private] -days 365]

set valid [tossl::x509::verify $cert $wrong_ca]
puts "Certificate with wrong CA: $valid (should be 0)"
```

## Error Handling

The command may return errors in the following cases:

- **Invalid certificate format**: If the certificate is not valid PEM format
- **Invalid CA certificate format**: If the CA certificate is not valid PEM format
- **Missing arguments**: If either certificate or CA certificate is not provided
- **Too many arguments**: If more than two arguments are provided
- **Memory allocation failure**: If OpenSSL cannot allocate memory for verification
- **Certificate store creation failure**: If the certificate store cannot be created

## Security Considerations

### Certificate Validation

- **Signature verification**: The command verifies the cryptographic signature of the certificate
- **Public key validation**: Ensures the certificate's public key is properly formatted
- **Certificate structure**: Validates the overall structure and format of the certificate

### Trust Model

- **CA trust**: The verification assumes the CA certificate is trusted
- **No revocation checking**: This command does not check certificate revocation lists (CRL) or OCSP
- **No path validation**: Only verifies direct signature, not full certificate chain validation

### Best Practices

1. **Always verify certificates**: Never trust certificates without verification
2. **Use trusted CA certificates**: Only use CA certificates from trusted sources
3. **Check certificate expiration**: Use `::tossl::x509::time_validate` to check validity periods
4. **Validate certificate purpose**: Ensure the certificate is intended for the intended use
5. **Handle errors gracefully**: Always check return values and handle errors appropriately

## Performance Considerations

- **Cryptographic operations**: Verification involves expensive cryptographic operations
- **Memory usage**: Certificate parsing and verification requires significant memory
- **Batch processing**: For multiple certificates, consider batching operations

## Related Commands

- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::x509::parse` - Parse and extract certificate information
- `::tossl::x509::time_validate` - Validate certificate time validity
- `::tossl::x509::fingerprint` - Generate certificate fingerprints
- `::tossl::x509::modify` - Modify certificate extensions
- `::tossl::key::generate` - Generate key pairs for certificates
- `::tossl::key::parse` - Parse and analyze keys

## Implementation Notes

- Uses OpenSSL's `X509_verify_cert()` function for verification
- Creates a certificate store containing the CA certificate
- Performs full cryptographic signature verification
- Returns boolean result (1 for valid, 0 for invalid)
- Handles memory cleanup automatically

## See Also

- [RFC 5280](https://tools.ietf.org/html/rfc5280) - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- [OpenSSL X.509 Documentation](https://www.openssl.org/docs/man1.1.1/man3/X509_verify_cert.html) 