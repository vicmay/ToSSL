# ::tossl::ca::sign

Sign a Certificate Signing Request (CSR) with a Certificate Authority (CA) to create a digital certificate.

## Overview

`::tossl::ca::sign` is a Certificate Authority (CA) command that signs Certificate Signing Requests (CSRs) to create valid X.509 digital certificates. This command is essential for establishing certificate hierarchies, creating end-entity certificates, and implementing Public Key Infrastructure (PKI) systems.

The command takes a CSR, a CA private key, and a CA certificate as input, and produces a signed certificate that can be used for SSL/TLS connections, code signing, document signing, and other cryptographic applications.

## Syntax

```tcl
::tossl::ca::sign -ca_key ca_private_key -ca_cert ca_certificate -csr certificate_signing_request ?-days validity_days?
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ca_key` | string | Yes | CA private key in PEM format |
| `-ca_cert` | string | Yes | CA certificate in PEM format |
| `-csr` | string | Yes | Certificate Signing Request in PEM format |
| `-days` | integer | No | Certificate validity period in days (default: 365) |

### Return Value

Returns a signed X.509 certificate in PEM format.

## Examples

### Basic Certificate Signing

```tcl
# Generate CA key and certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_public [dict get $ca_keys public]

# Create CA certificate
set ca_cert [tossl::x509::create -subject "CN=My CA" -issuer "CN=My CA" \
    -pubkey $ca_public -privkey $ca_private -days 365]

# Generate CSR key and create CSR
set csr_keys [tossl::key::generate -type rsa -bits 2048]
set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=www.example.com"]

# Sign the CSR to create a certificate
set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]

puts "Certificate created successfully"
puts "Certificate length: [string length $signed_cert] bytes"
```

### Server Certificate Creation

```tcl
# Generate CA infrastructure
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_cert [tossl::x509::create -subject "CN=Server CA" -issuer "CN=Server CA" \
    -pubkey [dict get $ca_keys public] -privkey [dict get $ca_keys private] -days 365]

# Create server CSR
set server_keys [tossl::key::generate -type rsa -bits 2048]
set server_csr [tossl::csr::create -key [dict get $server_keys private] \
    -subject "CN=server.example.com,O=Example Corp,C=US"]

# Sign server certificate
set server_cert [tossl::ca::sign -ca_key [dict get $ca_keys private] \
    -ca_cert $ca_cert -csr $server_csr -days 365]

# Save certificate to file
set f [open "server.crt" w]
puts $f $server_cert
close $f

puts "Server certificate saved to server.crt"
```

### Certificate Chain Creation

```tcl
# Generate root CA
set root_keys [tossl::key::generate -type rsa -bits 4096]
set root_cert [tossl::x509::create -subject "CN=Root CA" -issuer "CN=Root CA" \
    -pubkey [dict get $root_keys public] -privkey [dict get $root_keys private] -days 3650]

# Generate intermediate CA CSR
set int_keys [tossl::key::generate -type rsa -bits 2048]
set int_csr [tossl::csr::create -key [dict get $int_keys private] -subject "CN=Intermediate CA"]

# Sign intermediate CA certificate
set int_cert [tossl::ca::sign -ca_key [dict get $root_keys private] \
    -ca_cert $root_cert -csr $int_csr -days 1825]

# Generate end entity CSR
set end_keys [tossl::key::generate -type rsa -bits 2048]
set end_csr [tossl::csr::create -key [dict get $end_keys private] -subject "CN=end.example.com"]

# Sign end entity certificate with intermediate CA
set end_cert [tossl::ca::sign -ca_key [dict get $int_keys private] \
    -ca_cert $int_cert -csr $end_csr -days 365]

puts "Certificate chain created:"
puts "  Root CA -> Intermediate CA -> End Entity"
```

### Different Validity Periods

```tcl
# Generate CA infrastructure
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
    -pubkey [dict get $ca_keys public] -privkey [dict get $ca_keys private] -days 365]

# Create CSR
set csr_keys [tossl::key::generate -type rsa -bits 2048]
set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=test.example.com"]

# Sign with different validity periods
set periods {30 90 365 730 1825}

foreach days $periods {
    set cert [tossl::ca::sign -ca_key [dict get $ca_keys private] \
        -ca_cert $ca_cert -csr $csr -days $days]
    
    puts "Certificate with $days days validity created"
}
```

### Cross-Key-Type Signing

```tcl
# Generate RSA CA
set rsa_ca_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_ca_cert [tossl::x509::create -subject "CN=RSA CA" -issuer "CN=RSA CA" \
    -pubkey [dict get $rsa_ca_keys public] -privkey [dict get $rsa_ca_keys private] -days 365]

# Generate EC CSR
set ec_csr_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_csr [tossl::csr::create -key [dict get $ec_csr_keys private] -subject "CN=ec.example.com"]

# Sign EC CSR with RSA CA
set ec_cert [tossl::ca::sign -ca_key [dict get $rsa_ca_keys private] \
    -ca_cert $rsa_ca_cert -csr $ec_csr -days 365]

puts "EC certificate signed with RSA CA successfully"
```

### Certificate Validation

```tcl
# Generate and sign certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
    -pubkey [dict get $ca_keys public] -privkey [dict get $ca_keys private] -days 365]

set csr_keys [tossl::key::generate -type rsa -bits 2048]
set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=test.example.com"]

set signed_cert [tossl::ca::sign -ca_key [dict get $ca_keys private] \
    -ca_cert $ca_cert -csr $csr -days 365]

# Validate the signed certificate
if {[catch {tossl::x509::validate $signed_cert} result]} {
    puts "Certificate validation failed: $result"
} else {
    puts "Certificate validation successful"
}

# Parse certificate details
if {[catch {tossl::x509::parse $signed_cert} cert_info]} {
    puts "Certificate parsing failed: $cert_info"
} else {
    puts "Certificate parsing successful"
}
```

### Error Handling

```tcl
# Handle missing parameters
if {[catch {tossl::ca::sign -ca_key "key" -ca_cert "cert"} result]} {
    puts "Error: $result"
}

# Handle invalid CA key
if {[catch {tossl::ca::sign -ca_key "invalid-key" -ca_cert $ca_cert -csr $csr} result]} {
    puts "CA key error: $result"
}

# Handle invalid CA certificate
if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert "invalid-cert" -csr $csr} result]} {
    puts "CA certificate error: $result"
}

# Handle invalid CSR
if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr "invalid-csr"} result]} {
    puts "CSR error: $result"
}
```

### Performance Testing

```tcl
# Generate CA infrastructure once
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
    -pubkey [dict get $ca_keys public] -privkey [dict get $ca_keys private] -days 365]

set start_time [clock milliseconds]

# Sign multiple certificates
for {set i 0} {$i < 10} {incr i} {
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] \
        -subject "CN=server$i.example.com"]
    
    set cert [tossl::ca::sign -ca_key [dict get $ca_keys private] \
        -ca_cert $ca_cert -csr $csr -days 365]
    
    puts "Certificate $i created"
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "Created 10 certificates in ${duration}ms"
puts "Average time per certificate: [expr {double($duration) / 10}]ms"
```

## Certificate Properties

### Automatically Added Extensions

The signed certificate includes several standard extensions:

1. **Basic Constraints**: Indicates whether the certificate can be used as a CA
2. **Key Usage**: Specifies the allowed uses of the public key
3. **Subject Alternative Name**: Extends the subject name (if present in CSR)
4. **Authority Key Identifier**: Links to the CA's public key
5. **Subject Key Identifier**: Identifies the certificate's public key

### Certificate Structure

The signed certificate contains:

- **Version**: X.509 v3
- **Serial Number**: Unique identifier for the certificate
- **Subject**: From the CSR
- **Issuer**: From the CA certificate
- **Validity Period**: Based on the `-days` parameter
- **Public Key**: From the CSR
- **Signature**: Created using the CA's private key
- **Extensions**: Standard X.509 extensions

### Supported Key Types

The command supports signing CSRs with various key types:

- **RSA**: 1024, 2048, 4096 bits
- **EC**: Various curves (prime256v1, secp384r1, etc.)
- **Cross-key signing**: RSA CA can sign EC CSRs and vice versa

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "CA key, CA certificate, and CSR are required" | Missing required parameters | Provide all required parameters |
| "Failed to parse CA private key" | Invalid CA key format | Ensure CA key is valid PEM format |
| "Failed to parse CA certificate" | Invalid CA certificate format | Ensure CA certificate is valid PEM format |
| "Failed to parse CSR" | Invalid CSR format | Ensure CSR is valid PEM format |
| "Failed to sign certificate" | Internal signing error | Check CA key and certificate compatibility |

### Error Handling Examples

```tcl
# Robust certificate signing with error handling
proc sign_certificate_safely {ca_key ca_cert csr days} {
    if {[catch {
        tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days $days
    } result]} {
        puts "Certificate signing failed: $result"
        return ""
    } else {
        puts "Certificate signing successful"
        return $result
    }
}

# Usage
set cert [sign_certificate_safely $ca_private $ca_cert $csr 365]
if {$cert ne ""} {
    puts "Certificate created: [string length $cert] bytes"
} else {
    puts "Certificate creation failed"
}
```

## Security Considerations

### CA Key Security

1. **Key Protection**: CA private keys must be kept secure and confidential
2. **Key Storage**: Use hardware security modules (HSMs) for production CAs
3. **Key Rotation**: Implement regular CA key rotation procedures
4. **Access Control**: Limit access to CA private keys to authorized personnel

### Certificate Security

1. **Validity Periods**: Choose appropriate validity periods based on security requirements
2. **Key Sizes**: Use appropriate key sizes (RSA 2048+ bits, EC 256+ bits)
3. **Revocation**: Implement certificate revocation procedures
4. **Monitoring**: Monitor certificate usage and detect anomalies

### Best Practices

1. **Certificate Hierarchy**: Use multi-level certificate hierarchies for large deployments
2. **Naming Conventions**: Use consistent naming conventions for certificates
3. **Documentation**: Maintain documentation of certificate issuance procedures
4. **Audit Trail**: Keep logs of all certificate signing operations

## Integration with Other Commands

### With CSR Commands

```tcl
# Create and sign CSR in one workflow
set keys [tossl::key::generate -type rsa -bits 2048]
set csr [tossl::csr::create -key [dict get $keys private] -subject "CN=example.com"]

# Validate CSR before signing
if {[catch {tossl::csr::validate $csr} result]} {
    puts "CSR validation failed: $result"
} else {
    set cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    puts "Certificate signed successfully"
}
```

### With Certificate Commands

```tcl
# Sign certificate and immediately validate
set cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]

# Parse certificate details
set cert_info [tossl::x509::parse $cert]
puts "Subject: [dict get $cert_info subject]"
puts "Issuer: [dict get $cert_info issuer]"
puts "Valid until: [dict get $cert_info not_after]"

# Get certificate fingerprint
set fingerprint [tossl::x509::fingerprint $cert sha256]
puts "SHA-256 fingerprint: $fingerprint"
```

### With SSL Commands

```tcl
# Create certificate for SSL server
set server_keys [tossl::key::generate -type rsa -bits 2048]
set server_csr [tossl::csr::create -key [dict get $server_keys private] \
    -subject "CN=ssl.example.com"]

set server_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert \
    -csr $server_csr -days 365]

# Use in SSL context
set ctx [tossl::ssl::context create]
# ... configure SSL context with certificate and key
```

## Performance Characteristics

### Time Complexity

- **Single signing**: O(1) for basic operations
- **Batch signing**: Linear with number of certificates
- **Key size impact**: Larger keys require more time

### Memory Usage

- **Minimal overhead**: Only temporary storage for certificate creation
- **No persistent state**: Each operation is independent

### Performance Benchmarks

Typical performance characteristics:
- **RSA 2048-bit signing**: ~50-100ms per certificate
- **EC signing**: ~20-50ms per certificate
- **Batch operations**: ~500ms for 10 certificates

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's X.509 and EVP APIs
2. **Memory Management**: Properly frees all OpenSSL objects
3. **Error Handling**: Comprehensive error checking and reporting
4. **Extension Handling**: Automatically adds standard X.509 extensions

### Certificate Format

- **Output Format**: PEM (Privacy-Enhanced Mail) format
- **Encoding**: Base64-encoded DER data
- **Headers**: Standard X.509 certificate headers and footers

### Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Standard X.509**: Compatible with all X.509-compliant systems

## See Also

- `::tossl::ca::generate` - Generate CA certificates
- `::tossl::csr::create` - Create Certificate Signing Requests
- `::tossl::csr::validate` - Validate CSRs
- `::tossl::x509::create` - Create self-signed certificates
- `::tossl::x509::parse` - Parse certificate details
- `::tossl::x509::validate` - Validate certificates
- `::tossl::x509::verify` - Verify certificate chains 