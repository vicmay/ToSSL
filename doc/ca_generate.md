# ::tossl::ca::generate

Generate a Certificate Authority (CA) certificate for establishing PKI infrastructure.

## Overview

`::tossl::ca::generate` creates a Certificate Authority (CA) certificate that can be used to sign other certificates, establishing a Public Key Infrastructure (PKI) hierarchy. This command is essential for creating root CAs, intermediate CAs, and other certificate authority certificates.

The generated CA certificate includes standard X.509 extensions required for CA operations, such as Basic Constraints and Key Usage extensions that indicate the certificate can be used for signing other certificates.

## Syntax

```tcl
::tossl::ca::generate -key private_key -subject subject ?-days validity_days? ?-extensions extensions?
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-key` | string | Yes | Private key in PEM format |
| `-subject` | string | Yes | Subject distinguished name (DN) |
| `-days` | integer | No | Certificate validity period in days (default: 365) |
| `-extensions` | string | No | Additional X.509 extensions |

### Return Value

Returns a CA certificate in PEM format.

## Examples

### Basic CA Certificate Generation

```tcl
# Generate CA key
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]

# Generate CA certificate
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=My CA" -days 365]

puts "CA certificate generated successfully"
puts "Certificate length: [string length $ca_cert] bytes"
```

### Root CA with Long Validity

```tcl
# Generate root CA key (4096 bits for maximum security)
set root_keys [tossl::key::generate -type rsa -bits 4096]
set root_private [dict get $root_keys private]

# Generate root CA certificate with 10-year validity
set root_cert [tossl::ca::generate -key $root_private \
    -subject "CN=Root CA,O=My Organization,C=US" -days 3650]

puts "Root CA certificate generated with 10-year validity"
```

### Intermediate CA Certificate

```tcl
# Generate intermediate CA key
set int_keys [tossl::key::generate -type rsa -bits 2048]
set int_private [dict get $int_keys private]

# Generate intermediate CA certificate
set int_cert [tossl::ca::generate -key $int_private \
    -subject "CN=Intermediate CA,OU=Certificate Authority,O=My Organization,C=US" \
    -days 1825]

puts "Intermediate CA certificate generated"
```

### EC-based CA Certificate

```tcl
# Generate EC CA key
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_private [dict get $ec_keys private]

# Generate EC-based CA certificate
set ec_ca_cert [tossl::ca::generate -key $ec_private \
    -subject "CN=EC CA,O=My Organization,C=US" -days 365]

puts "EC-based CA certificate generated"
```

### Different Subject Formats

```tcl
# Generate CA key
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]

# Simple subject
set cert1 [tossl::ca::generate -key $ca_private -subject "CN=Simple CA" -days 365]

# Subject with organization
set cert2 [tossl::ca::generate -key $ca_private \
    -subject "CN=Test CA,O=Test Organization" -days 365]

# Full subject with multiple components
set cert3 [tossl::ca::generate -key $ca_private \
    -subject "CN=Full CA,OU=Certificate Authority,O=Test Organization,ST=Test State,L=Test City,C=US" \
    -days 365]

puts "Generated 3 CA certificates with different subject formats"
```

### Certificate Chain Creation

```tcl
# Generate root CA
set root_keys [tossl::key::generate -type rsa -bits 4096]
set root_private [dict get $root_keys private]
set root_cert [tossl::ca::generate -key $root_private \
    -subject "CN=Root CA,O=My Organization,C=US" -days 3650]

# Generate intermediate CA
set int_keys [tossl::key::generate -type rsa -bits 2048]
set int_private [dict get $int_keys private]
set int_cert [tossl::ca::generate -key $int_private \
    -subject "CN=Intermediate CA,O=My Organization,C=US" -days 1825]

# Generate end entity CSR
set end_keys [tossl::key::generate -type rsa -bits 2048]
set end_csr [tossl::csr::create -key [dict get $end_keys private] \
    -subject "CN=end.example.com"]

# Sign end entity certificate with intermediate CA
set end_cert [tossl::ca::sign -ca_key $int_private -ca_cert $int_cert -csr $end_csr -days 365]

puts "Certificate chain created:"
puts "  Root CA -> Intermediate CA -> End Entity"
```

### Different Validity Periods

```tcl
# Generate CA key
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]

# Generate CAs with different validity periods
set periods {30 90 365 730 1825 3650}

foreach days $periods {
    set ca_cert [tossl::ca::generate -key $ca_private \
        -subject "CN=Test CA $days" -days $days]
    
    puts "Generated CA with $days days validity"
}
```

### CA Certificate Validation

```tcl
# Generate CA key and certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]

# Validate the generated certificate
if {[catch {tossl::x509::validate $ca_cert} result]} {
    puts "Certificate validation failed: $result"
} else {
    puts "Certificate validation successful"
}

# Parse certificate details
if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
    puts "Certificate parsing failed: $cert_info"
} else {
    puts "Certificate parsing successful"
    puts "Subject: [dict get $cert_info subject]"
    puts "Issuer: [dict get $cert_info issuer]"
    puts "Valid until: [dict get $cert_info not_after]"
}
```

### Integration with CA Signing

```tcl
# Generate CA infrastructure
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]

# Generate server CSR
set server_keys [tossl::key::generate -type rsa -bits 2048]
set server_csr [tossl::csr::create -key [dict get $server_keys private] \
    -subject "CN=server.example.com"]

# Sign server certificate with CA
set server_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $server_csr -days 365]

puts "Server certificate signed by CA successfully"
```

### Error Handling

```tcl
# Handle missing parameters
if {[catch {tossl::ca::generate -key "key"} result]} {
    puts "Error: $result"
}

# Handle invalid key
if {[catch {tossl::ca::generate -key "invalid-key" -subject "CN=Test CA"} result]} {
    puts "Key error: $result"
}

# Handle invalid subject
if {[catch {tossl::ca::generate -key $ca_private -subject ""} result]} {
    puts "Subject error: $result"
}

# Handle invalid validity period
if {[catch {tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days -1} result]} {
    puts "Validity error: $result"
}
```

### Performance Testing

```tcl
# Generate CA key once
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]

set start_time [clock milliseconds]

# Generate multiple CA certificates
for {set i 0} {$i < 10} {incr i} {
    set ca_cert [tossl::ca::generate -key $ca_private \
        -subject "CN=Test CA $i" -days 365]
    
    puts "Generated CA certificate $i"
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "Generated 10 CA certificates in ${duration}ms"
puts "Average time per certificate: [expr {double($duration) / 10}]ms"
```

## Certificate Properties

### Automatically Added Extensions

The generated CA certificate includes several standard extensions:

1. **Basic Constraints**: `CA:TRUE` - Indicates this certificate can be used as a CA
2. **Key Usage**: `keyCertSign,cRLSign` - Allows signing certificates and CRLs
3. **Authority Key Identifier**: Links to the CA's public key
4. **Subject Key Identifier**: Identifies the certificate's public key

### Certificate Structure

The generated CA certificate contains:

- **Version**: X.509 v3
- **Serial Number**: Unique identifier for the certificate
- **Subject**: As specified in the `-subject` parameter
- **Issuer**: Same as subject (self-signed)
- **Validity Period**: Based on the `-days` parameter
- **Public Key**: Derived from the provided private key
- **Signature**: Self-signed using the provided private key
- **Extensions**: Standard CA extensions

### Supported Key Types

The command supports CA generation with various key types:

- **RSA**: 1024, 2048, 4096 bits (recommended: 2048+ bits)
- **EC**: Various curves (prime256v1, secp384r1, etc.)
- **DSA**: If supported by OpenSSL

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "Key and subject are required" | Missing required parameters | Provide both `-key` and `-subject` |
| "Failed to parse private key" | Invalid key format | Ensure key is valid PEM format |
| "Failed to create certificate" | Memory allocation error | Check system resources |
| "Failed to set certificate version" | Internal OpenSSL error | Check OpenSSL installation |
| "Failed to sign certificate" | Signing operation failed | Verify key compatibility |

### Error Handling Examples

```tcl
# Robust CA generation with error handling
proc generate_ca_safely {key subject days} {
    if {[catch {
        tossl::ca::generate -key $key -subject $subject -days $days
    } result]} {
        puts "CA generation failed: $result"
        return ""
    } else {
        puts "CA generation successful"
        return $result
    }
}

# Usage
set ca_cert [generate_ca_safely $ca_private "CN=Test CA" 365]
if {$ca_cert ne ""} {
    puts "CA certificate created: [string length $ca_cert] bytes"
} else {
    puts "CA certificate creation failed"
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
3. **Subject Names**: Use meaningful and unique subject names
4. **Certificate Hierarchy**: Plan certificate hierarchy carefully

### Best Practices

1. **Root CA**: Use 4096-bit RSA or strong EC keys for root CAs
2. **Intermediate CAs**: Use 2048-bit RSA or strong EC keys for intermediate CAs
3. **Validity Periods**: Root CAs: 10+ years, Intermediate CAs: 5 years, End entities: 1-2 years
4. **Naming Conventions**: Use consistent naming conventions for CA certificates
5. **Documentation**: Maintain documentation of CA issuance procedures

## Integration with Other Commands

### With Key Generation

```tcl
# Generate and use CA key in one workflow
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_public [dict get $ca_keys public]

set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=My CA" -days 365]

puts "CA key pair and certificate generated"
```

### With Certificate Commands

```tcl
# Generate CA and immediately validate
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]

# Parse certificate details
set cert_info [tossl::x509::parse $ca_cert]
puts "Subject: [dict get $cert_info subject]"
puts "Issuer: [dict get $cert_info issuer]"
puts "Valid until: [dict get $cert_info not_after]"

# Get certificate fingerprint
set fingerprint [tossl::x509::fingerprint $ca_cert sha256]
puts "SHA-256 fingerprint: $fingerprint"
```

### With CA Signing

```tcl
# Generate CA and use it to sign certificates
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]

# Generate and sign server certificate
set server_keys [tossl::key::generate -type rsa -bits 2048]
set server_csr [tossl::csr::create -key [dict get $server_keys private] \
    -subject "CN=server.example.com"]

set server_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $server_csr -days 365]

puts "Complete PKI workflow completed"
```

### With SSL Commands

```tcl
# Generate CA for SSL server
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=SSL CA" -days 365]

# Generate server certificate
set server_keys [tossl::key::generate -type rsa -bits 2048]
set server_csr [tossl::csr::create -key [dict get $server_keys private] \
    -subject "CN=ssl.example.com"]

set server_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $server_csr -days 365]

# Use in SSL context
set ctx [tossl::ssl::context create]
# ... configure SSL context with certificate and key
```

## Performance Characteristics

### Time Complexity

- **Single generation**: O(1) for basic operations
- **Batch generation**: Linear with number of certificates
- **Key size impact**: Larger keys require more time

### Memory Usage

- **Minimal overhead**: Only temporary storage for certificate creation
- **No persistent state**: Each operation is independent

### Performance Benchmarks

Typical performance characteristics:
- **RSA 2048-bit generation**: ~100-200ms per certificate
- **EC generation**: ~50-100ms per certificate
- **Batch operations**: ~1-2 seconds for 10 certificates

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's X.509 and EVP APIs
2. **Memory Management**: Properly frees all OpenSSL objects
3. **Error Handling**: Comprehensive error checking and reporting
4. **Extension Handling**: Automatically adds standard CA extensions

### Certificate Format

- **Output Format**: PEM (Privacy-Enhanced Mail) format
- **Encoding**: Base64-encoded DER data
- **Headers**: Standard X.509 certificate headers and footers

### Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Standard X.509**: Compatible with all X.509-compliant systems

## See Also

- `::tossl::ca::sign` - Sign certificates with a CA
- `::tossl::key::generate` - Generate cryptographic keys
- `::tossl::x509::create` - Create self-signed certificates
- `::tossl::x509::parse` - Parse certificate details
- `::tossl::x509::validate` - Validate certificates
- `::tossl::x509::verify` - Verify certificate chains 