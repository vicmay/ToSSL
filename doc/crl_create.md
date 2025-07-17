# ::tossl::crl::create

## Overview

The `::tossl::crl::create` command creates a Certificate Revocation List (CRL) using a CA's private key and certificate. A CRL is a list of certificates that have been revoked by the Certificate Authority (CA) before their expiration date. This command is essential for PKI (Public Key Infrastructure) management and certificate lifecycle operations.

## Syntax

```tcl
::tossl::crl::create -key <private_key> -cert <certificate> -days <validity_days>
```

## Parameters

- **-key** or **-ca_key** (required): The CA's private key in PEM format. This key is used to sign the CRL.
- **-cert** or **-ca_cert** (required): The CA's certificate in PEM format. This certificate provides the issuer information for the CRL.
- **-days** (required): The validity period of the CRL in days from the current time.

## Returns

Returns a PEM-encoded X.509 CRL as a string.

## Examples

### Basic CRL Creation

```tcl
# Generate CA key pair
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keypair private]
set ca_public [dict get $ca_keypair public]

# Create CA certificate
set ca_cert [tossl::x509::create -subject "CN=My CA" -issuer "CN=My CA" \
    -pubkey $ca_public -privkey $ca_private -days 365]

# Create CRL with 30-day validity
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
puts "CRL: $crl"
```

### CRL Creation with Alternative Parameter Names

```tcl
# Using -ca_key and -ca_cert parameters
set crl [tossl::crl::create -ca_key $ca_private -ca_cert $ca_cert -days 30]
```

### CRL Creation with Different Validity Periods

```tcl
# Short-term CRL (7 days)
set short_crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 7]

# Long-term CRL (1 year)
set long_crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 365]
```

### CRL Creation with EC Keys

```tcl
# Generate EC CA key pair
set ec_keypair [tossl::key::generate -type ec -curve prime256v1]
set ec_private [dict get $ec_keypair private]
set ec_public [dict get $ec_keypair public]

# Create EC CA certificate
set ec_cert [tossl::x509::create -subject "CN=EC CA" -issuer "CN=EC CA" \
    -pubkey $ec_public -privkey $ec_private -days 365]

# Create CRL with EC key
set ec_crl [tossl::crl::create -key $ec_private -cert $ec_cert -days 30]
```

### CRL Creation and Parsing

```tcl
# Create CRL
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]

# Parse and verify CRL information
set crl_info [tossl::crl::parse $crl]
puts "CRL Version: [dict get $crl_info version]"
puts "CRL Issuer: [dict get $crl_info issuer]"
puts "Last Update: [dict get $crl_info last_update]"
puts "Next Update: [dict get $crl_info next_update]"
```

## Error Handling

### Common Errors

1. **Missing Required Parameters**
   ```tcl
   # Error: Missing key parameter
   tossl::crl::create -cert $ca_cert -days 30
   # Result: "Key and certificate are required"
   ```

2. **Invalid Key Format**
   ```tcl
   # Error: Invalid private key
   tossl::crl::create -key "invalid key" -cert $ca_cert -days 30
   # Result: "Failed to parse private key"
   ```

3. **Invalid Certificate Format**
   ```tcl
   # Error: Invalid certificate
   tossl::crl::create -key $ca_private -cert "invalid cert" -days 30
   # Result: "Failed to parse certificate"
   ```

4. **Invalid Days Parameter**
   ```tcl
   # Error: Non-numeric days
   tossl::crl::create -key $ca_private -cert $ca_cert -days "invalid"
   # Result: Error in parameter conversion
   ```

5. **Negative or Zero Days**
   ```tcl
   # Error: Negative days
   tossl::crl::create -key $ca_private -cert $ca_cert -days -1
   # Result: Error in parameter conversion
   ```

### Error Recovery

```tcl
# Safe CRL creation with error handling
proc create_crl_safe {key cert days} {
    if {[catch {
        tossl::crl::create -key $key -cert $cert -days $days
    } result]} {
        puts "CRL creation failed: $result"
        return ""
    }
    return $result
}

set crl [create_crl_safe $ca_private $ca_cert 30]
if {$crl ne ""} {
    puts "CRL created successfully"
} else {
    puts "CRL creation failed"
}
```

## Security Considerations

### Key Security
- **Private Key Protection**: The CA private key used to sign the CRL must be kept secure and never shared.
- **Key Strength**: Use strong keys (2048+ bits for RSA, prime256v1 or better for EC).
- **Key Storage**: Store private keys in secure hardware modules (HSMs) when possible.

### CRL Validity
- **Update Frequency**: CRLs should be updated regularly to reflect current revocation status.
- **Validity Period**: Choose appropriate validity periods based on your security requirements.
- **Distribution**: Ensure CRLs are distributed to all relying parties.

### Certificate Authority
- **CA Certificate**: The CA certificate should have appropriate key usage extensions.
- **CA Security**: The CA system should be protected from unauthorized access.
- **Audit Trail**: Maintain logs of all CRL operations for audit purposes.

## Best Practices

### CRL Management
```tcl
# Regular CRL update procedure
proc update_crl {ca_key ca_cert validity_days} {
    set crl [tossl::crl::create -key $ca_key -cert $ca_cert -days $validity_days]
    
    # Save CRL to file
    set filename "crl_-[clock format [clock seconds] -format %Y%m%d].pem"
    set file [open $filename w]
    puts $file $crl
    close $file
    
    return $crl
}

# Update CRL monthly
set monthly_crl [update_crl $ca_private $ca_cert 30]
```

### CRL Validation
```tcl
# Validate CRL before use
proc validate_crl {crl ca_cert} {
    # Parse CRL
    set crl_info [tossl::crl::parse $crl]
    
    # Check version
    if {[dict get $crl_info version] != 1} {
        return 0
    }
    
    # Check issuer matches CA
    set ca_info [tossl::x509::parse $ca_cert]
    if {![string match "*[dict get $ca_info subject]*" [dict get $crl_info issuer]]} {
        return 0
    }
    
    return 1
}
```

### CRL Distribution
```tcl
# Generate CRL with appropriate metadata
proc generate_distribution_crl {ca_key ca_cert days} {
    set crl [tossl::crl::create -key $ca_key -cert $ca_cert -days $days]
    
    # Create distribution package
    set package [dict create \
        crl $crl \
        timestamp [clock seconds] \
        validity_days $days \
        issuer [dict get [tossl::x509::parse $ca_cert] subject]]
    
    return $package
}
```

## Performance Considerations

### CRL Size
- CRLs can become large as the number of revoked certificates grows.
- Consider using delta CRLs for large certificate populations.
- Monitor CRL size and update frequency for optimal performance.

### Update Frequency
- Balance security requirements with operational overhead.
- Use shorter validity periods for high-security environments.
- Implement automated CRL generation and distribution.

## Integration Examples

### Web Server CRL Distribution
```tcl
# Generate CRL for web server distribution
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 7]

# Save to web-accessible location
set web_path "/var/www/crl/ca.crl"
set file [open $web_path w]
puts $file $crl
close $file

puts "CRL available at: http://example.com/crl/ca.crl"
```

### LDAP CRL Distribution
```tcl
# Generate CRL for LDAP distribution
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]

# Convert to DER format for LDAP
set crl_der [tossl::crl::convert -format der $crl]

# Store in LDAP directory
# (LDAP operations would be implemented separately)
puts "CRL ready for LDAP distribution"
```

## Troubleshooting

### Common Issues

1. **CRL Parsing Errors**
   - Ensure the CRL is properly formatted
   - Check that the CA certificate is valid
   - Verify the private key matches the certificate

2. **Signature Verification Failures**
   - Confirm the private key is correct
   - Check that the certificate is not expired
   - Verify the key usage extensions

3. **Performance Issues**
   - Monitor CRL generation time
   - Consider using stronger hardware for large CRLs
   - Optimize update frequency

### Debugging

```tcl
# Debug CRL creation
proc debug_crl_creation {key cert days} {
    puts "Debug: Starting CRL creation"
    puts "Debug: Key length: [string length $key]"
    puts "Debug: Certificate length: [string length $cert]"
    puts "Debug: Validity days: $days"
    
    if {[catch {
        set crl [tossl::crl::create -key $key -cert $cert -days $days]
        puts "Debug: CRL created successfully"
        puts "Debug: CRL length: [string length $crl]"
        return $crl
    } result]} {
        puts "Debug: CRL creation failed: $result"
        return ""
    }
}
```

## Related Commands

- `::tossl::crl::parse` - Parse and extract information from a CRL
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::key::generate` - Generate cryptographic key pairs
- `::tossl::x509::parse` - Parse X.509 certificates

## Standards Compliance

The `::tossl::crl::create` command generates CRLs that comply with:
- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- RFC 6818 - Updates to the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

The generated CRLs include:
- Version 2 CRL format
- Proper issuer identification
- Last update and next update timestamps
- Digital signature using SHA-256
- PEM encoding for easy distribution 