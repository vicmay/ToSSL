# ::tossl::x509::validate

## Overview

The `::tossl::x509::validate` command validates the time validity of an X.509 certificate by checking its "not before" and "not after" dates against the current system time. This is a fundamental operation for determining whether a certificate is currently active and usable.

## Syntax

```tcl
::tossl::x509::validate <certificate>
```

- `<certificate>`: PEM-encoded X.509 certificate to validate (required)

## Return Value

The command returns a descriptive string indicating the validation result:

- `"Certificate is valid"` - The certificate is within its validity period
- `"Certificate is expired"` - The certificate has passed its expiration date
- `"Certificate is not yet valid"` - The certificate's validity period hasn't started yet
- Returns an error if the certificate cannot be parsed or other errors occur

## Examples

### Basic Certificate Validation

```tcl
;# Generate a test certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" \
          -pubkey $pub -privkey $priv -days 365]

;# Validate the certificate
set result [tossl::x509::validate $cert]
puts "Validation result: $result"

if {$result eq "Certificate is valid"} {
    puts "Certificate can be used"
} else {
    puts "Certificate cannot be used: $result"
}
```

### Error Handling

```tcl
;# Handle validation errors
if {[catch {
    set result [tossl::x509::validate $cert]
    puts "Validation result: $result"
} err]} {
    puts "Validation failed: $err"
}

;# Handle invalid certificates
if {[catch {
    tossl::x509::validate "invalid certificate data"
} err]} {
    puts "Error: $err"
}
```

### Integration with Other Commands

```tcl
;# Create and validate a certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

set cert [tossl::x509::create -subject "CN=Integration Test" -issuer "CN=Test CA" \
          -pubkey $pub -privkey $priv -days 365]

;# Validate the certificate
set validation_result [tossl::x509::validate $cert]

;# Parse certificate details
set cert_info [tossl::x509::parse $cert]

puts "Certificate subject: [dict get $cert_info subject]"
puts "Certificate issuer: [dict get $cert_info issuer]"
puts "Validation status: $validation_result"
```

### Validating Different Key Types

```tcl
;# Validate RSA certificate
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_cert [tossl::x509::create -subject "CN=RSA Test" -issuer "CN=Test CA" \
              -pubkey [dict get $rsa_keys public] -privkey [dict get $rsa_keys private] -days 365]
set rsa_valid [tossl::x509::validate $rsa_cert]
puts "RSA certificate: $rsa_valid"

;# Validate EC certificate
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_cert [tossl::x509::create -subject "CN=EC Test" -issuer "CN=Test CA" \
             -pubkey [dict get $ec_keys public] -privkey [dict get $ec_keys private] -days 365]
set ec_valid [tossl::x509::validate $ec_cert]
puts "EC certificate: $ec_valid"

;# Validate DSA certificate
set dsa_keys [tossl::key::generate -type dsa -bits 2048]
set dsa_cert [tossl::x509::create -subject "CN=DSA Test" -issuer "CN=Test CA" \
              -pubkey [dict get $dsa_keys public] -privkey [dict get $dsa_keys private] -days 365]
set dsa_valid [tossl::x509::validate $dsa_cert]
puts "DSA certificate: $dsa_valid"
```

### Batch Validation

```tcl
;# Validate multiple certificates
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

set certificates {}
for {set i 1} {$i <= 5} {incr i} {
    set cert [tossl::x509::create -subject "CN=Cert$i" -issuer "CN=Test CA" \
              -pubkey $pub -privkey $priv -days 365]
    lappend certificates $cert
}

foreach cert $certificates {
    set result [tossl::x509::validate $cert]
    puts "Certificate validation: $result"
}
```

## Error Handling

The command may return errors in the following cases:

- **Missing arguments**: If no certificate is provided
- **Too many arguments**: If more than one argument is provided
- **Invalid certificate format**: If the certificate is not valid PEM format
- **Parse errors**: If the certificate cannot be parsed by OpenSSL
- **Memory allocation failure**: If OpenSSL cannot allocate memory for validation

### Error Examples

```tcl
;# Missing certificate
catch {tossl::x509::validate} err
puts "Error: $err"
# Output: wrong # args: should be "tossl::x509::validate certificate"

;# Invalid certificate data
catch {tossl::x509::validate "invalid data"} err
puts "Error: $err"
# Output: Failed to parse certificate

;# Too many arguments
catch {tossl::x509::validate "cert1" "cert2"} err
puts "Error: $err"
# Output: wrong # args: should be "tossl::x509::validate certificate"
```

## Security Considerations

### Time Validation

- **System clock dependency**: Validation relies on the system clock being accurate
- **Time zone considerations**: Certificates use UTC time, but system time may be in local timezone
- **Clock skew**: Network time synchronization issues can affect validation results

### Certificate Trust

- **No signature verification**: This command only validates time, not cryptographic signatures
- **No revocation checking**: Does not check certificate revocation lists (CRL) or OCSP
- **No chain validation**: Only validates the individual certificate, not the certificate chain

### Best Practices

1. **Always validate before use**: Check certificate validity before using for authentication
2. **Combine with other checks**: Use with `::tossl::x509::verify` for complete validation
3. **Handle time zones**: Ensure system time is properly synchronized
4. **Regular validation**: Re-validate certificates periodically, not just at load time
5. **Error handling**: Always handle validation errors gracefully

## Performance Considerations

- **Fast operation**: Time validation is computationally inexpensive
- **Memory efficient**: Minimal memory usage for validation operations
- **Batch processing**: Can efficiently validate multiple certificates
- **Caching**: Results are not cached, so repeated calls re-validate

## Related Commands

- `::tossl::x509::parse` - Parse certificate details including validity dates
- `::tossl::x509::time_validate` - Detailed time validation with structured output
- `::tossl::x509::verify` - Verify certificate signature against CA
- `::tossl::x509::create` - Create new X.509 certificates
- `::tossl::x509::fingerprint` - Generate certificate fingerprints
- `::tossl::cert::status` - Check certificate status including revocation

## Implementation Notes

- Uses OpenSSL's `X509_cmp_time()` function for time comparisons
- Compares against current system time using `time(NULL)`
- Returns descriptive string messages for easy interpretation
- Handles both PEM and DER certificate formats
- Thread-safe for concurrent access
- Memory cleanup is automatic

## Comparison with Other Commands

### vs `::tossl::x509::time_validate`

- **`::tossl::x509::validate`**: Returns simple string messages, focuses on overall validity
- **`::tossl::x509::time_validate`**: Returns structured data with detailed time information

### vs `::tossl::x509::verify`

- **`::tossl::x509::validate`**: Validates time validity only
- **`::tossl::x509::verify`**: Validates cryptographic signature against CA

## See Also

- [RFC 5280](https://tools.ietf.org/html/rfc5280) - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- [OpenSSL X.509 Documentation](https://www.openssl.org/docs/man1.1.1/man3/X509_cmp_time.html) 