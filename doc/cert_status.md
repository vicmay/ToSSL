# ::tossl::cert::status

Check the status of X.509 certificates, including validity, expiration, and revocation status.

## Syntax

    tossl::cert::status check <certificate>
    tossl::cert::status ocsp <certificate> <responder_url>

## Description

The `::tossl::cert::status` command provides certificate status checking functionality with two main operations:

### `check` Operation

Performs a comprehensive status check on an X.509 certificate, examining:
- Certificate validity
- Expiration status
- Not-yet-valid status
- Revocation status (currently always returns 0 as not implemented)
- Overall certificate status

### `ocsp` Operation

Performs Online Certificate Status Protocol (OCSP) checking to determine if a certificate has been revoked. Currently implemented as a stub that returns fixed values.

## Parameters

### For `check` operation:
- `<certificate>`: The X.509 certificate to check (PEM or DER format)

### For `ocsp` operation:
- `<certificate>`: The X.509 certificate to check (PEM or DER format)
- `<responder_url>`: The URL of the OCSP responder server

## Output

### `check` Operation Output

Returns a Tcl dictionary with the following keys:

- `valid`: Boolean (1/0) indicating if the certificate is valid
- `revoked`: Boolean (1/0) indicating if the certificate is revoked (currently always 0)
- `expired`: Boolean (1/0) indicating if the certificate has expired
- `not_yet_valid`: Boolean (1/0) indicating if the certificate is not yet valid
- `status`: Overall status as a string ("valid" or "invalid")

### `ocsp` Operation Output

Returns a Tcl dictionary with the following keys:

- `ocsp_status`: Status string ("unknown" for stub implementation)
- `response_time`: Response time as string ("0" for stub implementation)
- `next_update`: Next update time as string ("0" for stub implementation)

## Examples

### Basic Certificate Status Check

```tcl
# Load a certificate from file
set f [open "certificate.pem" r]
set cert_data [read $f]
close $f

# Check certificate status
set status [tossl::cert::status check $cert_data]

# Extract status information
if {[dict get $status status] eq "valid"} {
    puts "Certificate is valid"
} else {
    puts "Certificate is invalid"
    if {[dict get $status expired]} {
        puts "  - Certificate has expired"
    }
    if {[dict get $status not_yet_valid]} {
        puts "  - Certificate is not yet valid"
    }
    if {[dict get $status revoked]} {
        puts "  - Certificate is revoked"
    }
}
```

### OCSP Status Check

```tcl
# Check certificate status via OCSP
set ocsp_status [tossl::cert::status ocsp $cert_data "http://ocsp.example.com"]

puts "OCSP Status: [dict get $ocsp_status ocsp_status]"
puts "Response Time: [dict get $ocsp_status response_time]"
puts "Next Update: [dict get $ocsp_status next_update]"
```

### Certificate Chain Validation

```tcl
# Generate a CA certificate
set ca_key [tossl::key::generate rsa 2048]
set ca_cert [tossl::ca::generate $ca_key {CN=Test CA} 365]

# Generate a leaf certificate
set leaf_key [tossl::key::generate rsa 2048]
set csr [tossl::csr::create $leaf_key {CN=test.example.com}]
set leaf_cert [tossl::ca::sign $ca_cert $ca_key $csr 30]

# Check both certificates
set ca_status [tossl::cert::status check $ca_cert]
set leaf_status [tossl::cert::status check $leaf_cert]

puts "CA Certificate Status: [dict get $ca_status status]"
puts "Leaf Certificate Status: [dict get $leaf_status status]"
```

### Batch Certificate Checking

```tcl
# Check multiple certificates
set certificates [list cert1.pem cert2.pem cert3.pem]
set results {}

foreach cert_file $certificates {
    set f [open $cert_file r]
    set cert_data [read $f]
    close $f
    
    set status [tossl::cert::status check $cert_data]
    lappend results [list $cert_file [dict get $status status]]
}

# Report results
foreach result $results {
    puts "[lindex $result 0]: [lindex $result 1]"
}
```

## Error Handling

The command returns errors in the following cases:

- Missing operation parameter
- Invalid operation (not "check" or "ocsp")
- Missing certificate data for `check` operation
- Missing certificate or responder URL for `ocsp` operation
- Invalid certificate data (cannot be parsed as PEM or DER)

### Error Examples

```tcl
# Missing operation
if {[catch {tossl::cert::status} err]} {
    puts "Error: $err"
}

# Invalid operation
if {[catch {tossl::cert::status invalid} err]} {
    puts "Error: $err"
}

# Missing certificate
if {[catch {tossl::cert::status check} err]} {
    puts "Error: $err"
}

# Invalid certificate data
if {[catch {tossl::cert::status check "invalid_data"} err]} {
    puts "Error: $err"
}
```

## Security Considerations

### Certificate Validation

- The `check` operation performs basic certificate validation including expiration checks
- Revocation checking is not currently implemented and always returns false
- The command does not validate certificate chains or signatures
- For production use, combine with `::tossl::x509::verify` for complete validation

### OCSP Implementation

- The OCSP operation is currently a stub implementation
- Real OCSP checking requires network connectivity to responder servers
- OCSP responses should be validated for authenticity
- Consider implementing OCSP stapling for better performance

### Best Practices

1. **Always check expiration**: Use the `expired` and `not_yet_valid` fields
2. **Combine with other validation**: Use with `::tossl::x509::verify` for complete validation
3. **Handle errors gracefully**: Check for parsing errors and invalid certificates
4. **Cache results appropriately**: Certificate status doesn't change frequently
5. **Monitor OCSP availability**: Real OCSP checking requires responder availability

## Performance Notes

- Certificate parsing is relatively fast for standard certificates
- The command is suitable for batch processing of multiple certificates
- OCSP checking (when fully implemented) will have network latency
- Consider caching results for frequently checked certificates

## Limitations

- Revocation checking is not implemented (always returns false)
- OCSP operation is a stub implementation
- No certificate chain validation
- No signature validation
- Limited to basic X.509 certificate fields

## Related Commands

- `::tossl::x509::verify` - Complete certificate validation including chains
- `::tossl::x509::parse` - Parse certificate details
- `::tossl::ocsp::create_request` - Create OCSP requests
- `::tossl::ocsp::parse_response` - Parse OCSP responses
- `::tossl::crl::parse` - Parse Certificate Revocation Lists 