# ::tossl::x509::parse

## Overview

The `::tossl::x509::parse` command parses a PEM-encoded X.509 certificate and extracts key information including subject, issuer, serial number, and validity dates. This command is essential for certificate inspection and validation workflows.

## Syntax

```tcl
::tossl::x509::parse <certificate>
```

- `<certificate>`: PEM-encoded X.509 certificate (required)

## Return Value

Returns a Tcl list with key-value pairs containing the following certificate information:

- `subject`: Distinguished Name (DN) of the certificate subject
- `issuer`: Distinguished Name (DN) of the certificate issuer  
- `serial`: Serial number in hexadecimal format
- `not_before`: Certificate validity start date (ASN.1 TIME format)
- `not_after`: Certificate validity end date (ASN.1 TIME format)

## Examples

### Basic Certificate Parsing

```tcl
;# Generate a test certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $keys private]
set public_key [dict get $keys public]

set cert [tossl::x509::create -subject "CN=example.com" -issuer "CN=example.com" \
          -pubkey $public_key -privkey $private_key -days 365]

;# Parse the certificate
set parsed [tossl::x509::parse $cert]

;# Convert to dictionary for easier access
set cert_info [dict create {*}$parsed]

;# Display certificate information
puts "Subject: [dict get $cert_info subject]"
puts "Issuer: [dict get $cert_info issuer]"
puts "Serial: [dict get $cert_info serial]"
puts "Valid from: [dict get $cert_info not_before]"
puts "Valid until: [dict get $cert_info not_after]"
```

### Certificate Chain Analysis

```tcl
;# Create CA certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_public [dict get $ca_keys public]

set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
             -pubkey $ca_public -privkey $ca_private -days 365]

;# Create certificate signed by CA
set cert_keys [tossl::key::generate -type rsa -bits 2048]
set cert_public [dict get $cert_keys public]

set signed_cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" \
                 -pubkey $cert_public -privkey $ca_private -days 365]

;# Parse both certificates
set ca_info [dict create {*}[tossl::x509::parse $ca_cert]]
set cert_info [dict create {*}[tossl::x509::parse $signed_cert]]

;# Verify certificate chain
if {[dict get $cert_info issuer] eq [dict get $ca_info subject]} {
    puts "Certificate chain is valid"
} else {
    puts "Certificate chain is invalid"
}
```

### Certificate Validation Workflow

```tcl
proc validate_certificate {cert_pem} {
    # Parse certificate
    set cert_info [dict create {*}[tossl::x509::parse $cert_pem]]
    
    # Check if certificate is self-signed
    set is_self_signed [expr {[dict get $cert_info subject] eq [dict get $cert_info issuer]}]
    
    # Extract validity dates
    set not_before [dict get $cert_info not_before]
    set not_after [dict get $cert_info not_after]
    
    # Get current time in ASN.1 format
    set current_time [clock format [clock seconds] -format "%Y%m%d%H%M%SZ" -gmt true]
    
    # Check if certificate is currently valid
    set is_valid [expr {$current_time >= $not_before && $current_time <= $not_after}]
    
    return [dict create \
        subject [dict get $cert_info subject] \
        issuer [dict get $cert_info issuer] \
        serial [dict get $cert_info serial] \
        self_signed $is_self_signed \
        valid $is_valid \
        not_before $not_before \
        not_after $not_after]
}

;# Usage
set validation_result [validate_certificate $cert]
puts "Certificate validation: $validation_result"
```

### Certificate Information Display

```tcl
proc display_cert_info {cert_pem} {
    set cert_info [dict create {*}[tossl::x509::parse $cert_pem]]
    
    puts "=== Certificate Information ==="
    puts "Subject: [dict get $cert_info subject]"
    puts "Issuer: [dict get $cert_info issuer]"
    puts "Serial Number: [dict get $cert_info serial]"
    puts "Valid From: [dict get $cert_info not_before]"
    puts "Valid Until: [dict get $cert_info not_after]"
    
    # Check if self-signed
    if {[dict get $cert_info subject] eq [dict get $cert_info issuer]} {
        puts "Type: Self-signed certificate"
    } else {
        puts "Type: CA-signed certificate"
    }
}

;# Usage
display_cert_info $cert
```

## Error Handling

The command will return an error in the following cases:

- **Missing argument**: No certificate provided
- **Invalid certificate**: Certificate is not valid PEM format
- **Corrupted data**: Certificate data is corrupted or incomplete
- **Empty certificate**: Certificate string is empty

### Error Handling Example

```tcl
proc safe_parse_certificate {cert_pem} {
    if {[string length $cert_pem] == 0} {
        return [dict create error "Empty certificate provided"]
    }
    
    set parse_rc [catch {set parsed [tossl::x509::parse $cert_pem]} parse_err]
    if {$parse_rc != 0} {
        return [dict create error "Failed to parse certificate: $parse_err"]
    }
    
    return [dict create {*}$parsed]
}

;# Usage
set result [safe_parse_certificate $cert]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Certificate parsed successfully"
    puts "Subject: [dict get $result subject]"
}
```

## Security Considerations

### Certificate Validation

- Always validate parsed certificates before using them in security-sensitive operations
- Check certificate validity dates to ensure the certificate is not expired
- Verify certificate chains using `::tossl::x509::verify` for proper trust validation
- Use `::tossl::x509::validate` for comprehensive certificate validation

### Input Validation

- Ensure certificates come from trusted sources
- Validate certificate format before parsing
- Handle parsing errors gracefully in production code
- Be aware that parsing alone does not verify certificate authenticity

### Best Practices

```tcl
proc secure_cert_parse {cert_pem} {
    # Input validation
    if {[string length $cert_pem] == 0} {
        error "Empty certificate provided"
    }
    
    # Parse certificate
    set parse_rc [catch {set parsed [tossl::x509::parse $cert_pem]} parse_err]
    if {$parse_rc != 0} {
        error "Certificate parsing failed: $parse_err"
    }
    
    # Convert to dictionary
    set cert_info [dict create {*}$parsed]
    
    # Validate required fields
    set required_fields {subject issuer serial not_before not_after}
    foreach field $required_fields {
        if {![dict exists $cert_info $field]} {
            error "Missing required field: $field"
        }
    }
    
    return $cert_info
}
```

## Performance Notes

- Certificate parsing is generally fast for standard certificates
- Performance may vary with certificate size and complexity
- For high-throughput applications, consider caching parsed results
- Large certificate chains may require more processing time

## Related Commands

- `::tossl::x509::create` — Create a new X.509 certificate
- `::tossl::x509::verify` — Verify certificate signature
- `::tossl::x509::validate` — Validate certificate chain
- `::tossl::x509::fingerprint` — Generate certificate fingerprint
- `::tossl::x509::modify` — Modify certificate extensions
- `::tossl::x509::time_validate` — Validate certificate time validity

## Troubleshooting

### Common Issues

- **"Failed to parse certificate"**: Ensure the certificate is valid PEM format
- **"Failed to create BIO"**: Memory allocation issue, check system resources
- **Missing fields**: Certificate may be corrupted or incomplete

### Debugging Tips

```tcl
;# Enable detailed error reporting
proc debug_parse_cert {cert_pem} {
    puts "Certificate length: [string length $cert_pem]"
    puts "Certificate starts with: [string range $cert_pem 0 50]"
    
    set parse_rc [catch {set parsed [tossl::x509::parse $cert_pem]} parse_err]
    if {$parse_rc != 0} {
        puts "Parse error: $parse_err"
        return
    }
    
    puts "Parse successful, fields: [llength $parsed]"
    set cert_info [dict create {*}$parsed]
    dict for {key value} $cert_info {
        puts "  $key: $value"
    }
}
``` 