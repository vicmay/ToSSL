# ::tossl::x509::time_validate

Validate the time validity of an X.509 certificate by checking its "not before" and "not after" dates against the current time.

## Syntax

    tossl::x509::time_validate <certificate>

## Description

The `::tossl::x509::time_validate` command checks whether an X.509 certificate is currently valid based on its time constraints. This command examines the certificate's validity period and compares it against the current system time to determine if the certificate is active.

The command performs two main checks:
1. **Not Before Check**: Verifies that the current time is after or equal to the certificate's "not before" date
2. **Not After Check**: Verifies that the current time is before or equal to the certificate's "not after" date

## Parameters

- **`<certificate>`** (required): The X.509 certificate to validate in PEM format

## Return Value

Returns a Tcl list containing key-value pairs with the following structure:

```
not_before_valid <boolean> not_after_valid <boolean> valid <boolean>
```

### List Elements

- **`not_before_valid`** (boolean): Whether the current time is after or equal to the certificate's "not before" date
- **`not_after_valid`** (boolean): Whether the current time is before or equal to the certificate's "not after" date  
- **`valid`** (boolean): Overall validity status (true only if both `not_before_valid` and `not_after_valid` are true)

## Examples

### Basic Certificate Time Validation

```tcl
# Load a certificate from file
set f [open "certificate.pem" r]
set cert_data [read $f]
close $f

# Validate certificate time
set time_validation [tossl::x509::time_validate $cert_data]
puts "Time validation result: $time_validation"

# Extract individual validation results
set not_before_idx [lsearch $time_validation "not_before_valid"]
set not_after_idx [lsearch $time_validation "not_after_valid"]
set valid_idx [lsearch $time_validation "valid"]

set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]

puts "Not before valid: $not_before_valid"
puts "Not after valid: $not_after_valid"
puts "Overall valid: $overall_valid"
```

### Certificate Status Checking

```tcl
# Check certificate status with detailed reporting
set time_validation [tossl::x509::time_validate $cert_data]

set not_before_idx [lsearch $time_validation "not_before_valid"]
set not_after_idx [lsearch $time_validation "not_after_valid"]
set valid_idx [lsearch $time_validation "valid"]

set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]

if {$overall_valid} {
    puts "✓ Certificate is currently valid"
} else {
    puts "✗ Certificate is not currently valid"
    
    if {!$not_before_valid} {
        puts "  - Certificate is not yet valid (before start date)"
    }
    
    if {!$not_after_valid} {
        puts "  - Certificate has expired (after end date)"
    }
}
```

### Integration with Certificate Parsing

```tcl
# Get detailed certificate information and validate time
set cert_info [tossl::x509::parse $cert_data]
set time_validation [tossl::x509::time_validate $cert_data]

puts "Certificate: [dict get $cert_info subject]"
puts "Issuer: [dict get $cert_info issuer]"
puts "Valid from: [dict get $cert_info not_before]"
puts "Valid until: [dict get $cert_info not_after]"

# Extract time validation results
set valid_idx [lsearch $time_validation "valid"]
set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]

if {$overall_valid} {
    puts "Status: ✓ Valid"
} else {
    puts "Status: ✗ Invalid"
}
```

### Batch Certificate Validation

```tcl
# Validate multiple certificates
set certificates [list cert1.pem cert2.pem cert3.pem]

foreach cert_file $certificates {
    set f [open $cert_file r]
    set cert_data [read $f]
    close $f
    
    set time_validation [tossl::x509::time_validate $cert_data]
    
    set valid_idx [lsearch $time_validation "valid"]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    puts "$cert_file: [expr {$overall_valid ? \"Valid\" : \"Invalid\"}]"
}
```

### Certificate Monitoring

```tcl
# Monitor certificate expiration
proc check_certificate_expiration {cert_data warning_days} {
    set time_validation [tossl::x509::time_validate $cert_data]
    
    set not_after_idx [lsearch $time_validation "not_after_valid"]
    set valid_idx [lsearch $time_validation "valid"]
    
    set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    if {!$overall_valid} {
        if {!$not_after_valid} {
            puts "ALERT: Certificate has expired!"
        } else {
            puts "ALERT: Certificate is not yet valid!"
        }
        return 0
    }
    
    # Parse certificate to get expiration date
    set cert_info [tossl::x509::parse $cert_data]
    set not_after_str [dict get $cert_info not_after]
    
    # Convert to timestamp and check if within warning period
    set expiration_time [clock scan $not_after_str]
    set current_time [clock seconds]
    set days_until_expiry [expr {($expiration_time - $current_time) / 86400}]
    
    if {$days_until_expiry <= $warning_days} {
        puts "WARNING: Certificate expires in $days_until_expiry days"
        return 1
    }
    
    puts "Certificate is valid for $days_until_expiry more days"
    return 2
}

# Usage
set status [check_certificate_expiration $cert_data 30]
```

## Time Validation Logic

### Not Before Check
- **Purpose**: Ensures the certificate is not being used before its intended start date
- **Logic**: Current time >= Certificate "not before" date
- **Result**: `not_before_valid` = 1 if true, 0 if false

### Not After Check
- **Purpose**: Ensures the certificate has not expired
- **Logic**: Current time <= Certificate "not after" date
- **Result**: `not_after_valid` = 1 if true, 0 if false

### Overall Validity
- **Purpose**: Combined validity status
- **Logic**: `not_before_valid` AND `not_after_valid`
- **Result**: `valid` = 1 only if both individual checks are true

## Common Scenarios

### Valid Certificate
```
not_before_valid 1 not_after_valid 1 valid 1
```

### Expired Certificate
```
not_before_valid 1 not_after_valid 0 valid 0
```

### Not Yet Valid Certificate
```
not_before_valid 0 not_after_valid 1 valid 0
```

### Invalid Certificate (Both Issues)
```
not_before_valid 0 not_after_valid 0 valid 0
```

## Error Handling

The command will return an error in the following cases:

- **Missing Arguments**: No certificate provided
- **Extra Arguments**: Too many arguments provided
- **Invalid Certificate**: Certificate data is not in valid PEM format
- **Parse Errors**: Certificate cannot be parsed by OpenSSL

### Error Examples

```tcl
# Missing certificate
catch {tossl::x509::time_validate} err
puts "Error: $err"
# Output: wrong # args: should be "tossl::x509::time_validate certificate"

# Invalid certificate data
catch {tossl::x509::time_validate "invalid data"} err
puts "Error: $err"
# Output: Failed to parse certificate
```

## Performance Considerations

- The command is designed to be fast and lightweight
- Time validation uses system clock, so accuracy depends on system time
- Multiple rapid calls are supported without performance degradation
- Certificate parsing is optimized for PEM format

## Security Considerations

- Always validate certificate time before using certificates for authentication
- Consider time zone differences when interpreting results
- System clock accuracy affects validation results
- Certificates should be validated at the time of use, not just at load time

## Related Commands

- `::tossl::x509::parse` - Parse certificate details including validity dates
- `::tossl::x509::validate` - Comprehensive certificate validation
- `::tossl::x509::verify` - Verify certificate signature against CA
- `::tossl::cert::status` - Check certificate status including revocation

## Implementation Notes

- Uses OpenSSL's `X509_cmp_time()` function for time comparisons
- Compares against current system time using `time(NULL)`
- Returns results as a Tcl list for easy parsing
- Handles both PEM and DER certificate formats
- Thread-safe for concurrent access

## Version Information

- **Introduced**: OpenSSL 3.x compatibility
- **Dependencies**: Requires OpenSSL 3.x or later
- **Platform Support**: Available on all platforms supported by OpenSSL
- **Time Format**: Uses system time for comparisons 