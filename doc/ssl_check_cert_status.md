# ::tossl::ssl::check_cert_status

## Overview

The `::tossl::ssl::check_cert_status` command retrieves comprehensive status information about the peer certificate in an SSL/TLS connection. This command provides detailed analysis of certificate validity, expiration status, OCSP stapling, and certificate transparency features. This information is crucial for security auditing, compliance checking, and understanding the security posture of SSL connections.

## Syntax

```tcl
::tossl::ssl::check_cert_status -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns a formatted string containing certificate status information in the format:
```
expired <yes|no>, not_yet_valid <yes|no>, ocsp_stapled <yes|no>, certificate_transparency <yes|no>
```

Where:
- **`expired`**: Whether the certificate has expired (yes/no)
- **`not_yet_valid`**: Whether the certificate is not yet valid (yes/no)
- **`ocsp_stapled`**: Whether OCSP stapling is present (yes/no)
- **`certificate_transparency`**: Whether certificate transparency extension is present (yes/no)

If no certificate is present, returns `"no_cert"`.

## Description

The `::tossl::ssl::check_cert_status` command performs comprehensive analysis of the peer certificate in an SSL/TLS connection. This command is essential for:

- **Security Auditing**: Verifying certificate validity and security features
- **Compliance Checking**: Ensuring certificates meet security policy requirements
- **Monitoring**: Tracking certificate status and security features
- **Troubleshooting**: Diagnosing certificate-related connection issues

The command performs the following checks:

1. **Certificate Retrieval**: Gets the peer certificate from the SSL connection
2. **Expiration Check**: Validates certificate notAfter date against current time
3. **Validity Check**: Validates certificate notBefore date against current time
4. **OCSP Stapling Check**: Detects presence of OCSP stapling response
5. **Certificate Transparency Check**: Detects presence of CT extension
6. **Status Formatting**: Formats results into a readable string

## Examples

### Basic Certificate Status Retrieval

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Get certificate status
set status [tossl::ssl::check_cert_status -conn $conn]
puts "Certificate status: $status"
# Output: Certificate status: expired no, not_yet_valid no, ocsp_stapled yes, certificate_transparency no

# Parse the status information
if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
    puts "Expired: $expired"
    puts "Not yet valid: $not_yet_valid"
    puts "OCSP stapled: $ocsp_stapled"
    puts "Certificate transparency: $ct"
}

# Clean up
tossl::ssl::close -conn $conn
```

### Certificate Status Validation

```tcl
# Validate certificate status
proc validate_certificate_status {conn} {
    set status [tossl::ssl::check_cert_status -conn $conn]
    
    if {$status eq "no_cert"} {
        puts "No certificate present"
        return 0
    }
    
    if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
        puts "=== Certificate Status Validation ==="
        puts "Expired: $expired"
        puts "Not yet valid: $not_yet_valid"
        puts "OCSP stapled: $ocsp_stapled"
        puts "Certificate transparency: $ct"
        
        # Check for issues
        if {$expired eq "yes"} {
            puts "✗ Certificate has expired"
            return 0
        }
        
        if {$not_yet_valid eq "yes"} {
            puts "✗ Certificate is not yet valid"
            return 0
        }
        
        if {$ocsp_stapled eq "yes"} {
            puts "✓ OCSP stapling present (good)"
        } else {
            puts "⚠ No OCSP stapling (consider enabling)"
        }
        
        if {$ct eq "yes"} {
            puts "✓ Certificate transparency present (good)"
        } else {
            puts "⚠ No certificate transparency (consider enabling)"
        }
        
        return 1
    }
    
    puts "✗ Could not parse certificate status"
    return 0
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

if {[validate_certificate_status $conn]} {
    puts "Certificate status is acceptable"
} else {
    puts "Certificate status has issues"
}

tossl::ssl::close -conn $conn
```

### Security Monitoring

```tcl
# Monitor certificate security features
proc monitor_certificate_security {conn} {
    set status [tossl::ssl::check_cert_status -conn $conn]
    
    if {$status eq "no_cert"} {
        puts "Security Warning: No certificate present"
        return
    }
    
    if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
        puts "=== Certificate Security Monitor ==="
        
        # Check basic validity
        if {$expired eq "yes" || $not_yet_valid eq "yes"} {
            puts "✗ Certificate validity issue detected"
            if {$expired eq "yes"} {
                puts "  - Certificate has expired"
            }
            if {$not_yet_valid eq "yes"} {
                puts "  - Certificate is not yet valid"
            }
        } else {
            puts "✓ Certificate is valid"
        }
        
        # Check security features
        set security_score 0
        puts "\nSecurity Features:"
        
        if {$ocsp_stapled eq "yes"} {
            puts "✓ OCSP stapling: Enabled"
            incr security_score
        } else {
            puts "✗ OCSP stapling: Disabled"
        }
        
        if {$ct eq "yes"} {
            puts "✓ Certificate transparency: Enabled"
            incr security_score
        } else {
            puts "✗ Certificate transparency: Disabled"
        }
        
        puts "\nSecurity Score: $security_score/2"
        
        if {$security_score == 2} {
            puts "✓ Excellent security configuration"
        } elseif {$security_score == 1} {
            puts "⚠ Good security configuration (room for improvement)"
        } else {
            puts "✗ Basic security configuration (consider improvements)"
        }
    }
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
monitor_certificate_security $conn
tossl::ssl::close -conn $conn
```

### Certificate Status Comparison

```tcl
# Compare certificate status across multiple connections
proc compare_certificate_status {connections} {
    puts "=== Certificate Status Comparison ==="
    
    set results {}
    foreach {name conn} $connections {
        if {[catch {
            set status [tossl::ssl::check_cert_status -conn $conn]
            lappend results [list $name $status]
        } err]} {
            puts "$name: Error - $err"
        }
    }
    
    # Display results
    foreach result $results {
        set name [lindex $result 0]
        set status [lindex $result 1]
        puts "$name: $status"
    }
    
    # Analyze patterns
    set ocsp_count 0
    set ct_count 0
    set valid_count 0
    
    foreach result $results {
        set status [lindex $result 1]
        if {[regexp {ocsp_stapled yes} $status]} {
            incr ocsp_count
        }
        if {[regexp {certificate_transparency yes} $status]} {
            incr ct_count
        }
        if {[regexp {expired no.*not_yet_valid no} $status]} {
            incr valid_count
        }
    }
    
    puts "\nSummary:"
    puts "Valid certificates: $valid_count/[llength $results]"
    puts "OCSP stapling enabled: $ocsp_count/[llength $results]"
    puts "Certificate transparency enabled: $ct_count/[llength $results]"
}

# Usage
set connections {
    "Google" $conn1
    "GitHub" $conn2
    "Cloudflare" $conn3
}
compare_certificate_status $connections
```

### Certificate Status Logging

```tcl
# Log certificate status for monitoring
proc log_certificate_status {conn hostname} {
    set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
    set status [tossl::ssl::check_cert_status -conn $conn]
    
    # Parse status
    if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
        set log_entry "$timestamp | $hostname | expired=$expired | not_yet_valid=$not_yet_valid | ocsp_stapled=$ocsp_stapled | ct=$ct"
    } else {
        set log_entry "$timestamp | $hostname | status=$status"
    }
    
    # Write to log file
    set log_file "cert_status.log"
    set f [open $log_file a]
    puts $f $log_entry
    close $f
    
    puts "Logged: $log_entry"
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
log_certificate_status $conn "example.com"
tossl::ssl::close -conn $conn
```

### Certificate Status Alerting

```tcl
# Alert on certificate issues
proc alert_certificate_issues {conn hostname} {
    set status [tossl::ssl::check_cert_status -conn $conn]
    
    if {$status eq "no_cert"} {
        puts "ALERT: No certificate present for $hostname"
        return
    }
    
    if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
        set alerts {}
        
        if {$expired eq "yes"} {
            lappend alerts "Certificate expired"
        }
        
        if {$not_yet_valid eq "yes"} {
            lappend alerts "Certificate not yet valid"
        }
        
        if {$ocsp_stapled eq "no"} {
            lappend alerts "No OCSP stapling"
        }
        
        if {$ct eq "no"} {
            lappend alerts "No certificate transparency"
        }
        
        if {[llength $alerts] > 0} {
            puts "ALERT: $hostname has certificate issues:"
            foreach alert $alerts {
                puts "  - $alert"
            }
        } else {
            puts "✓ $hostname certificate status is good"
        }
    }
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
alert_certificate_issues $conn "example.com"
tossl::ssl::close -conn $conn
```

## Error Handling

### Common Errors

1. **SSL connection not found**
   ```tcl
   # Error: SSL connection not found
   # Cause: Invalid or closed connection handle
   # Solution: Ensure connection is valid and open
   ```

2. **Wrong number of arguments**
   ```tcl
   # Error: wrong # args: should be "tossl::ssl::check_cert_status -conn conn"
   # Cause: Missing or incorrect parameters
   # Solution: Use correct syntax with -conn parameter
   ```

### Error Handling Examples

```tcl
# Safe certificate status retrieval
proc safe_get_cert_status {conn} {
    if {[catch {
        set status [tossl::ssl::check_cert_status -conn $conn]
        return $status
    } err]} {
        puts "Failed to get certificate status: $err"
        return ""
    }
}

# Usage
set status [safe_get_cert_status $conn]
if {$status ne ""} {
    puts "Certificate status: $status"
} else {
    puts "No certificate status available"
}
```

```tcl
# Validate connection before certificate status query
proc get_cert_status_with_validation {conn} {
    # Check if connection exists
    if {![info exists conn] || $conn eq ""} {
        puts "Error: Invalid connection handle"
        return ""
    }
    
    # Try to get certificate status
    if {[catch {
        set status [tossl::ssl::check_cert_status -conn $conn]
        return $status
    } err]} {
        puts "Error getting certificate status: $err"
        return ""
    }
}

# Usage
set status [get_cert_status_with_validation $conn]
```

## Integration with Other Commands

The `::tossl::ssl::check_cert_status` command works with:

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::get_peer_cert` - Get peer certificate
- `::tossl::ssl::verify_peer` - Verify peer certificate
- `::tossl::ssl::close` - Close SSL connections

### Complete Certificate Status Workflow

```tcl
# Complete certificate status workflow example
proc certificate_status_workflow {host port} {
    # 1. Create SSL context
    set ctx [tossl::ssl::context create]
    
    # 2. Connect with SSL
    set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
    
    # 3. Get certificate status
    set status [tossl::ssl::check_cert_status -conn $conn]
    puts "Certificate status: $status"
    
    # 4. Parse and analyze status
    if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
        puts "Expired: $expired"
        puts "Not yet valid: $not_yet_valid"
        puts "OCSP stapled: $ocsp_stapled"
        puts "Certificate transparency: $ct"
        
        # 5. Make security decisions
        if {$expired eq "yes" || $not_yet_valid eq "yes"} {
            puts "Certificate has validity issues"
        } else {
            puts "Certificate is valid"
        }
        
        if {$ocsp_stapled eq "yes"} {
            puts "OCSP stapling is enabled"
        }
        
        if {$ct eq "yes"} {
            puts "Certificate transparency is enabled"
        }
    }
    
    # 6. Clean up
    tossl::ssl::close -conn $conn
    
    return $status
}

# Usage
set status [certificate_status_workflow "example.com" 443]
puts "Workflow completed with status: $status"
```

## Performance Considerations

### Efficiency

- **Fast retrieval**: Uses OpenSSL's X509 functions for efficient checking
- **No memory allocation**: Returns existing information without copying
- **Minimal overhead**: Negligible performance impact
- **Immediate return**: No blocking or waiting operations

### Best Practices

```tcl
# Cache certificate status for multiple uses
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
set status [tossl::ssl::check_cert_status -conn $conn]

# Use cached value instead of calling multiple times
if {[regexp {expired (yes|no)} $status -> expired]} {
    puts "Expired: $expired"
}
```

## Security Considerations

### Security Features

- **Read-only operation**: Only retrieves certificate status, no modification
- **OpenSSL security**: Uses OpenSSL's secure certificate functions
- **No state exposure**: Doesn't expose sensitive certificate data
- **Safe concurrency**: Thread-safe for concurrent access
- **No information leakage**: Only returns status details

### Security Best Practices

```tcl
# Validate certificate status before use
proc secure_cert_status_handling {conn allowed_status} {
    set status [tossl::ssl::check_cert_status -conn $conn]
    
    if {[regexp {expired (yes|no)} $status -> expired]} {
        if {$expired eq "no" && $status in $allowed_status} {
            puts "✓ Certificate status allowed"
            return $status
        } else {
            puts "✗ Certificate status not allowed"
            puts "  Allowed: $allowed_status"
            return ""
        }
    }
    return ""
}

# Usage with security validation
set allowed {expired no, not_yet_valid no, ocsp_stapled yes, certificate_transparency yes}
set status [secure_cert_status_handling $conn $allowed]

if {$status ne ""} {
    # Process with validated status
} else {
    # Reject connection
    tossl::ssl::close -conn $conn
}
```

## Troubleshooting

### Common Issues

1. **Empty or malformed certificate status**
   - **Cause**: Invalid SSL connection or corrupted state
   - **Solution**: Verify connection is valid and properly established

2. **Unexpected status values**
   - **Cause**: Certificate format or OpenSSL version issues
   - **Solution**: Check certificate format and OpenSSL compatibility

3. **Connection errors**
   - **Cause**: Invalid or closed connection
   - **Solution**: Ensure connection is valid and open

### Debugging Tips

```tcl
# Debug certificate status
proc debug_cert_status {conn} {
    puts "=== Certificate Status Debug ==="
    puts "Connection: $conn"
    
    if {[catch {
        set status [tossl::ssl::check_cert_status -conn $conn]
        puts "Certificate status: '$status'"
        puts "Length: [string length $status]"
        puts "Valid: [string is ascii $status]"
        
        # Parse components
        if {[regexp {^expired (yes|no), not_yet_valid (yes|no), ocsp_stapled (yes|no), certificate_transparency (yes|no)$} $status -> expired not_yet_valid ocsp_stapled ct]} {
            puts "Parsed components:"
            puts "  Expired: $expired"
            puts "  Not yet valid: $not_yet_valid"
            puts "  OCSP stapled: $ocsp_stapled"
            puts "  Certificate transparency: $ct"
        } else {
            puts "Could not parse certificate status"
        }
    } err]} {
        puts "Error: $err"
    }
}

# Usage
debug_cert_status $conn
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::get_peer_cert` - Get peer certificate
- `::tossl::ssl::verify_peer` - Verify peer certificate
- `::tossl::ssl::close` - Close SSL connections
- `::tossl::ssl::socket_info` - Get socket information
- `::tossl::ssl::cipher_info` - Get cipher information 