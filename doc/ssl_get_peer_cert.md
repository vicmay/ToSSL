# ::tossl::ssl::get_peer_cert

## Overview

The `::tossl::ssl::get_peer_cert` command retrieves the peer certificate from an established SSL/TLS connection in PEM format. This command is essential for certificate inspection, validation, and security auditing. It allows applications to examine the certificate presented by the remote peer during the SSL handshake, enabling certificate chain analysis, subject verification, and compliance checking.

## Syntax

```tcl
::tossl::ssl::get_peer_cert -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns the peer certificate as a PEM-formatted string. If no certificate is available, returns an empty string.

## Description

The `::tossl::ssl::get_peer_cert` command extracts the X.509 certificate that was presented by the remote peer during the SSL/TLS handshake. This certificate contains crucial information about the peer's identity, including:

- **Subject Information**: Common Name (CN), Organization (O), Country (C), etc.
- **Issuer Information**: Certificate Authority that issued the certificate
- **Validity Period**: Not-before and not-after dates
- **Public Key**: The public key associated with the certificate
- **Extensions**: Additional certificate properties (Subject Alternative Names, Key Usage, etc.)

The command performs the following operations:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Certificate Retrieval**: Gets the peer certificate from the SSL connection using `SSL_get1_peer_certificate()`
3. **Format Conversion**: Converts the certificate to PEM format for easy parsing and inspection
4. **Memory Management**: Properly frees OpenSSL resources after certificate extraction

### Certificate Format

The returned certificate is in PEM (Privacy-Enhanced Mail) format, which is a base64-encoded representation of the X.509 certificate wrapped in header and footer lines:

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvJ8T5TMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTkwMzI2MTQzNzU5WhcNMjAwMzI1MTQzNzU5WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA...
-----END CERTIFICATE-----
```

## Examples

### Basic Certificate Retrieval

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Get peer certificate
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]

if {[string length $peer_cert] > 0} {
    puts "Peer certificate retrieved successfully"
    puts "Certificate length: [string length $peer_cert] bytes"
    
    # Parse certificate for detailed information
    set cert_info [tossl::x509::parse $peer_cert]
    puts "Subject: [dict get $cert_info subject]"
    puts "Issuer: [dict get $cert_info issuer]"
    puts "Valid from: [dict get $cert_info not_before]"
    puts "Valid until: [dict get $cert_info not_after]"
} else {
    puts "No peer certificate available"
}

tossl::ssl::close -conn $conn
```

### Certificate Validation and Inspection

```tcl
proc validate_peer_certificate {conn} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        error "No peer certificate provided"
    }
    
    # Parse certificate
    set cert_info [tossl::x509::parse $peer_cert]
    
    # Check certificate validity
    set status [tossl::x509::validate $peer_cert]
    if {![dict get $status valid]} {
        error "Certificate validation failed: [dict get $status error]"
    }
    
    # Check certificate fingerprint
    set fingerprint [tossl::x509::fingerprint $peer_cert sha256]
    puts "Certificate SHA-256 fingerprint: $fingerprint"
    
    # Check subject information
    set subject [dict get $cert_info subject]
    puts "Certificate subject: $subject"
    
    # Check for specific fields
    if {[dict exists $cert_info subject_alt_names]} {
        set sans [dict get $cert_info subject_alt_names]
        puts "Subject Alternative Names: $sans"
    }
    
    return $cert_info
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

if {[catch {validate_peer_certificate $conn} cert_info]} {
    puts "Certificate validation failed: $cert_info"
    tossl::ssl::close -conn $conn
    exit 1
}

puts "Certificate validation successful"
tossl::ssl::close -conn $conn
```

### Server-Side Client Certificate Handling

```tcl
# Create SSL context for server with client certificate verification
set ctx [tossl::ssl::context create -cert server.pem -key server.key -verify require]

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Wrap socket with SSL
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Get client certificate
    set client_cert [tossl::ssl::get_peer_cert -conn $ssl_conn]
    
    if {[string length $client_cert] > 0} {
        puts "Client certificate from $addr:$port:"
        puts $client_cert
        
        # Parse client certificate
        set cert_info [tossl::x509::parse $client_cert]
        set subject [dict get $cert_info subject]
        puts "Client identity: $subject"
        
        # Check certificate status
        set status [tossl::ssl::check_cert_status -conn $ssl_conn]
        puts "Certificate status: $status"
        
        # Authorize based on certificate
        if {[authorize_client $subject]} {
            puts "Client authorized"
            tossl::ssl::write -conn $ssl_conn "Access granted"
        } else {
            puts "Client not authorized"
            tossl::ssl::write -conn $ssl_conn "Access denied"
        }
    } else {
        puts "No client certificate provided"
        tossl::ssl::write -conn $ssl_conn "Client certificate required"
    }
    
    tossl::ssl::close -conn $ssl_conn
    close $sock
}

proc authorize_client {subject} {
    # Implement client authorization logic based on certificate subject
    # This is a simple example - in practice, you'd check against a database
    return [string match "*authorized*" $subject]
}

vwait forever
```

### Certificate Chain Analysis

```tcl
proc analyze_certificate_chain {conn} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        error "No peer certificate available"
    }
    
    # Parse the certificate
    set cert_info [tossl::x509::parse $peer_cert]
    
    # Extract key information
    set subject [dict get $cert_info subject]
    set issuer [dict get $cert_info issuer]
    set not_before [dict get $cert_info not_before]
    set not_after [dict get $cert_info not_after]
    set fingerprint [tossl::x509::fingerprint $peer_cert sha256]
    
    # Create analysis report
    set report [dict create]
    dict set report subject $subject
    dict set report issuer $issuer
    dict set report not_before $not_before
    dict set report not_after $not_after
    dict set report fingerprint $fingerprint
    dict set report certificate $peer_cert
    
    # Check certificate validity
    set validity [tossl::x509::validate $peer_cert]
    dict set report valid [dict get $validity valid]
    
    if {![dict get $validity valid]} {
        dict set report validation_error [dict get $validity error]
    }
    
    return $report
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

set chain_analysis [analyze_certificate_chain $conn]

puts "Certificate Chain Analysis:"
puts "  Subject: [dict get $chain_analysis subject]"
puts "  Issuer: [dict get $chain_analysis issuer]"
puts "  Valid from: [dict get $chain_analysis not_before]"
puts "  Valid until: [dict get $chain_analysis not_after]"
puts "  SHA-256 Fingerprint: [dict get $chain_analysis fingerprint]"
puts "  Valid: [dict get $chain_analysis valid]"

if {[dict exists $chain_analysis validation_error]} {
    puts "  Validation Error: [dict get $chain_analysis validation_error]"
}

tossl::ssl::close -conn $conn
```

### Certificate Pinning Implementation

```tcl
proc verify_certificate_pin {conn expected_pin} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        error "No peer certificate available for pinning verification"
    }
    
    # Calculate certificate fingerprint
    set actual_pin [tossl::x509::fingerprint $peer_cert sha256]
    
    # Compare with expected pin
    if {$actual_pin eq $expected_pin} {
        puts "✓ Certificate pin verification successful"
        return 1
    } else {
        puts "✗ Certificate pin verification failed"
        puts "  Expected: $expected_pin"
        puts "  Actual:   $actual_pin"
        return 0
    }
}

# Usage with certificate pinning
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

# Expected certificate pin (SHA-256 fingerprint)
set expected_pin "d4:6e:9e:25:31:8c:40:96:13:ea:1f:4b:ad:80:bd:87:65:7b:0a:7e:65:e9:6b:01:40:67:0e:11:14:c2:26:ef"

if {[verify_certificate_pin $conn $expected_pin]} {
    puts "Proceeding with secure connection"
    # Continue with application logic
} else {
    puts "Certificate pin mismatch - aborting connection"
    tossl::ssl::close -conn $conn
    exit 1
}

tossl::ssl::close -conn $conn
```

### Certificate Monitoring and Logging

```tcl
proc log_certificate_info {conn hostname} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        puts "[clock format [clock seconds]]: $hostname - No certificate provided"
        return
    }
    
    # Parse certificate
    set cert_info [tossl::x509::parse $peer_cert]
    set subject [dict get $cert_info subject]
    set issuer [dict get $cert_info issuer]
    set not_after [dict get $cert_info not_after]
    set fingerprint [tossl::x509::fingerprint $peer_cert sha256]
    
    # Check expiration
    set expiration_date [clock scan $not_after]
    set days_until_expiry [expr {($expiration_date - [clock seconds]) / 86400}]
    
    puts "[clock format [clock seconds]]: $hostname"
    puts "  Subject: $subject"
    puts "  Issuer: $issuer"
    puts "  Expires: $not_after ([format "%.1f" $days_until_expiry] days)"
    puts "  Fingerprint: $fingerprint"
    
    # Alert if certificate expires soon
    if {$days_until_expiry < 30} {
        puts "  ⚠ WARNING: Certificate expires in [format "%.0f" $days_until_expiry] days"
    }
}

# Monitor multiple hosts
set hosts {example.com google.com github.com}
set ctx [tossl::ssl::context create]

foreach host $hosts {
    if {[catch {
        set conn [tossl::ssl::connect -ctx $ctx -host $host -port 443]
        log_certificate_info $conn $host
        tossl::ssl::close -conn $conn
    } err]} {
        puts "[clock format [clock seconds]]: $host - Connection failed: $err"
    }
}
```

### Integration with Certificate Transparency

```tcl
proc check_certificate_transparency {conn} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        error "No peer certificate available"
    }
    
    # Parse certificate
    set cert_info [tossl::x509::parse $peer_cert]
    
    # Check for Certificate Transparency extension
    if {[dict exists $cert_info extensions]} {
        set extensions [dict get $cert_info extensions]
        
        foreach ext $extensions {
            if {[string match "*CT Precertificate SCTs*" $ext]} {
                puts "✓ Certificate Transparency extension found"
                return 1
            }
        }
    }
    
    puts "⚠ No Certificate Transparency extension found"
    return 0
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

if {[check_certificate_transparency $conn]} {
    puts "Certificate supports transparency logging"
} else {
    puts "Certificate does not support transparency logging"
}

tossl::ssl::close -conn $conn
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL connection not found` | The specified connection handle is invalid or doesn't exist | Ensure the connection was created successfully and is still active |
| `wrong # args` | Missing required parameters | Ensure the `-conn` parameter is specified |
| Empty string | No peer certificate is available | Check if the peer provided a certificate during the SSL handshake |

## Security Considerations

### Certificate Validation

Always validate certificates retrieved with this command:

```tcl
proc secure_certificate_handling {conn} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] == 0} {
        error "No peer certificate provided"
    }
    
    # Validate certificate
    set validation [tossl::x509::validate $peer_cert]
    if {![dict get $validation valid]} {
        error "Certificate validation failed: [dict get $validation error]"
    }
    
    # Check certificate status
    set status [tossl::ssl::check_cert_status -conn $conn]
    set expired [lindex $status [expr {[lsearch $status "expired"] + 1}]]
    
    if {$expired eq "yes"} {
        error "Certificate has expired"
    }
    
    return $peer_cert
}
```

### Certificate Pinning

Implement certificate pinning for additional security:

```tcl
proc verify_certificate_pinning {conn expected_pins} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    set actual_pin [tossl::x509::fingerprint $peer_cert sha256]
    
    foreach expected_pin $expected_pins {
        if {$actual_pin eq $expected_pin} {
            return 1
        }
    }
    
    error "Certificate pin verification failed"
}
```

### Information Disclosure

Be careful not to log or expose sensitive certificate information:

```tcl
proc safe_certificate_logging {conn} {
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    set cert_info [tossl::x509::parse $peer_cert]
    
    # Only log non-sensitive information
    puts "Certificate subject: [dict get $cert_info subject]"
    puts "Certificate issuer: [dict get $cert_info issuer]"
    puts "Certificate expires: [dict get $cert_info not_after]"
    
    # Don't log the full certificate or private key information
}
```

## Performance Considerations

### Certificate Retrieval Efficiency

- **Fast Operation**: Certificate retrieval is a lightweight operation
- **Memory Usage**: The command properly manages OpenSSL memory resources
- **Format Conversion**: PEM conversion is efficient and doesn't require network I/O

### Caching Considerations

```tcl
# Cache certificate information for repeated access
set cert_cache [dict create]

proc get_cached_cert_info {conn} {
    global cert_cache
    
    if {[dict exists $cert_cache $conn]} {
        return [dict get $cert_cache $conn]
    }
    
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    set cert_info [tossl::x509::parse $peer_cert]
    
    dict set cert_cache $conn $cert_info
    return $cert_info
}
```

## Integration

This command integrates well with other TOSSL commands:

- **`::tossl::ssl::connect`**: Establish SSL connections for certificate retrieval
- **`::tossl::ssl::accept`**: Accept SSL connections for server-side certificate handling
- **`::tossl::x509::parse`**: Parse retrieved certificates for detailed information
- **`::tossl::x509::validate`**: Validate certificate authenticity and integrity
- **`::tossl::x509::fingerprint`**: Generate certificate fingerprints for pinning
- **`::tossl::ssl::check_cert_status`**: Check certificate expiration and status
- **`::tossl::ssl::verify_peer`**: Combine with standard certificate verification

## Troubleshooting

### Common Issues

1. **No certificate returned**: Ensure the SSL handshake completed successfully and the peer provided a certificate
2. **Connection not found**: Verify the SSL connection is established and active
3. **Invalid certificate format**: The command always returns PEM format, which should be compatible with most tools

### Debugging

```tcl
# Debug certificate retrieval
proc debug_certificate_retrieval {conn} {
    puts "Retrieving certificate for connection: $conn"
    
    if {[catch {
        set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
        puts "Certificate retrieval successful"
        puts "Certificate length: [string length $peer_cert] bytes"
        
        if {[string length $peer_cert] > 0} {
            puts "Certificate starts with: [string range $peer_cert 0 50]..."
            puts "Certificate ends with: ...[string range $peer_cert end-50 end]"
        }
        
        return $peer_cert
    } error]} {
        puts "Certificate retrieval failed: $error"
        return ""
    }
}
```

## See Also

- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::x509::parse` - Parse X.509 certificates
- `::tossl::x509::validate` - Validate certificates
- `::tossl::x509::fingerprint` - Generate certificate fingerprints
- `::tossl::ssl::check_cert_status` - Check certificate status
- `::tossl::ssl::verify_peer` - Verify peer certificates 