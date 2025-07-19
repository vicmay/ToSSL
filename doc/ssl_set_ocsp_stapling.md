# ::tossl::ssl::set_ocsp_stapling

## Overview

The `::tossl::ssl::set_ocsp_stapling` command enables or disables OCSP (Online Certificate Status Protocol) stapling for an SSL context. OCSP stapling is a security feature that allows servers to include a pre-signed OCSP response in the SSL/TLS handshake, eliminating the need for clients to make separate OCSP requests to certificate authorities. This improves performance, reduces privacy concerns, and enhances security by providing real-time certificate revocation status.

## Syntax

```tcl
::tossl::ssl::set_ocsp_stapling -ctx -ctx -enable context -enable enable
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-enable` | boolean/string | Yes | Enable (1, "true") or disable (0, "false") OCSP stapling |

## Return Value

Returns `"ok"` on success, or throws an error on failure.

## Description

OCSP stapling is a TLS extension (RFC 6066) that allows servers to include a pre-signed OCSP response in the SSL/TLS handshake. This provides several benefits:

### How OCSP Stapling Works

1. **Server Preparation**: The server periodically requests OCSP responses from the certificate authority
2. **Response Storage**: The server stores the OCSP response with its certificate
3. **Handshake Inclusion**: During SSL/TLS handshake, the server includes the OCSP response
4. **Client Verification**: The client verifies the OCSP response without making additional requests

### Benefits of OCSP Stapling

- **Performance**: Eliminates client-side OCSP requests, reducing handshake time
- **Privacy**: Clients don't need to contact certificate authorities directly
- **Reliability**: Reduces dependency on external OCSP responders
- **Security**: Provides real-time certificate revocation status

### Implementation Details

The command performs the following operations:

1. **Context Validation**: Verifies that the specified SSL context exists and is valid
2. **Parameter Parsing**: Parses the enable parameter (accepts 1/0, true/false, or other values)
3. **OCSP Configuration**: Sets the TLS extension status type to OCSP when enabled
4. **Callback Setup**: Configures the status callback (currently set to NULL as a stub)

## Examples

### Basic OCSP Stapling Configuration

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Enable OCSP stapling
set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
if {$result eq "ok"} {
    puts "OCSP stapling enabled successfully"
} else {
    puts "Failed to enable OCSP stapling: $result"
}

# Disable OCSP stapling
set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0]
if {$result eq "ok"} {
    puts "OCSP stapling disabled successfully"
} else {
    puts "Failed to disable OCSP stapling: $result"
}
```

### Server Configuration with OCSP Stapling

```tcl
# Create SSL context for server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Enable OCSP stapling for enhanced security
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Wrap socket with SSL (OCSP stapling will be included in handshake)
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Check if OCSP stapling was provided
    set cert_status [tossl::ssl::check_cert_status -conn $ssl_conn]
    set ocsp_stapled [lindex $cert_status [expr {[lsearch $cert_status "ocsp_stapled"] + 1}]]
    
    if {$ocsp_stapled eq "yes"} {
        puts "Client received OCSP stapled response"
    } else {
        puts "No OCSP stapling provided to client"
    }
    
    # Handle the connection
    set data [tossl::ssl::read -conn $ssl_conn 4096]
    tossl::ssl::write -conn $ssl_conn "Hello from OCSP-enabled server!"
    tossl::ssl::close -conn $ssl_conn
    close $sock
}

vwait forever
```

### Conditional OCSP Stapling Based on Certificate

```tcl
proc configure_ssl_context {cert_file key_file} {
    # Create SSL context
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Parse certificate to check if it supports OCSP
    set cert_data [read [open $cert_file r]]
    set cert_info [tossl::x509::parse $cert_data]
    
    # Check if certificate has OCSP responder URL
    if {[dict exists $cert_info extensions]} {
        set extensions [dict get $cert_info extensions]
        set has_ocsp 0
        
        foreach ext $extensions {
            if {[string match "*OCSP*" $ext] || [string match "*Authority Information Access*" $ext]} {
                set has_ocsp 1
                break
            }
        }
        
        if {$has_ocsp} {
            puts "Certificate supports OCSP - enabling stapling"
            tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
        } else {
            puts "Certificate does not support OCSP - stapling disabled"
            tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0
        }
    } else {
        puts "No extensions found - disabling OCSP stapling"
        tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0
    }
    
    return $ctx
}

# Usage
set ctx [configure_ssl_context "server.pem" "server.key"]
```

### OCSP Stapling with Multiple Contexts

```tcl
# Create multiple SSL contexts with different OCSP stapling configurations
set contexts {}

# Context 1: OCSP stapling enabled
set ctx1 [tossl::ssl::context create -cert server1.pem -key server1.key]
tossl::ssl::set_ocsp_stapling -ctx $ctx1 -enable 1
lappend contexts [list $ctx1 "enabled"]

# Context 2: OCSP stapling disabled
set ctx2 [tossl::ssl::context create -cert server2.pem -key server2.key]
tossl::ssl::set_ocsp_stapling -ctx $ctx2 -enable 0
lappend contexts [list $ctx2 "disabled"]

# Context 3: OCSP stapling enabled with boolean value
set ctx3 [tossl::ssl::context create -cert server3.pem -key server3.key]
tossl::ssl::set_ocsp_stapling -ctx $ctx3 -enable true
lappend contexts [list $ctx3 "enabled"]

# Display configuration
foreach {ctx status} $contexts {
    puts "Context $ctx: OCSP stapling $status"
}
```

### OCSP Stapling Monitoring

```tcl
proc monitor_ocsp_stapling {ctx} {
    # Enable OCSP stapling
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    
    if {$result eq "ok"} {
        puts "[clock format [clock seconds]]: OCSP stapling enabled for context $ctx"
        return 1
    } else {
        puts "[clock format [clock seconds]]: Failed to enable OCSP stapling for context $ctx"
        return 0
    }
}

# Monitor multiple contexts
set contexts {sslctx1 sslctx2 sslctx3}
set enabled_count 0

foreach ctx $contexts {
    if {[monitor_ocsp_stapling $ctx]} {
        incr enabled_count
    }
}

puts "OCSP stapling enabled on $enabled_count out of [llength $contexts] contexts"
```

### Integration with Certificate Transparency

```tcl
proc configure_enhanced_ssl_context {cert_file key_file} {
    # Create SSL context
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Enable OCSP stapling
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
    
    # Check certificate transparency support
    set cert_data [read [open $cert_file r]]
    set cert_info [tossl::x509::parse $cert_data]
    
    if {[dict exists $cert_info extensions]} {
        set extensions [dict get $cert_info extensions]
        set has_ct 0
        
        foreach ext $extensions {
            if {[string match "*Certificate Transparency*" $ext]} {
                set has_ct 1
                break
            }
        }
        
        if {$has_ct} {
            puts "Enhanced SSL context: OCSP stapling + Certificate Transparency"
        } else {
            puts "Enhanced SSL context: OCSP stapling enabled"
        }
    }
    
    return $ctx
}

# Usage
set ctx [configure_enhanced_ssl_context "server.pem" "server.key"]
```

### OCSP Stapling with Different Enable Values

```tcl
# Test different enable parameter values
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Numeric values
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1    ;# Enable
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0    ;# Disable

# Boolean values
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable true ;# Enable
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable false ;# Disable

# String values (handled gracefully)
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable "enabled"  ;# Handled
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable "disabled" ;# Handled

puts "OCSP stapling configuration completed"
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL context not found` | The specified context handle is invalid or doesn't exist | Ensure the context was created successfully and is still active |
| `wrong # args` | Missing required parameters | Ensure both `-ctx` and `-enable` parameters are specified |

## Security Considerations

### OCSP Stapling Benefits

OCSP stapling provides several security advantages:

```tcl
proc secure_ssl_configuration {cert_file key_file} {
    # Create SSL context
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Enable OCSP stapling for enhanced security
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
    
    # Additional security configurations
    # (These would be implemented with other commands)
    # tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
    # tossl::ssl::set_cert_pinning -ctx $ctx -pins "expected_pins"
    
    puts "Secure SSL context configured with OCSP stapling"
    return $ctx
}
```

### Privacy Protection

OCSP stapling enhances privacy by eliminating client-side OCSP requests:

```tcl
proc privacy_enhanced_server {cert_file key_file} {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Enable OCSP stapling to protect client privacy
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
    
    puts "Privacy-enhanced server: Clients won't contact CAs directly"
    return $ctx
}
```

### Performance Optimization

OCSP stapling improves performance by reducing handshake time:

```tcl
proc performance_optimized_context {cert_file key_file} {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Enable OCSP stapling for faster handshakes
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
    
    puts "Performance-optimized context: Faster SSL handshakes with OCSP stapling"
    return $ctx
}
```

## Performance Considerations

### OCSP Response Management

- **Response Caching**: The server should cache OCSP responses to avoid repeated requests
- **Response Freshness**: Ensure OCSP responses are refreshed before expiration
- **Response Size**: OCSP responses are typically small and don't significantly impact handshake size

### Resource Usage

```tcl
# Monitor OCSP stapling resource usage
proc monitor_ocsp_resources {ctx} {
    set start_time [clock clicks -milliseconds]
    
    # Enable OCSP stapling
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1
    
    set end_time [clock clicks -milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "OCSP stapling configuration completed in ${duration}ms"
    return $duration
}
```

## Integration

This command integrates well with other TOSSL commands:

- **`::tossl::ssl::context create`**: Create SSL contexts for OCSP stapling configuration
- **`::tossl::ssl::check_cert_status`**: Verify OCSP stapling status in connections
- **`::tossl::ssl::connect`**: Establish SSL connections with OCSP stapling
- **`::tossl::ssl::accept`**: Accept SSL connections with OCSP stapling
- **`::tossl::x509::parse`**: Parse certificates to check OCSP support

## Troubleshooting

### Common Issues

1. **OCSP stapling not working**: Ensure the certificate has OCSP responder information
2. **Context not found**: Verify the SSL context was created successfully
3. **Parameter errors**: Check that both required parameters are provided

### Debugging

```tcl
# Debug OCSP stapling configuration
proc debug_ocsp_stapling {ctx} {
    puts "Debugging OCSP stapling for context: $ctx"
    
    # Test enable
    if {[catch {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
        puts "Enable result: $result"
    } err]} {
        puts "Enable failed: $err"
        return 0
    }
    
    # Test disable
    if {[catch {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0]
        puts "Disable result: $result"
    } err]} {
        puts "Disable failed: $err"
        return 0
    }
    
    puts "OCSP stapling configuration debug completed"
    return 1
}
```

### Verification

```tcl
# Verify OCSP stapling configuration
proc verify_ocsp_stapling {ctx} {
    # Test enable
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    if {$result ne "ok"} {
        puts "OCSP stapling enable verification failed: $result"
        return 0
    }
    
    # Test disable
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0]
    if {$result ne "ok"} {
        puts "OCSP stapling disable verification failed: $result"
        return 0
    }
    
    puts "OCSP stapling configuration verified successfully"
    return 1
}
```

## See Also

- `::tossl::ssl::context create` - Create SSL contexts
- `::tossl::ssl::check_cert_status` - Check certificate status including OCSP stapling
- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::x509::parse` - Parse certificates for OCSP support
- `::tossl::ocsp::create_request` - Create OCSP requests
- `::tossl::ocsp::parse_response` - Parse OCSP responses 