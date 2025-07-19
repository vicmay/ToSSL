# ::tossl::ssl::protocol_version

## Overview

The `::tossl::ssl::protocol_version` command retrieves the minimum TLS protocol version configured for an SSL context. This command is essential for monitoring and verifying the TLS protocol settings of SSL contexts, ensuring compliance with security policies and understanding the protocol version range that will be used for SSL/TLS connections.

## Syntax

```tcl
::tossl::ssl::protocol_version -ctx context
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |

## Return Value

Returns a string representing the minimum TLS protocol version configured for the context. Possible values are:
- `"TLSv1.0"` - TLS 1.0 protocol
- `"TLSv1.1"` - TLS 1.1 protocol  
- `"TLSv1.2"` - TLS 1.2 protocol
- `"TLSv1.3"` - TLS 1.3 protocol
- `"unknown"` - Unknown or unsupported protocol version

## Description

The `::tossl::ssl::protocol_version` command queries the SSL context to determine the minimum TLS protocol version that will be accepted for SSL/TLS connections. This is useful for:

- **Security Monitoring**: Verifying that contexts are configured with secure protocol versions
- **Compliance Checking**: Ensuring adherence to security policies and standards
- **Debugging**: Understanding protocol version configuration issues
- **Documentation**: Recording protocol version settings for audit purposes

The command uses OpenSSL's `SSL_CTX_get_min_proto_version()` function to retrieve the protocol version and maps the numeric version codes to human-readable strings.

## Examples

### Basic Protocol Version Retrieval

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Get the configured protocol version
set version [tossl::ssl::protocol_version -ctx $ctx]
puts "SSL context protocol version: $version"

# Use the context for SSL operations
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
```

### Protocol Version with Custom Settings

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set specific protocol versions
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Verify the setting
set version [tossl::ssl::protocol_version -ctx $ctx]
puts "Configured minimum protocol version: $version"

if {$version eq "TLSv1.2"} {
    puts "✓ Context configured for secure TLS 1.2+ connections"
} else {
    puts "⚠ Context may allow insecure protocol versions"
}
```

### Security Policy Verification

```tcl
# Verify SSL context security settings
proc verify_ssl_security {ctx} {
    set version [tossl::ssl::protocol_version -ctx $ctx]
    
    switch $version {
        "TLSv1.3" {
            puts "✓ Excellent: TLS 1.3 (most secure)"
            return "excellent"
        }
        "TLSv1.2" {
            puts "✓ Good: TLS 1.2 (secure)"
            return "good"
        }
        "TLSv1.1" {
            puts "⚠ Warning: TLS 1.1 (deprecated)"
            return "warning"
        }
        "TLSv1.0" {
            puts "✗ Critical: TLS 1.0 (insecure)"
            return "critical"
        }
        default {
            puts "? Unknown: $version"
            return "unknown"
        }
    }
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set security_level [verify_ssl_security $ctx]
```

### Multiple Context Comparison

```tcl
# Compare protocol versions across multiple contexts
set contexts {}

# Create different contexts
set secure_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $secure_ctx -min TLSv1.3 -max TLSv1.3

set standard_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $standard_ctx -min TLSv1.2 -max TLSv1.3

set legacy_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $legacy_ctx -min TLSv1.0 -max TLSv1.3

lappend contexts [list "secure" $secure_ctx]
lappend contexts [list "standard" $standard_ctx]
lappend contexts [list "legacy" $legacy_ctx]

# Compare protocol versions
puts "=== Protocol Version Comparison ==="
foreach {name ctx_handle} $contexts {
    set version [tossl::ssl::protocol_version -ctx $ctx_handle]
    puts "$name context: $version"
}
```

### Protocol Version Monitoring

```tcl
# Monitor protocol versions in production
proc monitor_protocol_versions {contexts} {
    puts "=== SSL Protocol Version Monitor ==="
    puts "[clock format [clock seconds]]"
    
    foreach {name ctx} $contexts {
        if {[catch {
            set version [tossl::ssl::protocol_version -ctx $ctx]
            puts "  $name: $version"
            
            # Alert on insecure versions
            if {$version in {TLSv1.0 TLSv1.1}} {
                puts "    ⚠ ALERT: Insecure protocol version detected!"
            }
        } err]} {
            puts "  $name: ERROR - $err"
        }
    }
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set contexts [list "main_server" $ctx]

# Monitor periodically
monitor_protocol_versions $contexts
```

### Protocol Version Validation

```tcl
# Validate protocol version requirements
proc validate_protocol_version {ctx min_required} {
    set current_version [tossl::ssl::protocol_version -ctx $ctx]
    
    # Define version hierarchy
    set version_order {TLSv1.0 TLSv1.1 TLSv1.2 TLSv1.3}
    
    set current_index [lsearch $version_order $current_version]
    set required_index [lsearch $version_order $min_required]
    
    if {$current_index >= $required_index} {
        puts "✓ Protocol version meets requirement: $current_version >= $min_required"
        return 1
    } else {
        puts "✗ Protocol version below requirement: $current_version < $min_required"
        return 0
    }
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set is_secure [validate_protocol_version $ctx "TLSv1.2"]

if {!$is_secure} {
    puts "Upgrading to secure protocol version..."
    tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
}
```

### Protocol Version Logging

```tcl
# Log protocol version information
proc log_protocol_version {ctx context_name} {
    set version [tossl::ssl::protocol_version -ctx $ctx]
    set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
    
    set log_entry "$timestamp - Context: $context_name, Protocol: $version"
    puts $log_entry
    
    # Write to log file
    set log_file [open "ssl_protocol.log" a]
    puts $log_file $log_entry
    close $log_file
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
log_protocol_version $ctx "web_server"
```

### Protocol Version Compliance Check

```tcl
# Check compliance with security standards
proc check_compliance {ctx} {
    set version [tossl::ssl::protocol_version -ctx $ctx]
    
    # PCI DSS compliance (requires TLS 1.2+)
    set pci_compliant [expr {$version in {TLSv1.2 TLSv1.3}}]
    
    # NIST compliance (requires TLS 1.2+)
    set nist_compliant [expr {$version in {TLSv1.2 TLSv1.3}}]
    
    # HIPAA compliance (requires TLS 1.2+)
    set hipaa_compliant [expr {$version in {TLSv1.2 TLSv1.3}}]
    
    puts "=== Compliance Report ==="
    puts "Protocol Version: $version"
    puts "PCI DSS: [expr {$pci_compliant ? "✓" : "✗"}]"
    puts "NIST: [expr {$nist_compliant ? "✓" : "✗"}]"
    puts "HIPAA: [expr {$hipaa_compliant ? "✓" : "✗"}]"
    
    return [list $pci_compliant $nist_compliant $hipaa_compliant]
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set compliance [check_compliance $ctx]
```

## Error Handling

### Common Error Conditions

1. **SSL context not found**
   ```tcl
   tossl::ssl::protocol_version -ctx "invalid_handle"
   # Error: SSL context not found
   ```

2. **Missing parameters**
   ```tcl
   tossl::ssl::protocol_version
   # Error: wrong # args: should be "tossl::ssl::protocol_version -ctx ctx"
   ```

3. **Missing context parameter**
   ```tcl
   tossl::ssl::protocol_version -ctx
   # Error: wrong # args: should be "tossl::ssl::protocol_version -ctx ctx"
   ```

### Error Handling Best Practices

```tcl
# Robust protocol version retrieval
proc safe_protocol_version {ctx} {
    if {[catch {
        set version [tossl::ssl::protocol_version -ctx $ctx]
        return $version
    } err]} {
        puts "Error retrieving protocol version: $err"
        return "error"
    }
}

# Usage with error handling
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set version [safe_protocol_version $ctx]

if {$version ne "error"} {
    puts "Protocol version: $version"
} else {
    puts "Failed to retrieve protocol version"
}
```

```tcl
# Validate context before querying
proc validate_and_get_version {ctx} {
    # Check if context exists
    if {![info exists ctx] || $ctx eq ""} {
        puts "Error: Invalid context handle"
        return "invalid"
    }
    
    # Try to get protocol version
    if {[catch {
        set version [tossl::ssl::protocol_version -ctx $ctx]
        return $version
    } err]} {
        puts "Error getting protocol version: $err"
        return "error"
    }
}

# Usage
set result [validate_and_get_version $ctx]
```

## Integration with Other Commands

The `::tossl::ssl::protocol_version` command works with other SSL commands:

- **`::tossl::ssl::context create`** - Create SSL context
- **`::tossl::ssl::set_protocol_version`** - Set protocol version range
- **`::tossl::ssl::connect`** - Create SSL client connections
- **`::tossl::ssl::accept`** - Accept SSL server connections
- **`::tossl::ssl::socket_info`** - Get socket information

### Complete SSL Workflow Example

```tcl
# Complete SSL workflow with protocol version monitoring
proc secure_ssl_workflow {host port} {
    set ctx ""
    
    if {[catch {
        # 1. Create SSL context
        set ctx [tossl::ssl::context create -cert server.pem -key server.key]
        puts "✓ SSL context created"
        
        # 2. Set secure protocol versions
        tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
        puts "✓ Protocol versions configured"
        
        # 3. Verify protocol version
        set version [tossl::ssl::protocol_version -ctx $ctx]
        puts "✓ Minimum protocol version: $version"
        
        # 4. Establish SSL connection
        set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
        puts "✓ SSL connection established"
        
        # 5. Get connection information
        set socket_info [tossl::ssl::socket_info -conn $conn]
        puts "✓ Socket info: $socket_info"
        
        # 6. Perform SSL operations
        set request "GET / HTTP/1.1\r\nHost: $host\r\n\r\n"
        set bytes_written [tossl::ssl::write -conn $conn $request]
        puts "✓ Wrote $bytes_written bytes"
        
        set response [tossl::ssl::read -conn $conn -length 4096]
        puts "✓ Read [string length $response] bytes"
        
        return $response
        
    } err]} {
        puts "✗ SSL workflow failed: $err"
        return ""
    } finally {
        # 7. Clean up resources
        if {[info exists conn] && $conn ne ""} {
            catch {tossl::ssl::close -conn $conn}
        }
    }
}

# Usage
set response [secure_ssl_workflow "example.com" 443]
if {$response ne ""} {
    puts "Workflow completed successfully"
} else {
    puts "Workflow failed"
}
```

## Performance Considerations

### Efficiency

- **Fast lookup**: Uses linear search in global context array
- **Efficient query**: Direct OpenSSL function call
- **Minimal memory**: No additional memory allocation
- **Immediate return**: Returns immediately after version check

### Best Practices

```tcl
# Batch protocol version checking for better performance
proc batch_protocol_check {contexts} {
    set results {}
    
    foreach {name ctx} $contexts {
        if {[catch {
            set version [tossl::ssl::protocol_version -ctx $ctx]
            lappend results [list $name $version]
        } err]} {
            lappend results [list $name "error"]
        }
    }
    
    return $results
}

# Usage
set ctx1 [tossl::ssl::context create -cert server.pem -key server.key]
set ctx2 [tossl::ssl::context create -cert server.pem -key server.key]
set contexts [list "server1" $ctx1 "server2" $ctx2]

set versions [batch_protocol_check $contexts]
foreach {name version} $versions {
    puts "$name: $version"
}
```

## Security Considerations

### Security Features

- **Read-only operation**: No modification of SSL context
- **Secure query**: Uses OpenSSL's secure version functions
- **No information leakage**: Only exposes protocol version information
- **Safe access**: Thread-safe for concurrent access

### Security Best Practices

```tcl
# Secure protocol version monitoring
proc secure_protocol_monitor {ctx} {
    # Get protocol version securely
    if {[catch {
        set version [tossl::ssl::protocol_version -ctx $ctx]
        
        # Validate version security
        if {$version in {TLSv1.0 TLSv1.1}} {
            puts "⚠ SECURITY WARNING: Insecure protocol version: $version"
            return "insecure"
        } elseif {$version in {TLSv1.2 TLSv1.3}} {
            puts "✓ SECURE: Protocol version: $version"
            return "secure"
        } else {
            puts "? UNKNOWN: Protocol version: $version"
            return "unknown"
        }
    } err]} {
        puts "✗ ERROR: Failed to check protocol version: $err"
        return "error"
    }
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
set security_status [secure_protocol_monitor $ctx]
```

## Troubleshooting

### Common Issues

1. **Unknown protocol version**
   - **Cause**: OpenSSL version doesn't support the protocol
   - **Solution**: Upgrade OpenSSL or check version compatibility

2. **Context not found**
   - **Cause**: Context handle is invalid or context was freed
   - **Solution**: Verify context exists and is valid

3. **Unexpected protocol version**
   - **Cause**: Context was modified after creation
   - **Solution**: Check if `set_protocol_version` was called

### Debugging Tips

```tcl
# Debug protocol version issues
proc debug_protocol_version {ctx} {
    puts "=== Protocol Version Debug ==="
    puts "Context: $ctx"
    
    # Check if context exists
    if {[catch {tossl::ssl::protocol_version -ctx $ctx} err]} {
        puts "Context error: $err"
        return "invalid"
    }
    
    # Get protocol version
    set version [tossl::ssl::protocol_version -ctx $ctx]
    puts "Protocol version: $version"
    
    # Analyze version
    switch $version {
        "TLSv1.3" { puts "Status: Most secure" }
        "TLSv1.2" { puts "Status: Secure" }
        "TLSv1.1" { puts "Status: Deprecated" }
        "TLSv1.0" { puts "Status: Insecure" }
        "unknown" { puts "Status: Unknown/Unsupported" }
        default { puts "Status: Unexpected value" }
    }
    
    return $version
}

# Usage
set result [debug_protocol_version $ctx]
puts "Debug result: $result"
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::set_protocol_version` - Set protocol version range
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::socket_info` - Get socket information 