# ::tossl::ssl::context

## Overview

The `::tossl::ssl::context` command creates and manages SSL/TLS contexts for secure communication. An SSL context contains the configuration settings, certificates, and security parameters that will be used for SSL/TLS connections. This command is the foundation for all SSL/TLS operations in the ToSSL extension, providing a centralized way to configure security settings, certificates, and verification policies.

## Syntax

```tcl
::tossl::ssl::context create ?options?
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `create` | string | Yes | Subcommand to create a new SSL context |
| `options` | various | No | Configuration options for the SSL context |

### Available Options

| Option | Type | Description |
|--------|------|-------------|
| `-cert` | string | Path to server certificate file (PEM format) |
| `-key` | string | Path to server private key file (PEM format) |
| `-ca` | string | Path to CA certificate file for verification |
| `-verify` | string | Certificate verification mode: `peer`, `require`, or none |
| `-client_cert` | string | Path to client certificate file (PEM format) |
| `-client_key` | string | Path to client private key file (PEM format) |

## Return Value

Returns an SSL context handle (e.g., `sslctx1`) that can be used with other SSL commands like `::tossl::ssl::connect`, `::tossl::ssl::accept`, and various configuration commands.

## Description

The `::tossl::ssl::context create` command creates a new SSL/TLS context with the following default configuration:

- **Protocol Support**: Uses OpenSSL's `TLS_method()` for modern TLS support
- **Security Options**: Disables insecure protocols (SSLv2, SSLv3)
- **Verification**: No peer verification by default
- **Memory Management**: Efficient OpenSSL context management

The command supports various configuration options to customize the SSL context for different use cases:

1. **Server Configuration**: Load server certificates and keys
2. **Client Configuration**: Load client certificates for mutual authentication
3. **Verification Settings**: Configure certificate verification policies
4. **CA Configuration**: Load CA certificates for trust validation

## Examples

### Basic SSL Context Creation

```tcl
# Create a basic SSL context
set ctx [tossl::ssl::context create]
puts "SSL context created: $ctx"
# Output: SSL context created: sslctx1

# Verify context handle format
if {[regexp {^sslctx[0-9]+$} $ctx]} {
    puts "Context handle format is valid"
}
```

### Server SSL Context

```tcl
# Create SSL context for server with certificate and key
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key]

puts "Server context created: $ctx"

# Use context for SSL accept operations
set conn [tossl::ssl::accept -ctx $ctx -socket $client_socket]
```

### Client SSL Context with Verification

```tcl
# Create SSL context for client with CA verification
set ctx [tossl::ssl::context create \
    -ca ca.pem \
    -verify peer]

puts "Client context created: $ctx"

# Use context for SSL connect operations
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
```

### Mutual Authentication Context

```tcl
# Create context for mutual authentication
set ctx [tossl::ssl::context create \
    -cert client.pem \
    -key client.key \
    -ca ca.pem \
    -verify require]

puts "Mutual auth context created: $ctx"

# Both client and server will present certificates
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
```

### Complete Server Configuration

```tcl
# Create comprehensive server context
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -ca ca.pem \
    -verify peer \
    -client_cert client.pem \
    -client_key client.key]

puts "Complete server context created: $ctx"

# Configure additional features
tossl::ssl::set_cert_pinning -ctx $ctx -pins "pin1 pin2 pin3"
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable true
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
```

### Context for Different Use Cases

```tcl
# Development context (no verification)
set dev_ctx [tossl::ssl::context create]
puts "Development context: $dev_ctx"

# Production context (full verification)
set prod_ctx [tossl::ssl::context create \
    -ca ca.pem \
    -verify require]
puts "Production context: $prod_ctx"

# Testing context (peer verification)
set test_ctx [tossl::ssl::context create \
    -ca ca.pem \
    -verify peer]
puts "Testing context: $test_ctx"
```

### Context Management

```tcl
# Create multiple contexts for different purposes
set contexts {}

# Client context
set client_ctx [tossl::ssl::context create -ca ca.pem -verify peer]
lappend contexts $client_ctx

# Server context
set server_ctx [tossl::ssl::context create -cert server.pem -key server.key]
lappend contexts $server_ctx

# Admin context (mutual auth)
set admin_ctx [tossl::ssl::context create \
    -cert admin.pem -key admin.key \
    -ca ca.pem -verify require]
lappend contexts $admin_ctx

puts "Created contexts: $contexts"

# Use appropriate context for each operation
foreach {ctx_type ctx} {client $client_ctx server $server_ctx admin $admin_ctx} {
    puts "$ctx_type context: $ctx"
}
```

### Context with Advanced Features

```tcl
# Create context with all advanced features
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -ca ca.pem \
    -verify require]

puts "Advanced context created: $ctx"

# Set up ALPN callback
proc alpn_callback {protos} {
    if {"h2" in $protos} {
        return "h2"
    } elseif {"http/1.1" in $protos} {
        return "http/1.1"
    }
    return ""
}

tossl::ssl::set_alpn_callback -ctx $ctx -callback alpn_callback

# Set certificate pinning
tossl::ssl::set_cert_pinning -ctx $ctx -pins "sha256/pin1 sha256/pin2"

# Enable OCSP stapling
tossl::ssl::set_ocsp_stapling -ctx $ctx -enable true

# Set protocol version range
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

puts "Advanced features configured"
```

## Error Handling

### Common Errors

1. **Failed to create SSL context**
   ```tcl
   # Error: Failed to create SSL context
   # Cause: OpenSSL initialization failure or memory issues
   # Solution: Check OpenSSL installation and system resources
   ```

2. **Failed to load certificate**
   ```tcl
   # Error: Failed to load certificate
   # Cause: Invalid certificate file or format
   # Solution: Verify certificate file exists and is in PEM format
   ```

3. **Failed to load private key**
   ```tcl
   # Error: Failed to load private key
   # Cause: Invalid key file or format
   # Solution: Verify key file exists and is in PEM format
   ```

4. **Failed to load CA certificate**
   ```tcl
   # Error: Failed to load CA certificate
   # Cause: Invalid CA certificate file
   # Solution: Verify CA certificate file exists and is valid
   ```

### Error Handling Examples

```tcl
# Safe context creation with error handling
proc safe_create_context {args} {
    if {[catch {
        set ctx [tossl::ssl::context create {*}$args]
        return $ctx
    } err]} {
        puts "Failed to create SSL context: $err"
        return ""
    }
}

# Usage
set ctx [safe_create_context -cert server.pem -key server.key]
if {$ctx ne ""} {
    puts "Context created successfully: $ctx"
} else {
    puts "Context creation failed"
}
```

```tcl
# Validate certificate files before context creation
proc validate_and_create_context {cert_file key_file} {
    # Check if files exist
    if {![file exists $cert_file]} {
        puts "Certificate file not found: $cert_file"
        return ""
    }
    if {![file exists $key_file]} {
        puts "Key file not found: $key_file"
        return ""
    }
    
    # Try to create context
    if {[catch {
        set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
        return $ctx
    } err]} {
        puts "Context creation failed: $err"
        return ""
    }
}

# Usage
set ctx [validate_and_create_context "server.pem" "server.key"]
```

```tcl
# Context creation with fallback options
proc create_context_with_fallback {primary_cert backup_cert} {
    # Try primary certificate
    if {[file exists $primary_cert]} {
        if {[catch {
            set ctx [tossl::ssl::context create -cert $primary_cert]
            return $ctx
        } err]} {
            puts "Primary certificate failed: $err"
        }
    }
    
    # Try backup certificate
    if {[file exists $backup_cert]} {
        if {[catch {
            set ctx [tossl::ssl::context create -cert $backup_cert]
            return $ctx
        } err]} {
            puts "Backup certificate failed: $err"
            return ""
        }
    }
    
    # Create context without certificate
    if {[catch {
        set ctx [tossl::ssl::context create]
        return $ctx
    } err]} {
        puts "Context creation failed: $err"
        return ""
    }
}

# Usage
set ctx [create_context_with_fallback "server.pem" "backup.pem"]
```

## Integration with Other Commands

The `::tossl::ssl::context create` command works with:

- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::set_cert_pinning` - Configure certificate pinning
- `::tossl::ssl::set_ocsp_stapling` - Enable OCSP stapling
- `::tossl::ssl::set_protocol_version` - Set protocol version range
- `::tossl::ssl::set_alpn_callback` - Configure ALPN callback

### Complete SSL Workflow

```tcl
# Complete SSL workflow example
proc ssl_workflow {host port cert_file key_file} {
    # 1. Create SSL context
    set ctx [tossl::ssl::context create \
        -cert $cert_file \
        -key $key_file \
        -verify peer]
    
    # 2. Configure additional features
    tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
    tossl::ssl::set_cert_pinning -ctx $ctx -pins "sha256/pin1"
    
    # 3. Establish connection
    set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
    
    # 4. Perform SSL operations
    set data [tossl::ssl::read -conn $conn -length 1024]
    tossl::ssl::write -conn $conn $data
    
    # 5. Get connection information
    set info [tossl::ssl::socket_info -conn $conn]
    set cipher_info [tossl::ssl::cipher_info -conn $conn]
    
    # 6. Clean up
    tossl::ssl::close -conn $conn
    
    return [list context $ctx info $info cipher $cipher_info]
}

# Usage
set result [ssl_workflow "example.com" 443 "client.pem" "client.key"]
puts "Workflow completed: $result"
```

## Performance Considerations

### Efficiency

- **Fast creation**: Uses OpenSSL's optimized context creation
- **Memory efficient**: Minimal memory overhead for context storage
- **Reusable**: Contexts can be reused for multiple connections
- **Thread-safe**: Safe for concurrent access in multi-threaded applications

### Best Practices

```tcl
# Cache contexts for reuse
set contexts {}

proc get_or_create_context {type} {
    global contexts
    
    if {[dict exists $contexts $type]} {
        return [dict get $contexts $type]
    }
    
    # Create new context based on type
    switch $type {
        "client" {
            set ctx [tossl::ssl::context create -ca ca.pem -verify peer]
        }
        "server" {
            set ctx [tossl::ssl::context create -cert server.pem -key server.key]
        }
        "admin" {
            set ctx [tossl::ssl::context create \
                -cert admin.pem -key admin.key \
                -ca ca.pem -verify require]
        }
        default {
            set ctx [tossl::ssl::context create]
        }
    }
    
    dict set contexts $type $ctx
    return $ctx
}

# Usage
set client_ctx [get_or_create_context "client"]
set server_ctx [get_or_create_context "server"]
```

## Security Considerations

### Security Features

- **Protocol security**: Disables insecure SSLv2/SSLv3 protocols
- **Certificate verification**: Configurable peer certificate verification
- **Client authentication**: Support for mutual authentication
- **Certificate pinning**: Prevents certificate substitution attacks
- **OCSP stapling**: Real-time certificate status checking

### Security Best Practices

```tcl
# Secure context creation
proc create_secure_context {cert_file key_file ca_file} {
    # Validate file permissions
    if {[file readable $cert_file] && [file readable $key_file]} {
        # Check key file permissions (should be 600)
        set key_perms [file attributes $key_file -permissions]
        if {$key_perms != "0600"} {
            puts "Warning: Key file should have 600 permissions"
        }
    }
    
    # Create context with security options
    set ctx [tossl::ssl::context create \
        -cert $cert_file \
        -key $key_file \
        -ca $ca_file \
        -verify require]
    
    # Enable additional security features
    tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
    tossl::ssl::set_cert_pinning -ctx $ctx -pins "sha256/secure_pin"
    tossl::ssl::set_ocsp_stapling -ctx $ctx -enable true
    
    return $ctx
}

# Usage
set ctx [create_secure_context "server.pem" "server.key" "ca.pem"]
```

```tcl
# Context validation
proc validate_context_security {ctx} {
    puts "=== Context Security Validation ==="
    
    # Check if context exists
    if {[catch {
        # Try to use context for a test operation
        set test_conn [tossl::ssl::connect -ctx $ctx -host "test.example.com" -port 443]
        tossl::ssl::close -conn $test_conn
        puts "✓ Context is functional"
    } err]} {
        puts "✗ Context validation failed: $err"
        return 0
    }
    
    puts "✓ Context security validation passed"
    return 1
}

# Usage
if {[validate_context_security $ctx]} {
    puts "Context is ready for production use"
} else {
    puts "Context needs security review"
}
```

## Troubleshooting

### Common Issues

1. **Certificate format issues**
   - **Cause**: Non-PEM format certificates
   - **Solution**: Convert certificates to PEM format

2. **Key file permissions**
   - **Cause**: Insecure key file permissions
   - **Solution**: Set key file permissions to 600

3. **CA certificate chain issues**
   - **Cause**: Incomplete certificate chain
   - **Solution**: Include full certificate chain in CA file

4. **Protocol version conflicts**
   - **Cause**: Server/client protocol mismatch
   - **Solution**: Configure appropriate protocol version range

### Debugging Tips

```tcl
# Debug context creation
proc debug_context_creation {args} {
    puts "=== Context Creation Debug ==="
    puts "Arguments: $args"
    
    # Check file existence
    foreach {opt value} $args {
        if {$opt in {-cert -key -ca -client_cert -client_key}} {
            if {[file exists $value]} {
                puts "✓ File exists: $value"
                puts "  Size: [file size $value] bytes"
                puts "  Permissions: [file attributes $value -permissions]"
            } else {
                puts "✗ File missing: $value"
            }
        }
    }
    
    # Try to create context
    if {[catch {
        set ctx [tossl::ssl::context create {*}$args]
        puts "✓ Context created: $ctx"
        return $ctx
    } err]} {
        puts "✗ Context creation failed: $err"
        return ""
    }
}

# Usage
set ctx [debug_context_creation -cert server.pem -key server.key]
```

## See Also

- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::set_cert_pinning` - Configure certificate pinning
- `::tossl::ssl::set_ocsp_stapling` - Enable OCSP stapling
- `::tossl::ssl::set_protocol_version` - Set protocol version range
- `::tossl::ssl::set_alpn_callback` - Configure ALPN callback
- `::tossl::ssl::socket_info` - Get socket information
- `::tossl::ssl::cipher_info` - Get cipher information 