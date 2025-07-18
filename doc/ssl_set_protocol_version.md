# ::tossl::ssl::set_protocol_version

## Overview

The `::tossl::ssl::set_protocol_version` command configures the minimum and maximum TLS protocol versions for an SSL context. This allows fine-grained control over which TLS versions are acceptable for SSL/TLS connections, enabling security policy enforcement and compatibility management.

## Syntax

```tcl
::tossl::ssl::set_protocol_version -ctx context -min min_version -max max_version
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-min` | string | Yes | Minimum TLS version (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3) |
| `-max` | string | Yes | Maximum TLS version (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3) |

## Return Value

Returns `"ok"` on success, or throws an error on failure.

## Description

The `::tossl::ssl::set_protocol_version` command configures the acceptable TLS protocol version range for an SSL context. This setting affects all SSL/TLS connections created using this context, both as client and server.

### Supported TLS Versions

- **TLSv1.0**: TLS 1.0 (RFC 2246) - Deprecated, not recommended for security
- **TLSv1.1**: TLS 1.1 (RFC 4346) - Deprecated, not recommended for security  
- **TLSv1.2**: TLS 1.2 (RFC 5246) - Widely supported, secure
- **TLSv1.3**: TLS 1.3 (RFC 8446) - Latest version, most secure and performant

### Version Range Logic

The command sets both minimum and maximum protocol versions, creating an acceptable range. For example:
- `-min TLSv1.2 -max TLSv1.3`: Accepts only TLS 1.2 and 1.3
- `-min TLSv1.3 -max TLSv1.3`: Accepts only TLS 1.3
- `-min TLSv1.0 -max TLSv1.3`: Accepts all TLS versions (not recommended)

## Examples

### Basic Protocol Version Setting

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set to accept only TLS 1.2 and 1.3 (recommended)
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Verify the setting
set version_info [tossl::ssl::protocol_version -ctx $ctx]
puts "Protocol version range: $version_info"
```

### Security-Focused Configuration

```tcl
# Create context for high-security applications
set secure_ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Accept only TLS 1.3 (most secure)
tossl::ssl::set_protocol_version -ctx $secure_ctx -min TLSv1.3 -max TLSv1.3

# Use for sensitive connections
set conn [tossl::ssl::connect -ctx $secure_ctx -host example.com -port 443]
```

### Compatibility Configuration

```tcl
# Create context for legacy compatibility
set compat_ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Accept TLS 1.2 and 1.3 (good balance of security and compatibility)
tossl::ssl::set_protocol_version -ctx $compat_ctx -min TLSv1.2 -max TLSv1.3

# Use for connections that need broader compatibility
```

### Multiple Contexts with Different Policies

```tcl
# Create contexts for different security levels
set high_sec_ctx [tossl::ssl::context create -cert server.pem -key server.key]
set standard_ctx [tossl::ssl::context create -cert server.pem -key server.key]
set legacy_ctx [tossl::ssl::context create -cert server.pem -key server.key]

# High security: TLS 1.3 only
tossl::ssl::set_protocol_version -ctx $high_sec_ctx -min TLSv1.3 -max TLSv1.3

# Standard: TLS 1.2 and 1.3
tossl::ssl::set_protocol_version -ctx $standard_ctx -min TLSv1.2 -max TLSv1.3

# Legacy: All TLS versions (not recommended)
tossl::ssl::set_protocol_version -ctx $legacy_ctx -min TLSv1.0 -max TLSv1.3

# Use appropriate context based on security requirements
```

### Error Handling Example

```tcl
proc safe_set_protocol_version {ctx min_ver max_ver} {
    if {[catch {
        tossl::ssl::set_protocol_version -ctx $ctx -min $min_ver -max $max_ver
    } err]} {
        puts "Failed to set protocol version: $err"
        return 0
    }
    return 1
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
if {[safe_set_protocol_version $ctx TLSv1.2 TLSv1.3]} {
    puts "Protocol version set successfully"
} else {
    puts "Failed to set protocol version"
}
```

## Error Handling

The command may return the following errors:

| Error | Description | Resolution |
|-------|-------------|------------|
| `wrong # args` | Incorrect number of arguments | Provide exactly 7 arguments: command, -ctx, ctx, -min, min, -max, max |
| `Missing required parameters` | Missing required parameters | Ensure all three parameters (-ctx, -min, -max) are provided |
| `SSL context not found` | Invalid context handle | Verify context was created with `::tossl::ssl::context create` |

## Security Considerations

### Protocol Version Security

| TLS Version | Security Level | Recommendation |
|-------------|----------------|----------------|
| TLSv1.0 | **Insecure** | Never use in production |
| TLSv1.1 | **Insecure** | Never use in production |
| TLSv1.2 | **Secure** | Acceptable for most applications |
| TLSv1.3 | **Most Secure** | Recommended for new applications |

### Best Practices

```tcl
# Recommended: TLS 1.2 and 1.3 only
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# High security: TLS 1.3 only
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.3 -max TLSv1.3

# Avoid: Deprecated versions
# tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.0 -max TLSv1.1
```

### Security Policy Examples

```tcl
# Financial/Healthcare applications
set high_sec_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $high_sec_ctx -min TLSv1.3 -max TLSv1.3

# General web applications
set web_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $web_ctx -min TLSv1.2 -max TLSv1.3

# Internal/Development applications
set dev_ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $dev_ctx -min TLSv1.2 -max TLSv1.2
```

## Performance Considerations

### Protocol Version Impact

- **TLS 1.3**: Fastest handshake, best performance
- **TLS 1.2**: Good performance, widely supported
- **TLS 1.1/1.0**: Slower, deprecated

### Resource Management

```tcl
# Create contexts with appropriate protocol versions
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set protocol version before creating connections
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Reuse context for multiple connections
for {set i 0} {$i < 10} {incr i} {
    set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
    # Use connection...
    tossl::ssl::close -conn $conn
}
```

## Integration with Other Commands

The protocol version setting works with:

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Client connections
- `::tossl::ssl::accept` - Server connections
- `::tossl::ssl::protocol_version` - Retrieve current settings

### Complete SSL Server Example

```tcl
# Create secure SSL server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set secure protocol versions
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Create server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    fconfigure $sock -blocking 1
    
    # Accept SSL connection with configured protocol versions
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Get negotiated protocol version
    set version [tossl::ssl::protocol_version -ctx $ctx]
    puts "Negotiated TLS version: $version"
    
    # Handle secure communication
    set data [tossl::ssl::read -conn $ssl_conn -length 1024]
    tossl::ssl::write -conn $ssl_conn "Secure response"
    
    tossl::ssl::close -conn $ssl_conn
    close $sock
}
```

## Troubleshooting

### Common Issues

1. **Connection Fails After Setting Protocol Version**
   - Check if client supports the configured TLS versions
   - Verify protocol version range is valid (min ≤ max)
   - Ensure context is valid and properly created

2. **Unexpected Protocol Version Negotiated**
   - Verify protocol version settings with `::tossl::ssl::protocol_version`
   - Check if client/server supports the configured versions
   - Review OpenSSL version compatibility

3. **Performance Issues**
   - Use TLS 1.3 for best performance
   - Avoid deprecated TLS versions
   - Consider cipher suite selection

### Debugging Tips

```tcl
# Check current protocol version settings
set ctx [tossl::ssl::context create -cert server.pem -key server.key]
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Verify settings
set version_info [tossl::ssl::protocol_version -ctx $ctx]
puts "Protocol version info: $version_info"

# Test connection with specific versions
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
set negotiated_version [tossl::ssl::protocol_version -ctx $ctx]
puts "Negotiated version: $negotiated_version"
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::protocol_version` - Get current protocol version settings
- `::tossl::ssl::connect` - Create SSL client connection
- `::tossl::ssl::accept` - Accept SSL server connection
- `::tossl::ssl::cipher_info` - Get cipher suite information 