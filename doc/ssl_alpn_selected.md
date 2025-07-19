# ::tossl::ssl::alpn_selected

## Overview

The `::tossl::ssl::alpn_selected` command retrieves the negotiated Application-Layer Protocol Negotiation (ALPN) protocol from an established SSL/TLS connection. This command returns the protocol that was agreed upon during the SSL handshake between client and server.

## Syntax

```tcl
::tossl::ssl::alpn_selected -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns the negotiated ALPN protocol as a string. Common return values include:

- **`"h2"`** - HTTP/2 protocol
- **`"http/1.1"`** - HTTP/1.1 protocol  
- **`"http/1.0"`** - HTTP/1.0 protocol
- **`"spdy/1"`** - SPDY protocol
- **`"webrtc"`** - WebRTC protocol
- **`"ftp"`** - FTP protocol
- **`"imap"`** - IMAP protocol
- **`"pop3"`** - POP3 protocol
- **`"xmpp-client"`** - XMPP client protocol
- **`"xmpp-server"`** - XMPP server protocol
- **`""`** - Empty string if no ALPN protocol was negotiated

## Description

The `::tossl::ssl::alpn_selected` command queries the SSL connection to determine which application-layer protocol was negotiated during the SSL handshake. This is useful for applications that need to handle multiple protocols over the same SSL connection.

### How ALPN Works

1. **Client offers protocols**: During SSL handshake, client sends list of supported protocols
2. **Server selects protocol**: Server chooses preferred protocol from client's list
3. **Negotiation complete**: Both sides agree on the selected protocol
4. **Application uses protocol**: Application logic can query and use the negotiated protocol

### When to Use

- **Multi-protocol servers**: Handle HTTP/2 and HTTP/1.1 on same port
- **Protocol-specific logic**: Apply different handling based on negotiated protocol
- **Debugging**: Verify which protocol was actually negotiated
- **Load balancing**: Route traffic based on protocol capabilities

## Examples

### Basic ALPN Protocol Retrieval

```tcl
# Create SSL context
set ctx [tossl::ssl::context create]

# Connect with ALPN protocols
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443 -alpn h2,http/1.1]

# Get negotiated protocol
set protocol [tossl::ssl::alpn_selected -conn $conn]
puts "Negotiated protocol: $protocol"

# Handle based on protocol
switch $protocol {
    "h2" {
        puts "Using HTTP/2 for communication"
        # HTTP/2 specific handling
    }
    "http/1.1" {
        puts "Using HTTP/1.1 for communication"
        # HTTP/1.1 specific handling
    }
    default {
        puts "Unknown protocol: $protocol"
    }
}

# Clean up
tossl::ssl::close -conn $conn
```

### Server-Side ALPN Protocol Handling

```tcl
# Create server SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set ALPN callback for server
proc alpn_callback {protos} {
    puts "Client offered protocols: $protos"
    if {"h2" in $protos} {
        return "h2"
    }
    return [lindex $protos 0]
}

tossl::ssl::set_alpn_callback -ctx $ctx -callback alpn_callback

# Accept connection
set conn [tossl::ssl::accept -ctx $ctx -socket $client_socket]

# Get negotiated protocol
set protocol [tossl::ssl::alpn_selected -conn $conn]
puts "Server negotiated protocol: $protocol"

# Handle based on protocol
switch $protocol {
    "h2" {
        puts "Handling HTTP/2 request"
        # HTTP/2 specific server logic
    }
    "http/1.1" {
        puts "Handling HTTP/1.1 request"
        # HTTP/1.1 specific server logic
    }
}
```

### HTTP/2 Priority Server

```tcl
# Create HTTP/2 priority server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Define HTTP/2 priority callback
proc http2_priority {protos} {
    puts "Client offered: $protos"
    
    # Strict HTTP/2 preference
    if {"h2" in $protos} {
        puts "→ Selecting HTTP/2"
        return "h2"
    }
    
    # Reject if HTTP/2 not available
    puts "→ HTTP/2 not available, rejecting"
    return ""
}

tossl::ssl::set_alpn_callback -ctx $ctx -callback http2_priority

# Accept and check protocol
set conn [tossl::ssl::accept -ctx $ctx -socket $client_socket]
set protocol [tossl::ssl::alpn_selected -conn $conn]

if {$protocol eq "h2"} {
    puts "✓ HTTP/2 connection established"
    # Handle HTTP/2 traffic
} else {
    puts "✗ Non-HTTP/2 connection rejected"
    tossl::ssl::close -conn $conn
}
```

### Multi-Protocol Client

```tcl
# Create multi-protocol client
set ctx [tossl::ssl::context create]

# Connect with multiple protocol options
set conn [tossl::ssl::connect -ctx $ctx -host api.example.com -port 443 -alpn h2,http/1.1,spdy/1]

# Get negotiated protocol
set protocol [tossl::ssl::alpn_selected -conn $conn]
puts "Negotiated protocol: $protocol"

# Configure client based on protocol
switch $protocol {
    "h2" {
        puts "→ Using HTTP/2 client with multiplexing"
        set client_type "http2"
    }
    "http/1.1" {
        puts "→ Using HTTP/1.1 client with keep-alive"
        set client_type "http11"
    }
    "spdy/1" {
        puts "→ Using SPDY client (legacy)"
        set client_type "spdy"
    }
    default {
        puts "→ Using fallback client"
        set client_type "fallback"
    }
}

# Use protocol-specific client logic
puts "Client type: $client_type"
```

### Protocol Validation

```tcl
# Validate negotiated protocol
proc validate_alpn_protocol {conn expected_protocols} {
    set negotiated [tossl::ssl::alpn_selected -conn $conn]
    
    if {$negotiated in $expected_protocols} {
        puts "✓ Valid protocol negotiated: $negotiated"
        return 1
    } else {
        puts "✗ Invalid protocol negotiated: $negotiated"
        puts "  Expected one of: $expected_protocols"
        return 0
    }
}

# Usage
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443 -alpn h2,http/1.1]

if {[validate_alpn_protocol $conn {h2 http/1.1}]} {
    puts "Protocol validation passed"
} else {
    puts "Protocol validation failed"
    tossl::ssl::close -conn $conn
}
```

### Debugging ALPN Negotiation

```tcl
# Debug ALPN negotiation
proc debug_alpn_negotiation {conn} {
    set protocol [tossl::ssl::alpn_selected -conn $conn]
    
    puts "=== ALPN Negotiation Debug ==="
    puts "Connection: $conn"
    puts "Negotiated protocol: '$protocol'"
    puts "Protocol length: [string length $protocol]"
    
    if {$protocol eq ""} {
        puts "→ No ALPN protocol negotiated"
    } else {
        puts "→ ALPN protocol successfully negotiated"
    }
    
    return $protocol
}

# Usage
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443 -alpn h2,http/1.1]
set protocol [debug_alpn_negotiation $conn]
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
   # Error: wrong # args: should be "tossl::ssl::alpn_selected -conn conn"
   # Cause: Missing or incorrect parameters
   # Solution: Use correct syntax with -conn parameter
   ```

### Error Handling Examples

```tcl
# Safe ALPN protocol retrieval
proc safe_get_alpn_protocol {conn} {
    if {[catch {
        set protocol [tossl::ssl::alpn_selected -conn $conn]
        return $protocol
    } err]} {
        puts "Failed to get ALPN protocol: $err"
        return ""
    }
}

# Usage
set protocol [safe_get_alpn_protocol $conn]
if {$protocol ne ""} {
    puts "Protocol: $protocol"
} else {
    puts "No protocol or error occurred"
}
```

```tcl
# Validate connection before ALPN query
proc get_alpn_with_validation {conn} {
    # Check if connection exists
    if {![info exists conn] || $conn eq ""} {
        puts "Error: Invalid connection handle"
        return ""
    }
    
    # Try to get ALPN protocol
    if {[catch {
        set protocol [tossl::ssl::alpn_selected -conn $conn]
        return $protocol
    } err]} {
        puts "Error getting ALPN protocol: $err"
        return ""
    }
}

# Usage
set protocol [get_alpn_with_validation $conn]
```

## Integration with Other Commands

The `::tossl::ssl::alpn_selected` command works with:

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::set_alpn_callback` - Set ALPN callback for servers
- `::tossl::ssl::close` - Close SSL connections

### Complete ALPN Workflow

```tcl
# Complete ALPN workflow example
proc alpn_workflow {host port} {
    # 1. Create SSL context
    set ctx [tossl::ssl::context create]
    
    # 2. Connect with ALPN
    set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port -alpn h2,http/1.1]
    
    # 3. Get negotiated protocol
    set protocol [tossl::ssl::alpn_selected -conn $conn]
    
    # 4. Handle based on protocol
    switch $protocol {
        "h2" {
            puts "Using HTTP/2"
            # HTTP/2 specific logic
        }
        "http/1.1" {
            puts "Using HTTP/1.1"
            # HTTP/1.1 specific logic
        }
        default {
            puts "Unknown protocol: $protocol"
        }
    }
    
    # 5. Clean up
    tossl::ssl::close -conn $conn
    
    return $protocol
}

# Usage
set protocol [alpn_workflow "example.com" 443]
puts "Workflow completed with protocol: $protocol"
```

## Performance Considerations

### Efficiency

- **Fast retrieval**: Uses OpenSSL's `SSL_get0_alpn_selected()` for efficient lookup
- **No memory allocation**: Returns existing protocol string without copying
- **Minimal overhead**: Negligible performance impact
- **Immediate return**: No blocking or waiting operations

### Best Practices

```tcl
# Cache protocol for multiple uses
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443 -alpn h2,http/1.1]
set protocol [tossl::ssl::alpn_selected -conn $conn]

# Use cached value instead of calling multiple times
if {$protocol eq "h2"} {
    # HTTP/2 logic
} elseif {$protocol eq "http/1.1"} {
    # HTTP/1.1 logic
}
```

## Security Considerations

### Security Features

- **Read-only operation**: Only retrieves negotiated protocol, no modification
- **OpenSSL security**: Uses OpenSSL's secure ALPN implementation
- **No state exposure**: Doesn't expose internal SSL state
- **Safe concurrency**: Thread-safe for concurrent access
- **No information leakage**: Only returns negotiated protocol name

### Security Best Practices

```tcl
# Validate protocol before use
proc secure_protocol_handling {conn allowed_protocols} {
    set protocol [tossl::ssl::alpn_selected -conn $conn]
    
    if {$protocol in $allowed_protocols} {
        puts "✓ Protocol allowed: $protocol"
        return $protocol
    } else {
        puts "✗ Protocol not allowed: $protocol"
        puts "  Allowed: $allowed_protocols"
        return ""
    }
}

# Usage with security validation
set allowed {h2 http/1.1}
set protocol [secure_protocol_handling $conn $allowed]

if {$protocol ne ""} {
    # Process with validated protocol
} else {
    # Reject connection
    tossl::ssl::close -conn $conn
}
```

## Troubleshooting

### Common Issues

1. **Empty protocol returned**
   - **Cause**: No ALPN negotiation occurred
   - **Solution**: Check if client/server supports ALPN

2. **Unexpected protocol**
   - **Cause**: Client/server ALPN callback logic
   - **Solution**: Review ALPN callback implementation

3. **Connection errors**
   - **Cause**: Invalid or closed connection
   - **Solution**: Ensure connection is valid and open

### Debugging Tips

```tcl
# Debug ALPN negotiation
proc debug_alpn {conn} {
    puts "=== ALPN Debug ==="
    puts "Connection: $conn"
    
    if {[catch {
        set protocol [tossl::ssl::alpn_selected -conn $conn]
        puts "Protocol: '$protocol'"
        puts "Length: [string length $protocol]"
        puts "Valid: [string is ascii $protocol]"
    } err]} {
        puts "Error: $err"
    }
}

# Usage
debug_alpn $conn
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::set_alpn_callback` - Set ALPN callback for servers
- `::tossl::ssl::close` - Close SSL connections
- `::tossl::ssl::cipher_info` - Get cipher information
- `::tossl::ssl::protocol_version` - Get protocol version 