# ::tossl::ssl::set_alpn_callback

## Overview

The `::tossl::ssl::set_alpn_callback` command registers a Tcl callback function for Application-Layer Protocol Negotiation (ALPN) in SSL/TLS connections. This allows applications to dynamically select the most appropriate protocol during the SSL handshake based on client preferences and server capabilities.

## Syntax

```tcl
::tossl::ssl::set_alpn_callback -ctx context -callback callback_name
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-callback` | string | Yes | Name of the Tcl procedure to call during ALPN negotiation |

## Return Value

Returns `"ok"` on success, or throws an error on failure.

## Description

The `::tossl::ssl::set_alpn_callback` command configures an ALPN callback for an SSL context. When a client connects and offers ALPN protocols, the callback function is invoked with the list of offered protocols, allowing the server to select the most appropriate one.

### ALPN Callback Function Signature

The callback function must accept one parameter (the list of offered protocols) and return the selected protocol name:

```tcl
proc alpn_callback {protocols} {
    # protocols is a Tcl list of offered protocols
    # Return the selected protocol name
    return "selected_protocol"
}
```

### How ALPN Works

1. **Client offers protocols**: During SSL handshake, client sends list of supported protocols
2. **Server callback invoked**: TOSSL calls the registered Tcl callback with the offered protocols
3. **Protocol selection**: Callback returns the preferred protocol from the offered list
4. **Negotiation complete**: Both client and server agree on the selected protocol

### Supported Protocols

Common ALPN protocols include:
- **h2**: HTTP/2 (RFC 7540)
- **http/1.1**: HTTP/1.1
- **http/1.0**: HTTP/1.0
- **spdy/1**: SPDY protocol
- **spdy/2**: SPDY protocol
- **spdy/3**: SPDY protocol
- **webrtc**: WebRTC
- **c-webrtc**: WebRTC over reliable transport
- **ftp**: FTP
- **imap**: IMAP
- **pop3**: POP3
- **managesieve**: ManageSieve
- **coap**: CoAP
- **xmpp-client**: XMPP client
- **xmpp-server**: XMPP server
- **acme-tls/1**: ACME TLS protocol

## Examples

### Basic ALPN Callback

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Define ALPN callback
proc alpn_select {protos} {
    puts "ALPN callback called with: $protos"
    
    # Prefer HTTP/2 if available
    if {"h2" in $protos} {
        puts "Selecting HTTP/2"
        return "h2"
    }
    
    # Fall back to HTTP/1.1
    if {"http/1.1" in $protos} {
        puts "Selecting HTTP/1.1"
        return "http/1.1"
    }
    
    # Default to first available
    set selected [lindex $protos 0]
    puts "Selecting first available: $selected"
    return $selected
}

# Register the callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback alpn_select
```

### HTTP/2 Priority ALPN Callback

```tcl
# Create context for HTTP/2 server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Define HTTP/2 priority callback
proc http2_priority {protos} {
    puts "HTTP/2 priority callback called with: $protos"
    
    # Strict HTTP/2 preference
    if {"h2" in $protos} {
        puts "→ Selecting HTTP/2 (h2)"
        return "h2"
    }
    
    # Reject connection if HTTP/2 not available
    puts "→ HTTP/2 not available, rejecting connection"
    return ""
}

# Register callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback http2_priority
```

### Multi-Protocol Server

```tcl
# Create context for multi-protocol server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Define multi-protocol callback
proc multi_protocol_select {protos} {
    puts "Multi-protocol callback called with: $protos"
    
    # Priority order: h2 > http/1.1 > others
    set priorities {h2 http/1.1 http/1.0}
    
    foreach proto $priorities {
        if {$proto in $protos} {
            puts "→ Selecting $proto"
            return $proto
        }
    }
    
    # If none of our priorities are available, select first
    set selected [lindex $protos 0]
    puts "→ Selecting fallback: $selected"
    return $selected
}

# Register callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback multi_protocol_select
```

### Custom Protocol Handler

```tcl
# Create context for custom protocol
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Define custom protocol callback
proc custom_protocol_select {protos} {
    puts "Custom protocol callback called with: $protos"
    
    # Check for our custom protocol
    if {"myapp/v1" in $protos} {
        puts "→ Selecting custom protocol: myapp/v1"
        return "myapp/v1"
    }
    
    # Check for our custom protocol v2
    if {"myapp/v2" in $protos} {
        puts "→ Selecting custom protocol: myapp/v2"
        return "myapp/v2"
    }
    
    # Fall back to HTTP/1.1 for web interface
    if {"http/1.1" in $protos} {
        puts "→ Selecting HTTP/1.1 for web interface"
        return "http/1.1"
    }
    
    # Reject if no suitable protocol
    puts "→ No suitable protocol found"
    return ""
}

# Register callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback custom_protocol_select
```

### Complete SSL Server with ALPN

```tcl
# Create secure SSL server with ALPN
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set secure protocol versions
tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3

# Define ALPN callback
proc server_alpn_select {protos} {
    puts "Server ALPN callback called with: $protos"
    
    # Prefer HTTP/2 for better performance
    if {"h2" in $protos} {
        puts "→ Selecting HTTP/2"
        return "h2"
    }
    
    # Accept HTTP/1.1 as fallback
    if {"http/1.1" in $protos} {
        puts "→ Selecting HTTP/1.1"
        return "http/1.1"
    }
    
    # Reject other protocols
    puts "→ Rejecting unsupported protocols"
    return ""
}

# Register ALPN callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback server_alpn_select

# Create server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    fconfigure $sock -blocking 1
    
    # Accept SSL connection with ALPN
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Get negotiated protocol
    set protocol [tossl::ssl::alpn_selected -conn $ssl_conn]
    puts "Negotiated protocol: $protocol"
    
    # Handle based on protocol
    switch $protocol {
        "h2" {
            puts "Handling HTTP/2 connection"
            # HTTP/2 specific handling
        }
        "http/1.1" {
            puts "Handling HTTP/1.1 connection"
            # HTTP/1.1 specific handling
        }
        default {
            puts "Unknown protocol: $protocol"
        }
    }
    
    # Send response
    tossl::ssl::write -conn $ssl_conn "Hello from $protocol server!"
    
    tossl::ssl::close -conn $ssl_conn
    close $sock
}
```

### Error Handling Example

```tcl
proc safe_set_alpn_callback {ctx callback_name} {
    if {[catch {
        tossl::ssl::set_alpn_callback -ctx $ctx -callback $callback_name
    } err]} {
        puts "Failed to set ALPN callback: $err"
        return 0
    }
    return 1
}

# Usage
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

proc my_alpn_callback {protos} {
    return [lindex $protos 0]
}

if {[safe_set_alpn_callback $ctx my_alpn_callback]} {
    puts "ALPN callback set successfully"
} else {
    puts "Failed to set ALPN callback"
}
```

## Error Handling

The command may return the following errors:

| Error | Description | Resolution |
|-------|-------------|------------|
| `wrong # args` | Incorrect number of arguments | Provide exactly 5 arguments: command, -ctx, ctx, -callback, callback |
| `SSL context not found` | Invalid context handle | Verify context was created with `::tossl::ssl::context create` |

## Security Considerations

### Protocol Selection Security

- **Validate offered protocols**: Ensure only expected protocols are accepted
- **Avoid protocol downgrade**: Don't select weaker protocols when stronger ones are available
- **Reject unknown protocols**: Return empty string for unsupported protocols

### Callback Function Security

```tcl
# Secure ALPN callback example
proc secure_alpn_callback {protos} {
    # Validate input
    if {![llength $protos]} {
        puts "Warning: Empty protocol list"
        return ""
    }
    
    # Define allowed protocols
    set allowed_protocols {h2 http/1.1}
    
    # Check each offered protocol
    foreach proto $protos {
        if {$proto in $allowed_protocols} {
            puts "Accepting protocol: $proto"
            return $proto
        }
    }
    
    # Reject if no allowed protocols
    puts "Rejecting connection - no allowed protocols"
    return ""
}
```

### Best Practices

```tcl
# Recommended: Strict protocol validation
proc strict_alpn_callback {protos} {
    # Only accept known, secure protocols
    if {"h2" in $protos} {
        return "h2"
    }
    if {"http/1.1" in $protos} {
        return "http/1.1"
    }
    # Reject everything else
    return ""
}

# Avoid: Accepting any protocol
proc unsafe_alpn_callback {protos} {
    # DON'T DO THIS - accepts any protocol
    return [lindex $protos 0]
}
```

## Performance Considerations

### Callback Performance

- **Keep callbacks fast**: ALPN callbacks are called during handshake
- **Avoid blocking operations**: Don't perform I/O or heavy computation
- **Cache decisions**: Consider caching protocol preferences

### Resource Management

```tcl
# Efficient ALPN callback with caching
set protocol_cache {}

proc cached_alpn_callback {protos} {
    global protocol_cache
    
    # Check cache first
    set cache_key [join $protos ","]
    if {[info exists protocol_cache($cache_key)]} {
        return $protocol_cache($cache_key)
    }
    
    # Make selection
    set selected ""
    if {"h2" in $protos} {
        set selected "h2"
    } elseif {"http/1.1" in $protos} {
        set selected "http/1.1"
    }
    
    # Cache result
    set protocol_cache($cache_key) $selected
    return $selected
}
```

## Integration with Other Commands

The ALPN callback works with:

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::ssl::alpn_selected` - Get negotiated protocol
- `::tossl::ssl::connect` - Client connections with ALPN

### Client-Side ALPN Example

```tcl
# Client with ALPN support
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
    }
    "http/1.1" {
        puts "Using HTTP/1.1 for communication"
    }
    default {
        puts "Unknown protocol: $protocol"
    }
}
```

## Troubleshooting

### Common Issues

1. **Callback Not Called**
   - Verify callback is registered before SSL handshake
   - Check if client supports ALPN
   - Ensure protocol versions support ALPN (TLS 1.2+)

2. **Unexpected Protocol Selected**
   - Review callback logic
   - Check client's offered protocols
   - Verify callback return value

3. **Connection Fails After ALPN**
   - Ensure callback returns valid protocol from offered list
   - Check for empty string returns
   - Verify protocol name spelling

### Debugging Tips

```tcl
# Debug ALPN callback
proc debug_alpn_callback {protos} {
    puts "DEBUG: ALPN callback called"
    puts "DEBUG: Offered protocols: $protos"
    puts "DEBUG: Protocol count: [llength $protos]"
    
    foreach proto $protos {
        puts "DEBUG: Protocol: '$proto'"
    }
    
    set selected [lindex $protos 0]
    puts "DEBUG: Selecting: '$selected'"
    return $selected
}

# Register debug callback
tossl::ssl::set_alpn_callback -ctx $ctx -callback debug_alpn_callback
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::ssl::alpn_selected` - Get negotiated ALPN protocol
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::set_protocol_version` - Set TLS protocol versions 