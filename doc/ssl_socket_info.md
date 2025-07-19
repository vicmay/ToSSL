# ::tossl::ssl::socket_info

## Overview

The `::tossl::ssl::socket_info` command retrieves detailed information about an SSL/TLS connection's underlying socket and SSL object. This command provides essential debugging and monitoring information including the file descriptor, SSL object pointer, and negotiated protocol version. This information is crucial for troubleshooting SSL connections, monitoring protocol versions, and understanding connection state.

## Syntax

```tcl
::tossl::ssl::socket_info -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns a formatted string containing socket information in the format:
```
fd=<file_descriptor>, ssl=<ssl_object_pointer>, protocol=<ssl_protocol_version>
```

Where:
- **`fd`**: The underlying socket file descriptor number
- **`ssl`**: Memory address of the SSL object (hexadecimal)
- **`protocol`**: The negotiated SSL/TLS protocol version (e.g., "TLSv1.3", "TLSv1.2")

## Description

The `::tossl::ssl::socket_info` command provides low-level information about an SSL/TLS connection that is useful for:

- **Debugging**: Understanding connection state and protocol negotiation
- **Monitoring**: Tracking protocol versions and socket usage
- **Troubleshooting**: Identifying connection issues and SSL object state
- **Performance Analysis**: Monitoring file descriptor usage and connection details

The command performs the following operations:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Socket Retrieval**: Gets the underlying socket file descriptor from the connection
3. **SSL Object Access**: Retrieves the SSL object pointer for the connection
4. **Protocol Detection**: Determines the negotiated SSL/TLS protocol version
5. **Information Formatting**: Formats the information into a readable string

## Examples

### Basic Socket Information Retrieval

```tcl
# Create SSL context
set ctx [tossl::ssl::context create]

# Connect to a server
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Get socket information
set info [tossl::ssl::socket_info -conn $conn]
puts "Socket info: $info"
# Output: Socket info: fd=3, ssl=0x7f8b2c001234, protocol=TLSv1.3

# Parse the information
if {[regexp {^fd=(\d+), ssl=(0x[0-9a-f]+), protocol=([A-Za-z0-9.]+)$} $info -> fd ssl_ptr protocol]} {
    puts "File descriptor: $fd"
    puts "SSL object: $ssl_ptr"
    puts "Protocol: $protocol"
}

# Clean up
tossl::ssl::close -conn $conn
```

### Server-Side Socket Information

```tcl
# Create server SSL context
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Accept connection
set conn [tossl::ssl::accept -ctx $ctx -socket $client_socket]

# Get socket information
set info [tossl::ssl::socket_info -conn $conn]
puts "Server socket info: $info"

# Extract protocol version
if {[regexp {protocol=([A-Za-z0-9.]+)} $info -> protocol]} {
    puts "Negotiated protocol: $protocol"
    
    # Handle based on protocol
    switch $protocol {
        "TLSv1.3" {
            puts "Using modern TLS 1.3"
        }
        "TLSv1.2" {
            puts "Using TLS 1.2"
        }
        default {
            puts "Using legacy protocol: $protocol"
        }
    }
}
```

### Connection Debugging

```tcl
# Debug connection information
proc debug_ssl_connection {conn} {
    puts "=== SSL Connection Debug ==="
    
    # Get socket info
    set info [tossl::ssl::socket_info -conn $conn]
    puts "Socket info: $info"
    
    # Parse components
    if {[regexp {^fd=(\d+), ssl=(0x[0-9a-f]+), protocol=([A-Za-z0-9.]+)$} $info -> fd ssl_ptr protocol]} {
        puts "File descriptor: $fd"
        puts "SSL object address: $ssl_ptr"
        puts "Protocol version: $protocol"
        
        # Validate protocol
        if {$protocol in {TLSv1.3 TLSv1.2}} {
            puts "✓ Protocol is secure"
        } else {
            puts "⚠ Protocol may be insecure: $protocol"
        }
    } else {
        puts "✗ Could not parse socket info"
    }
}

# Usage
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
debug_ssl_connection $conn
```

### Protocol Version Monitoring

```tcl
# Monitor protocol versions across connections
proc monitor_protocol_versions {connections} {
    puts "=== Protocol Version Monitor ==="
    
    foreach conn $connections {
        if {[catch {
            set info [tossl::ssl::socket_info -conn $conn]
            if {[regexp {protocol=([A-Za-z0-9.]+)} $info -> protocol]} {
                puts "Connection $conn: $protocol"
            }
        } err]} {
            puts "Connection $conn: Error - $err"
        }
    }
}

# Usage
set connections [list $conn1 $conn2 $conn3]
monitor_protocol_versions $connections
```

### File Descriptor Tracking

```tcl
# Track file descriptor usage
proc track_file_descriptors {connections} {
    puts "=== File Descriptor Tracking ==="
    
    set fds {}
    foreach conn $connections {
        if {[catch {
            set info [tossl::ssl::socket_info -conn $conn]
            if {[regexp {fd=(\d+)} $info -> fd]} {
                lappend fds $fd
                puts "Connection $conn uses fd $fd"
            }
        } err]} {
            puts "Connection $conn: Error - $err"
        }
    }
    
    puts "Total file descriptors: [llength $fds]"
    puts "Unique file descriptors: [lsort -unique $fds]"
    return $fds
}

# Usage
set fds [track_file_descriptors [list $conn1 $conn2 $conn3]]
```

### Connection State Validation

```tcl
# Validate connection state
proc validate_connection_state {conn} {
    puts "=== Connection State Validation ==="
    
    if {[catch {
        set info [tossl::ssl::socket_info -conn $conn]
        puts "Connection info: $info"
        
        # Check if info is well-formed
        if {[regexp {^fd=\d+, ssl=0x[0-9a-f]+, protocol=[A-Za-z0-9.]+$} $info]} {
            puts "✓ Connection state is valid"
            return 1
        } else {
            puts "✗ Connection state is invalid"
            return 0
        }
    } err]} {
        puts "✗ Connection validation failed: $err"
        return 0
    }
}

# Usage
if {[validate_connection_state $conn]} {
    puts "Connection is ready for use"
} else {
    puts "Connection needs attention"
}
```

### Performance Analysis

```tcl
# Analyze connection performance characteristics
proc analyze_connection_performance {conn} {
    puts "=== Connection Performance Analysis ==="
    
    set info [tossl::ssl::socket_info -conn $conn]
    
    # Extract protocol for performance analysis
    if {[regexp {protocol=([A-Za-z0-9.]+)} $info -> protocol]} {
        puts "Protocol: $protocol"
        
        # Protocol-specific performance notes
        switch $protocol {
            "TLSv1.3" {
                puts "✓ Modern protocol with optimal performance"
                puts "  - Zero-RTT resumption support"
                puts "  - Improved cipher suites"
                puts "  - Better security"
            }
            "TLSv1.2" {
                puts "✓ Good protocol with acceptable performance"
                puts "  - Widely supported"
                puts "  - Standard security level"
            }
            default {
                puts "⚠ Legacy protocol may have performance issues"
            }
        }
    }
}

# Usage
analyze_connection_performance $conn
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
   # Error: wrong # args: should be "tossl::ssl::socket_info -conn conn"
   # Cause: Missing or incorrect parameters
   # Solution: Use correct syntax with -conn parameter
   ```

### Error Handling Examples

```tcl
# Safe socket info retrieval
proc safe_get_socket_info {conn} {
    if {[catch {
        set info [tossl::ssl::socket_info -conn $conn]
        return $info
    } err]} {
        puts "Failed to get socket info: $err"
        return ""
    }
}

# Usage
set info [safe_get_socket_info $conn]
if {$info ne ""} {
    puts "Socket info: $info"
} else {
    puts "No socket info available"
}
```

```tcl
# Validate connection before socket info query
proc get_socket_info_with_validation {conn} {
    # Check if connection exists
    if {![info exists conn] || $conn eq ""} {
        puts "Error: Invalid connection handle"
        return ""
    }
    
    # Try to get socket info
    if {[catch {
        set info [tossl::ssl::socket_info -conn $conn]
        return $info
    } err]} {
        puts "Error getting socket info: $err"
        return ""
    }
}

# Usage
set info [get_socket_info_with_validation $conn]
```

## Integration with Other Commands

The `::tossl::ssl::socket_info` command works with:

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::cipher_info` - Get cipher information
- `::tossl::ssl::close` - Close SSL connections

### Complete Socket Info Workflow

```tcl
# Complete socket info workflow example
proc socket_info_workflow {host port} {
    # 1. Create SSL context
    set ctx [tossl::ssl::context create]
    
    # 2. Connect with SSL
    set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
    
    # 3. Get socket information
    set info [tossl::ssl::socket_info -conn $conn]
    puts "Socket info: $info"
    
    # 4. Parse and analyze information
    if {[regexp {^fd=(\d+), ssl=(0x[0-9a-f]+), protocol=([A-Za-z0-9.]+)$} $info -> fd ssl_ptr protocol]} {
        puts "File descriptor: $fd"
        puts "SSL object: $ssl_ptr"
        puts "Protocol: $protocol"
        
        # 5. Use information for connection management
        if {$protocol eq "TLSv1.3"} {
            puts "Using optimal protocol"
        }
    }
    
    # 6. Clean up
    tossl::ssl::close -conn $conn
    
    return $info
}

# Usage
set info [socket_info_workflow "example.com" 443]
puts "Workflow completed with info: $info"
```

## Performance Considerations

### Efficiency

- **Fast retrieval**: Uses OpenSSL's `SSL_get_version()` for efficient protocol lookup
- **No memory allocation**: Returns existing information without copying
- **Minimal overhead**: Negligible performance impact
- **Immediate return**: No blocking or waiting operations

### Best Practices

```tcl
# Cache socket info for multiple uses
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
set info [tossl::ssl::socket_info -conn $conn]

# Use cached value instead of calling multiple times
if {[regexp {protocol=([A-Za-z0-9.]+)} $info -> protocol]} {
    puts "Protocol: $protocol"
}
```

## Security Considerations

### Security Features

- **Read-only operation**: Only retrieves socket information, no modification
- **OpenSSL security**: Uses OpenSSL's secure protocol detection
- **No state exposure**: Doesn't expose sensitive SSL state
- **Safe concurrency**: Thread-safe for concurrent access
- **No information leakage**: Only returns socket details

### Security Best Practices

```tcl
# Validate socket info before use
proc secure_socket_info_handling {conn allowed_protocols} {
    set info [tossl::ssl::socket_info -conn $conn]
    
    if {[regexp {protocol=([A-Za-z0-9.]+)} $info -> protocol]} {
        if {$protocol in $allowed_protocols} {
            puts "✓ Protocol allowed: $protocol"
            return $protocol
        } else {
            puts "✗ Protocol not allowed: $protocol"
            puts "  Allowed: $allowed_protocols"
            return ""
        }
    }
    return ""
}

# Usage with security validation
set allowed {TLSv1.3 TLSv1.2}
set protocol [secure_socket_info_handling $conn $allowed]

if {$protocol ne ""} {
    # Process with validated protocol
} else {
    # Reject connection
    tossl::ssl::close -conn $conn
}
```

## Troubleshooting

### Common Issues

1. **Empty or malformed socket info**
   - **Cause**: Invalid SSL connection or corrupted state
   - **Solution**: Verify connection is valid and properly established

2. **Unexpected protocol version**
   - **Cause**: Server/client protocol negotiation
   - **Solution**: Check SSL context configuration and server capabilities

3. **Connection errors**
   - **Cause**: Invalid or closed connection
   - **Solution**: Ensure connection is valid and open

### Debugging Tips

```tcl
# Debug socket info
proc debug_socket_info {conn} {
    puts "=== Socket Info Debug ==="
    puts "Connection: $conn"
    
    if {[catch {
        set info [tossl::ssl::socket_info -conn $conn]
        puts "Socket info: '$info'"
        puts "Length: [string length $info]"
        puts "Valid: [string is ascii $info]"
        
        # Parse components
        if {[regexp {^fd=(\d+), ssl=(0x[0-9a-f]+), protocol=([A-Za-z0-9.]+)$} $info -> fd ssl_ptr protocol]} {
            puts "Parsed components:"
            puts "  FD: $fd"
            puts "  SSL: $ssl_ptr"
            puts "  Protocol: $protocol"
        } else {
            puts "Could not parse socket info"
        }
    } err]} {
        puts "Error: $err"
    }
}

# Usage
debug_socket_info $conn
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::cipher_info` - Get cipher information
- `::tossl::ssl::close` - Close SSL connections
- `::tossl::ssl::protocol_version` - Get protocol version 