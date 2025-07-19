# ::tossl::ssl::close

## Overview

The `::tossl::ssl::close` command gracefully closes an SSL/TLS connection and performs comprehensive resource cleanup. This command is essential for proper SSL connection management, ensuring that all SSL objects, socket file descriptors, and memory resources are properly deallocated. It performs a proper SSL shutdown sequence including sending the close_notify alert to the peer.

## Syntax

```tcl
::tossl::ssl::close -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns `"ok"` on successful closure, or an error message if the operation fails.

## Description

The `::tossl::ssl::close` command performs a comprehensive SSL connection cleanup process:

1. **Connection Lookup**: Finds the SSL connection in the global connection list
2. **SSL Shutdown**: Performs `SSL_shutdown()` to send close_notify alert to peer
3. **SSL Object Cleanup**: Frees the SSL object with `SSL_free()`
4. **Socket Cleanup**: Closes the underlying socket file descriptor
5. **Memory Cleanup**: Frees the connection handle name and removes from global list
6. **Resource Deallocation**: Ensures all allocated resources are properly released

This command is critical for preventing resource leaks and ensuring proper SSL connection termination.

## Examples

### Basic SSL Connection Closure

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Perform SSL operations
set data [tossl::ssl::read -conn $conn -length 1024]
tossl::ssl::write -conn $conn "Hello, World!"

# Close the SSL connection
set result [tossl::ssl::close -conn $conn]
if {$result eq "ok"} {
    puts "SSL connection closed successfully"
} else {
    puts "Error closing SSL connection: $result"
}
```

### SSL Connection with Error Handling

```tcl
# Safe SSL connection closure
proc safe_ssl_close {conn} {
    if {[catch {
        set result [tossl::ssl::close -conn $conn]
        return $result
    } err]} {
        puts "Error closing SSL connection: $err"
        return "error"
    }
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Perform operations
tossl::ssl::write -conn $conn "Test data"

# Safe closure
set close_result [safe_ssl_close $conn]
if {$close_result eq "ok"} {
    puts "Connection closed successfully"
} else {
    puts "Failed to close connection"
}
```

### Multiple SSL Connections Management

```tcl
# Manage multiple SSL connections
set connections {}

# Create multiple connections
for {set i 0} {$i < 3} {incr i} {
    set ctx [tossl::ssl::context create]
    set conn [tossl::ssl::connect -ctx $ctx -host "server$i.example.com" -port 443]
    lappend connections $conn
    puts "Created connection: $conn"
}

# Perform operations on all connections
foreach conn $connections {
    tossl::ssl::write -conn $conn "Hello from client"
    set response [tossl::ssl::read -conn $conn -length 1024]
    puts "Response from $conn: [string length $response] bytes"
}

# Close all connections in reverse order
for {set i [llength $connections]} {$i > 0} {incr i -1} {
    set conn [lindex $connections [expr $i - 1]]
    set result [tossl::ssl::close -conn $conn]
    if {$result eq "ok"} {
        puts "Closed connection: $conn"
    } else {
        puts "Failed to close connection: $conn"
    }
}
```

### SSL Server Connection Closure

```tcl
# SSL server with proper connection closure
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Accept callback with proper cleanup
proc accept_ssl_connection {sock addr port} {
    global ctx
    
    # Accept SSL connection
    set conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    if {[catch {
        # Handle client request
        set request [tossl::ssl::read -conn $conn -length 1024]
        puts "Received request: [string length $request] bytes"
        
        # Send response
        set response "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
        tossl::ssl::write -conn $conn $response
        
        # Close SSL connection
        tossl::ssl::close -conn $conn
        puts "SSL connection closed"
        
    } err]} {
        puts "Error handling SSL connection: $err"
        # Ensure connection is closed even on error
        catch {tossl::ssl::close -conn $conn}
    }
}

# Start server
set server [socket -server accept_ssl_connection 8443]
puts "SSL server listening on port 8443"
vwait forever
```

### SSL Connection with Timeout and Cleanup

```tcl
# SSL connection with timeout and proper cleanup
proc ssl_connection_with_timeout {host port timeout} {
    set ctx [tossl::ssl::context create]
    set conn ""
    
    if {[catch {
        # Set socket timeout
        set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
        
        # Perform operations with timeout
        after $timeout {
            if {$conn ne ""} {
                puts "Connection timeout, closing..."
                catch {tossl::ssl::close -conn $conn}
            }
        }
        
        # Normal operations
        tossl::ssl::write -conn $conn "GET / HTTP/1.1\r\nHost: $host\r\n\r\n"
        set response [tossl::ssl::read -conn $conn -length 4096]
        
        return $response
        
    } err]} {
        puts "SSL operation failed: $err"
        return ""
    } finally {
        # Always close connection
        if {$conn ne ""} {
            catch {tossl::ssl::close -conn $conn}
        }
    }
}

# Usage
set response [ssl_connection_with_timeout "example.com" 443 5000]
if {$response ne ""} {
    puts "Received response: [string length $response] bytes"
} else {
    puts "No response received"
}
```

### SSL Connection Pool Management

```tcl
# SSL connection pool with proper cleanup
set connection_pool {}

proc get_ssl_connection {host port} {
    global connection_pool
    
    # Try to reuse existing connection
    foreach conn_info $connection_pool {
        lassign $conn_info conn conn_host conn_port
        if {$conn_host eq $host && $conn_port eq $port} {
            # Remove from pool and return
            set connection_pool [lsearch -all -inline -not $connection_pool $conn_info]
            return $conn
        }
    }
    
    # Create new connection
    set ctx [tossl::ssl::context create]
    set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
    return $conn
}

proc return_ssl_connection {conn host port} {
    global connection_pool
    
    # Add connection back to pool
    lappend connection_pool [list $conn $host $port]
}

proc cleanup_ssl_pool {} {
    global connection_pool
    
    foreach conn_info $connection_pool {
        lassign $conn_info conn host port
        catch {tossl::ssl::close -conn $conn}
        puts "Closed pooled connection to $host:$port"
    }
    set connection_pool {}
}

# Usage
set conn1 [get_ssl_connection "api1.example.com" 443]
set conn2 [get_ssl_connection "api2.example.com" 443]

# Use connections
tossl::ssl::write -conn $conn1 "Request 1"
tossl::ssl::write -conn $conn2 "Request 2"

# Return connections to pool
return_ssl_connection $conn1 "api1.example.com" 443
return_ssl_connection $conn2 "api2.example.com" 443

# Clean up pool when done
cleanup_ssl_pool
```

### SSL Connection Monitoring and Cleanup

```tcl
# Monitor and cleanup SSL connections
set active_connections {}

proc monitor_ssl_connections {} {
    global active_connections
    
    puts "=== SSL Connection Monitor ==="
    puts "Active connections: [llength $active_connections]"
    
    foreach conn_info $active_connections {
        lassign $conn_info conn host port start_time
        set duration [expr [clock seconds] - $start_time]
        puts "  $conn -> $host:$port (duration: ${duration}s)"
    }
}

proc cleanup_expired_connections {max_age} {
    global active_connections
    
    set current_time [clock seconds]
    set expired_connections {}
    
    foreach conn_info $active_connections {
        lassign $conn_info conn host port start_time
        if {[expr $current_time - $start_time] > $max_age} {
            lappend expired_connections $conn_info
        }
    }
    
    foreach conn_info $expired_connections {
        lassign $conn_info conn host port start_time
        puts "Closing expired connection: $conn (age: [expr $current_time - $start_time]s)"
        catch {tossl::ssl::close -conn $conn}
        set active_connections [lsearch -all -inline -not $active_connections $conn_info]
    }
    
    return [llength $expired_connections]
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host "example.com" -port 443]

# Track connection
lappend active_connections [list $conn "example.com" 443 [clock seconds]]

# Monitor connections
monitor_ssl_connections

# Clean up expired connections (older than 300 seconds)
set closed_count [cleanup_expired_connections 300]
puts "Closed $closed_count expired connections"

# Manual cleanup
tossl::ssl::close -conn $conn
set active_connections [lsearch -all -inline -not $active_connections [list $conn "example.com" 443 [clock seconds]]]
```

## Error Handling

### Common Error Conditions

1. **SSL connection not found**
   ```tcl
   tossl::ssl::close -conn "invalid_handle"
   # Error: SSL connection not found
   ```

2. **Missing parameters**
   ```tcl
   tossl::ssl::close
   # Error: wrong # args: should be "tossl::ssl::close -conn conn"
   ```

3. **Missing connection parameter**
   ```tcl
   tossl::ssl::close -conn
   # Error: wrong # args: should be "tossl::ssl::close -conn conn"
   ```

4. **Already closed connection**
   ```tcl
   tossl::ssl::close -conn $conn
   tossl::ssl::close -conn $conn  # Second close
   # Error: SSL connection not found
   ```

### Error Handling Best Practices

```tcl
# Robust SSL connection closure
proc robust_ssl_close {conn} {
    if {[catch {
        set result [tossl::ssl::close -conn $conn]
        return $result
    } err]} {
        puts "Warning: Error closing SSL connection: $err"
        return "error"
    }
}

# Usage with error handling
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Perform operations
tossl::ssl::write -conn $conn "Test data"

# Robust closure
set close_result [robust_ssl_close $conn]
if {$close_result eq "ok"} {
    puts "Connection closed successfully"
} else {
    puts "Connection closure had issues"
}
```

```tcl
# Validate connection before closing
proc validate_and_close {conn} {
    # Check if connection exists
    if {![info exists conn] || $conn eq ""} {
        puts "Error: Invalid connection handle"
        return "error"
    }
    
    # Try to close connection
    if {[catch {
        set result [tossl::ssl::close -conn $conn]
        return $result
    } err]} {
        puts "Error closing connection: $err"
        return "error"
    }
}

# Usage
set result [validate_and_close $conn]
```

## Integration with Other Commands

The `::tossl::ssl::close` command works with other SSL commands:

- **`::tossl::ssl::context create`** - Create SSL context for connection
- **`::tossl::ssl::connect`** - Establish SSL connection (client)
- **`::tossl::ssl::accept`** - Accept SSL connection (server)
- **`::tossl::ssl::read`** - Read data from SSL connection
- **`::tossl::ssl::write`** - Write data to SSL connection
- **`::tossl::ssl::socket_info`** - Get socket information
- **`::tossl::ssl::cipher_info`** - Get cipher information

### Complete SSL Workflow Example

```tcl
# Complete SSL workflow with proper cleanup
proc complete_ssl_workflow {host port} {
    set ctx ""
    set conn ""
    
    if {[catch {
        # 1. Create SSL context
        set ctx [tossl::ssl::context create]
        puts "✓ SSL context created"
        
        # 2. Establish SSL connection
        set conn [tossl::ssl::connect -ctx $ctx -host $host -port $port]
        puts "✓ SSL connection established: $conn"
        
        # 3. Get connection information
        set socket_info [tossl::ssl::socket_info -conn $conn]
        puts "✓ Socket info: $socket_info"
        
        set cipher_info [tossl::ssl::cipher_info -conn $conn]
        puts "✓ Cipher info: $cipher_info"
        
        # 4. Perform SSL operations
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
        # 5. Clean up resources
        if {$conn ne ""} {
            if {[catch {tossl::ssl::close -conn $conn} close_err]} {
                puts "✗ Error closing connection: $close_err"
            } else {
                puts "✓ SSL connection closed"
            }
        }
    }
}

# Usage
set response [complete_ssl_workflow "example.com" 443]
if {$response ne ""} {
    puts "Workflow completed successfully"
} else {
    puts "Workflow failed"
}
```

## Performance Considerations

### Efficiency

- **Fast lookup**: Uses linear search in global connection array
- **Efficient cleanup**: Direct resource deallocation without overhead
- **Minimal memory**: No additional memory allocation during close
- **Immediate return**: Returns immediately after cleanup operations

### Best Practices

```tcl
# Batch connection cleanup for better performance
proc batch_ssl_cleanup {connections} {
    set closed_count 0
    
    foreach conn $connections {
        if {[catch {tossl::ssl::close -conn $conn} err]} {
            puts "Warning: Failed to close $conn: $err"
        } else {
            incr closed_count
        }
    }
    
    puts "Closed $closed_count out of [llength $connections] connections"
    return $closed_count
}

# Usage
set connections [list conn1 conn2 conn3 conn4]
set closed [batch_ssl_cleanup $connections]
```

## Security Considerations

### Security Features

- **Proper SSL shutdown**: Uses `SSL_shutdown()` for graceful closure
- **Secure cleanup**: Properly cleans up SSL state and sensitive data
- **Resource isolation**: Ensures no sensitive data remains in memory
- **Safe deallocation**: Uses secure memory deallocation functions

### Security Best Practices

```tcl
# Secure SSL connection closure
proc secure_ssl_close {conn} {
    # Perform secure closure
    if {[catch {
        set result [tossl::ssl::close -conn $conn]
        
        # Verify connection is no longer accessible
        if {[catch {tossl::ssl::socket_info -conn $conn} err]} {
            if {[string match "*SSL connection not found*" $err]} {
                puts "✓ Connection securely closed and inaccessible"
                return "secure"
            }
        }
        
        return $result
    } err]} {
        puts "✗ Secure closure failed: $err"
        return "insecure"
    }
}

# Usage
set result [secure_ssl_close $conn]
if {$result eq "secure"} {
    puts "Connection securely closed"
} else {
    puts "Connection closure may have security issues"
}
```

## Troubleshooting

### Common Issues

1. **Connection already closed**
   - **Cause**: Attempting to close a connection that was already closed
   - **Solution**: Check connection state before closing

2. **Resource leaks**
   - **Cause**: Not calling close on all connections
   - **Solution**: Always close connections in finally blocks

3. **Invalid connection handles**
   - **Cause**: Using connection handles after they've been closed
   - **Solution**: Validate connection handles before use

### Debugging Tips

```tcl
# Debug SSL connection closure
proc debug_ssl_close {conn} {
    puts "=== SSL Close Debug ==="
    puts "Connection: $conn"
    
    # Check if connection exists before closing
    if {[catch {tossl::ssl::socket_info -conn $conn} err]} {
        puts "Connection not found or invalid: $err"
        return "invalid"
    }
    
    puts "Connection is valid, proceeding with close..."
    
    # Attempt to close
    if {[catch {
        set result [tossl::ssl::close -conn $conn]
        puts "Close result: $result"
        return $result
    } err]} {
        puts "Close error: $err"
        return "error"
    }
}

# Usage
set result [debug_ssl_close $conn]
puts "Debug result: $result"
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Create SSL client connections
- `::tossl::ssl::accept` - Accept SSL server connections
- `::tossl::ssl::read` - Read data from SSL connection
- `::tossl::ssl::write` - Write data to SSL connection
- `::tossl::ssl::socket_info` - Get socket information
- `::tossl::ssl::cipher_info` - Get cipher information 