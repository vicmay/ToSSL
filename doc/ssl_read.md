# ::tossl::ssl::read

## Overview

The `::tossl::ssl::read` command reads encrypted data from an SSL/TLS connection and returns the decrypted data as a byte array. This command is used for receiving secure data over established SSL/TLS connections, handling the decryption process automatically.

## Syntax

```tcl
::tossl::ssl::read -conn connection ?-length length?
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |
| `-length` | integer | No | Maximum number of bytes to read (default: 1024) |

## Return Value

Returns a Tcl byte array containing the decrypted data read from the SSL connection. The actual number of bytes returned may be less than the requested length if fewer bytes are available.

## Description

The `::tossl::ssl::read` command performs the following operations:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Buffer Allocation**: Allocates a buffer of the specified size for reading data
3. **SSL Read Operation**: Calls OpenSSL's `SSL_read()` function to read and decrypt data
4. **Data Return**: Returns the decrypted data as a Tcl byte array

The command handles the SSL/TLS decryption process transparently, so applications receive plaintext data even though it was transmitted over an encrypted connection.

## Examples

### Basic SSL Read Operation

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Read data from the SSL connection
set data [tossl::ssl::read -conn $conn -length 1024]
puts "Received [string length $data] bytes"

# Convert to string if it's text data
set text [encoding convertfrom utf-8 $data]
puts "Received text: $text"

tossl::ssl::close -conn $conn
```

### Reading with Default Length

```tcl
# Use default read length (1024 bytes)
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

# Read with default length
set data [tossl::ssl::read -conn $conn]
puts "Read [string length $data] bytes with default length"

tossl::ssl::close -conn $conn
```

### Reading Large Data in Chunks

```tcl
proc read_large_data {conn total_size} {
    set chunk_size 4096
    set all_data ""
    set bytes_read 0
    
    while {$bytes_read < $total_size} {
        set remaining [expr {$total_size - $bytes_read}]
        set read_size [expr {$remaining < $chunk_size ? $remaining : $chunk_size}]
        
        set chunk [tossl::ssl::read -conn $conn -length $read_size]
        set chunk_len [string length $chunk]
        
        if {$chunk_len == 0} {
            # No more data available
            break
        }
        
        append all_data $chunk
        incr bytes_read $chunk_len
    }
    
    return $all_data
}

# Usage example
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host large-file.example.com -port 443]

# Read a large file (e.g., 1MB)
set large_data [read_large_data $conn 1048576]
puts "Read [string length $large_data] bytes total"

tossl::ssl::close -conn $conn
```

### Server-Side Reading

```tcl
# Create SSL context for server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Wrap socket with SSL
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Read client data
    set client_data [tossl::ssl::read -conn $ssl_conn -length 1024]
    puts "Received from client: [string length $client_data] bytes"
    
    # Process the data
    set text [encoding convertfrom utf-8 $client_data]
    puts "Client message: $text"
    
    # Send response
    tossl::ssl::write -conn $ssl_conn "Hello from SSL server!"
    
    # Clean up
    tossl::ssl::close -conn $ssl_conn
    close $sock
}

vwait forever
```

### Error Handling with SSL Read

```tcl
proc safe_ssl_read {conn length} {
    if {[catch {
        set data [tossl::ssl::read -conn $conn -length $length]
        return [list "success" $data]
    } error]} {
        return [list "error" $error]
    }
}

# Usage with error handling
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

set result [safe_ssl_read $conn 1024]
set status [lindex $result 0]
set data [lindex $result 1]

if {$status eq "success"} {
    puts "Successfully read [string length $data] bytes"
} else {
    puts "SSL read failed: $data"
}

tossl::ssl::close -conn $conn
```

### Reading Binary Data

```tcl
# Read binary data (e.g., image file)
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host binary.example.com -port 443]

# Read binary data
set binary_data [tossl::ssl::read -conn $conn -length 8192]

# Save to file
set f [open "downloaded_image.jpg" wb]
fconfigure $f -translation binary
puts -nonewline $f $binary_data
close $f

puts "Saved [string length $binary_data] bytes to downloaded_image.jpg"

tossl::ssl::close -conn $conn
```

### Integration with HTTP

```tcl
proc read_http_response {conn} {
    set response ""
    set headers_complete 0
    
    while {!$headers_complete} {
        set chunk [tossl::ssl::read -conn $conn -length 1024]
        if {[string length $chunk] == 0} {
            break
        }
        
        append response $chunk
        
        # Check for end of headers (double CRLF)
        if {[string first "\r\n\r\n" $response] != -1} {
            set headers_complete 1
        }
    }
    
    return $response
}

# Usage in HTTP client
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host api.example.com -port 443]

# Send HTTP request
set request "GET /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
tossl::ssl::write -conn $conn $request

# Read HTTP response
set response [read_http_response $conn]
puts "HTTP Response: $response"

tossl::ssl::close -conn $conn
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL connection not found` | The specified connection handle is invalid or doesn't exist | Ensure the connection was created successfully and is still active |
| `SSL read failed` | The SSL read operation failed (connection closed, timeout, etc.) | Check if the connection is still valid and the peer is sending data |
| `Missing connection parameter` | The `-conn` parameter was not provided | Ensure the `-conn` parameter is specified |
| `wrong # args` | Missing required parameters | Ensure both `-conn` and optionally `-length` parameters are provided |

## Performance Considerations

### Read Buffer Sizing

- **Small buffers (1-4KB)**: Good for interactive applications and small messages
- **Medium buffers (4-16KB)**: Good for general-purpose applications
- **Large buffers (16KB+)**: Good for bulk data transfer, but may block longer

### Memory Usage

```tcl
# Efficient reading for large files
proc read_efficiently {conn file_size} {
    set buffer_size 8192  ;# 8KB buffer
    set f [open "output.bin" wb]
    fconfigure $f -translation binary
    
    set total_read 0
    while {$total_read < $file_size} {
        set remaining [expr {$file_size - $total_read}]
        set read_size [expr {$remaining < $buffer_size ? $remaining : $buffer_size}]
        
        set data [tossl::ssl::read -conn $conn -length $read_size]
        set bytes_read [string length $data]
        
        if {$bytes_read == 0} {
            break  ;# No more data
        }
        
        puts -nonewline $f $data
        incr total_read $bytes_read
    }
    
    close $f
    return $total_read
}
```

## Security Considerations

### Data Integrity

- SSL/TLS automatically handles data integrity verification
- No additional checksum validation is required
- The command will fail if data integrity is compromised

### Timing Attacks

- Reading fixed amounts of data may reveal information about data patterns
- Consider using variable read sizes for sensitive applications
- Implement proper error handling to avoid information leakage

### Buffer Management

```tcl
# Secure buffer handling
proc secure_read {conn max_size} {
    # Limit maximum read size to prevent memory exhaustion
    if {$max_size > 1048576} {  ;# 1MB limit
        error "Read size too large"
    }
    
    set data [tossl::ssl::read -conn $conn -length $max_size]
    
    # Clear sensitive data from memory when done
    # (Tcl handles this automatically, but be aware)
    return $data
}
```

## Integration

This command integrates well with other TOSSL SSL commands:

- **`::tossl::ssl::connect`**: Establish SSL connections for reading
- **`::tossl::ssl::accept`**: Accept SSL connections for server-side reading
- **`::tossl::ssl::write`**: Send data over SSL connections
- **`::tossl::ssl::close`**: Close SSL connections after reading

## Troubleshooting

### Common Issues

1. **Connection closed unexpectedly**: Check if the peer has closed the connection
2. **No data received**: Verify that the peer is actually sending data
3. **Partial reads**: Handle cases where less data than requested is returned
4. **Memory issues**: Use appropriate buffer sizes for your application

### Debugging

```tcl
# Debug SSL read operations
proc debug_ssl_read {conn length} {
    puts "Attempting to read $length bytes from connection $conn"
    
    if {[catch {
        set data [tossl::ssl::read -conn $conn -length $length]
        puts "Successfully read [string length $data] bytes"
        return $data
    } error]} {
        puts "SSL read failed: $error"
        return ""
    }
}
```

## See Also

- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::ssl::write` - Write data to SSL connections
- `::tossl::ssl::close` - Close SSL connections 