# ::tossl::ssl::write

## Overview

The `::tossl::ssl::write` command writes encrypted data to an SSL/TLS connection. This command takes plaintext data, encrypts it using the negotiated SSL/TLS cipher suite, and sends it over the secure connection. It returns the number of bytes successfully written.

## Syntax

```tcl
::tossl::ssl::write -conn connection data
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |
| `data` | string/bytes | Yes | Data to write to the SSL connection (will be encrypted automatically) |

## Return Value

Returns the number of bytes successfully written as a string. For example, `"15"` indicates that 15 bytes were written.

## Description

The `::tossl::ssl::write` command performs the following operations:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Data Conversion**: Converts the input data to a byte array for processing
3. **SSL Encryption**: Uses OpenSSL's `SSL_write()` function to encrypt the data using the negotiated cipher suite
4. **Network Transmission**: Sends the encrypted data over the underlying TCP connection
5. **Result Return**: Returns the number of bytes successfully written

The command handles all SSL/TLS encryption automatically, so applications can send plaintext data and it will be securely encrypted before transmission.

## Examples

### Basic SSL Write Operation

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Write data to the SSL connection
set message "Hello, Secure World!"
set bytes_written [tossl::ssl::write -conn $conn $message]
puts "Wrote $bytes_written bytes"

# Clean up
tossl::ssl::close -conn $conn
```

### Writing HTTP Request

```tcl
# Create SSL context and connect to HTTPS server
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host api.example.com -port 443]

# Write HTTP GET request
set http_request "GET /api/data HTTP/1.1\r\n"
append http_request "Host: api.example.com\r\n"
append http_request "Connection: close\r\n"
append http_request "\r\n"

set bytes_written [tossl::ssl::write -conn $conn $http_request]
puts "HTTP request sent: $bytes_written bytes"

# Read response
set response [tossl::ssl::read -conn $conn -length 4096]
puts "Response: $response"

tossl::ssl::close -conn $conn
```

### Writing Binary Data

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host binary.example.com -port 443]

# Write binary data
set binary_data [binary format H* "48656c6c6f20576f726c64"] ;# "Hello World" in hex
set bytes_written [tossl::ssl::write -conn $conn $binary_data]
puts "Binary data sent: $bytes_written bytes"

tossl::ssl::close -conn $conn
```

### Writing Large Data in Chunks

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host upload.example.com -port 443]

# Large data to send
set large_data [string repeat "This is a large data block. " 1000]

# Send in chunks
set chunk_size 1024
set total_written 0
set data_length [string length $large_data]

for {set offset 0} {$offset < $data_length} {incr offset $chunk_size} {
    set chunk [string range $large_data $offset [expr {$offset + $chunk_size - 1}]]
    set bytes_written [tossl::ssl::write -conn $conn $chunk]
    incr total_written $bytes_written
    puts "Sent chunk: $bytes_written bytes (total: $total_written)"
}

puts "Total data sent: $total_written bytes"
tossl::ssl::close -conn $conn
```

### Error Handling Example

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Write with error handling
if {[catch {
    set message "Hello, World!"
    set bytes_written [tossl::ssl::write -conn $conn $message]
    puts "Successfully wrote $bytes_written bytes"
} err]} {
    puts "Write failed: $err"
    # Handle error appropriately
}

tossl::ssl::close -conn $conn
```

## Error Handling

### Common Error Conditions

1. **Invalid Connection Handle**
   ```tcl
   tossl::ssl::write -conn "invalid_handle" "data"
   # Error: SSL connection not found
   ```

2. **Missing Parameters**
   ```tcl
   tossl::ssl::write
   # Error: wrong # args: should be "tossl::ssl::write -conn conn data"
   ```

3. **Missing Data Parameter**
   ```tcl
   tossl::ssl::write -conn $conn
   # Error: wrong # args: should be "tossl::ssl::write -conn conn data"
   ```

4. **SSL Write Failure**
   ```tcl
   tossl::ssl::write -conn $conn "data"
   # Error: SSL write failed
   ```

### Error Handling Best Practices

```tcl
proc safe_ssl_write {conn data} {
    if {[catch {
        set bytes_written [tossl::ssl::write -conn $conn $data]
        return $bytes_written
    } err]} {
        puts "SSL write error: $err"
        return -1
    }
}

# Usage
set result [safe_ssl_write $conn "Hello, World!"]
if {$result >= 0} {
    puts "Successfully wrote $result bytes"
} else {
    puts "Write operation failed"
}
```

## Integration with Other SSL Commands

The `::tossl::ssl::write` command works with other SSL commands:

- **`::tossl::ssl::context create`** - Create SSL context for connection
- **`::tossl::ssl::connect`** - Establish SSL connection (client)
- **`::tossl::ssl::accept`** - Accept SSL connection (server)
- **`::tossl::ssl::read`** - Read data from SSL connection
- **`::tossl::ssl::close`** - Close SSL connection

### Complete SSL Client Example

```tcl
# Complete SSL client example
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Send request
set request "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
set bytes_sent [tossl::ssl::write -conn $conn $request]

# Read response
set response [tossl::ssl::read -conn $conn -length 4096]
puts "Response: $response"

# Clean up
tossl::ssl::close -conn $conn
```

## Performance Considerations

### Optimization Tips

1. **Chunk Large Data**: For large data sets, write in chunks to avoid memory issues
2. **Reuse Connections**: Keep connections open for multiple writes when possible
3. **Monitor Return Values**: Always check the number of bytes written
4. **Handle Partial Writes**: Be prepared for cases where not all data is written in one call

### Performance Characteristics

- **Encryption Overhead**: Data is automatically encrypted using the negotiated cipher suite
- **Memory Usage**: Efficient memory handling for large data sets
- **Blocking Behavior**: May block if the SSL buffer is full
- **Error Recovery**: Robust error handling for network issues

## Security Considerations

### Security Features

1. **Automatic Encryption**: All data is encrypted using the negotiated SSL/TLS cipher suite
2. **Cipher Suite Security**: Uses secure cipher suites negotiated during handshake
3. **No Plaintext Exposure**: Plaintext data is never transmitted over the network
4. **Integrity Protection**: Data integrity is protected by the SSL/TLS protocol

### Security Best Practices

1. **Validate Connection State**: Ensure the SSL connection is properly established before writing
2. **Handle Errors Securely**: Don't expose sensitive information in error messages
3. **Use Strong Cipher Suites**: Configure SSL context to use strong cipher suites
4. **Verify Certificates**: Enable certificate verification for client connections

### Security Example

```tcl
# Secure SSL write with certificate verification
set ctx [tossl::ssl::context create -verify peer]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

# Verify connection is secure
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
if {$peer_cert ne ""} {
    puts "Connection is secure with certificate verification"
    
    # Write sensitive data
    set sensitive_data "password=secret123"
    set bytes_written [tossl::ssl::write -conn $conn $sensitive_data]
    puts "Sensitive data sent securely: $bytes_written bytes"
} else {
    puts "Warning: No peer certificate received"
}

tossl::ssl::close -conn $conn
```

## Troubleshooting

### Common Issues

1. **Connection Not Found**
   - Ensure the connection handle is valid
   - Check that the connection was established successfully
   - Verify the connection hasn't been closed

2. **Write Failures**
   - Check network connectivity
   - Verify the remote server is still accepting connections
   - Ensure the SSL handshake completed successfully

3. **Partial Writes**
   - Handle cases where not all data is written
   - Implement retry logic for large data sets
   - Check return values for bytes written

4. **Performance Issues**
   - Use appropriate chunk sizes for large data
   - Monitor memory usage for very large writes
   - Consider connection pooling for multiple writes

### Debugging Tips

```tcl
# Enable detailed error reporting
set ctx [tossl::ssl::context create -verify peer]

# Test write with error handling
if {[catch {
    set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
    set bytes_written [tossl::ssl::write -conn $conn "test data"]
    puts "Write successful: $bytes_written bytes"
} err]} {
    puts "Write failed: $err"
    # Check SSL error state
    puts "SSL error: [tossl::ssl::get_error -conn $conn]"
}
```

## Related Commands

- **`::tossl::ssl::read`** - Read data from SSL connection
- **`::tossl::ssl::connect`** - Establish SSL connection
- **`::tossl::ssl::accept`** - Accept SSL connection
- **`::tossl::ssl::close`** - Close SSL connection
- **`::tossl::ssl::context`** - Create SSL context
- **`::tossl::ssl::get_peer_cert`** - Get peer certificate
- **`::tossl::ssl::verify_peer`** - Verify peer certificate 