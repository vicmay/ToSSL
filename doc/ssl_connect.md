# ::tossl::ssl::connect

## Overview

The `::tossl::ssl::connect` command establishes an SSL/TLS connection to a remote server as a client. This command creates a TCP connection to the specified host and port, then performs the SSL/TLS handshake to establish a secure encrypted channel. It supports advanced features like Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN).

## Syntax

```tcl
::tossl::ssl::connect -ctx context -host host -port port ?-sni servername? ?-alpn protocols?
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-host` | string | Yes | Target hostname or IP address to connect to |
| `-port` | integer | Yes | Target port number for the connection |
| `-sni` | string | No | Server Name Indication (SNI) hostname to send during handshake |
| `-alpn` | string | No | Application-Layer Protocol Negotiation protocols (comma-separated) |

## Return Value

Returns an SSL connection handle (e.g., `sslconn1`) that can be used with other SSL commands like `::tossl::ssl::read`, `::tossl::ssl::write`, and `::tossl::ssl::close`.

## Description

The `::tossl::ssl::connect` command performs the client-side SSL/TLS connection process:

1. **Context Validation**: Verifies that the provided SSL context exists and is valid
2. **Socket Creation**: Creates a TCP socket connection to the specified host and port
3. **SSL Object Creation**: Creates a new SSL object using the provided context
4. **Socket Association**: Associates the SSL object with the socket file descriptor
5. **SNI Configuration**: Sets the Server Name Indication if provided
6. **ALPN Configuration**: Sets the Application-Layer Protocol Negotiation if provided
7. **Handshake Execution**: Performs the SSL/TLS handshake using `SSL_connect()`
8. **Connection Handle**: Returns a connection handle for subsequent SSL operations

This command is typically used in client applications to establish secure connections to SSL/TLS servers.

## Examples

### Basic SSL Client Connection

```tcl
# Create SSL context for client
set ctx [tossl::ssl::context create]

# Connect to a server
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Send and receive data
tossl::ssl::write -conn $conn "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
set response [tossl::ssl::read -conn $conn -length 4096]

# Clean up
tossl::ssl::close -conn $conn
```

### SSL Client with Certificate Verification

```tcl
# Create context with CA certificate for verification
set ctx [tossl::ssl::context create \
    -ca ca.pem \
    -verify peer]

# Connect to server with verification
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Verify the peer certificate
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
if {[string length $peer_cert] > 0} {
    puts "Server certificate verified"
} else {
    puts "Warning: No server certificate received"
}

# Use the connection
tossl::ssl::write -conn $conn "Hello, secure server!"
set reply [tossl::ssl::read -conn $conn -length 1024]

tossl::ssl::close -conn $conn
```

### SSL Client with SNI Support

```tcl
# Create SSL context
set ctx [tossl::ssl::context create -ca ca.pem -verify peer]

# Connect with SNI for virtual hosting
set conn [tossl::ssl::connect -ctx $ctx -host 192.168.1.100 -port 443 -sni "example.com"]

# The server will use the SNI hostname to select the appropriate certificate
puts "Connected to server with SNI: example.com"

tossl::ssl::close -conn $conn
```

### SSL Client with ALPN Support

```tcl
# Create SSL context
set ctx [tossl::ssl::context create]

# Connect with ALPN for protocol negotiation
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443 -alpn "h2,http/1.1"]

# Check which protocol was negotiated
set proto [tossl::ssl::alpn_selected -conn $conn]
puts "Negotiated protocol: $proto"

if {$proto eq "h2"} {
    puts "Using HTTP/2 protocol"
} else {
    puts "Using HTTP/1.1 protocol"
}

tossl::ssl::close -conn $conn
```

### SSL Client with Client Certificate Authentication

```tcl
# Create context with client certificate for mutual authentication
set ctx [tossl::ssl::context create \
    -client_cert client.pem \
    -client_key client.key \
    -ca ca.pem \
    -verify peer]

# Connect with mutual authentication
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

# Both client and server certificates are verified
puts "Mutual authentication completed"

tossl::ssl::close -conn $conn
```

### Error Handling Example

```tcl
proc safe_ssl_connect {ctx host port {sni ""} {alpn ""}} {
    set params [list -ctx $ctx -host $host -port $port]
    if {$sni ne ""} {
        lappend params -sni $sni
    }
    if {$alpn ne ""} {
        lappend params -alpn $alpn
    }
    
    if {[catch {
        set conn [tossl::ssl::connect {*}$params]
        return $conn
    } err]} {
        puts "SSL connection failed: $err"
        return ""
    }
}

# Usage
set conn [safe_ssl_connect $ctx "example.com" 443 "example.com" "h2,http/1.1"]
if {$conn ne ""} {
    puts "SSL connection established: $conn"
    # Use the connection...
    tossl::ssl::close -conn $conn
} else {
    puts "Failed to establish SSL connection"
}
```

### Advanced SSL Client with Multiple Features

```tcl
# Create comprehensive SSL context
set ctx [tossl::ssl::context create \
    -client_cert client.pem \
    -client_key client.key \
    -ca ca.pem \
    -verify require]

# Connect with SNI and ALPN
set conn [tossl::ssl::connect -ctx $ctx -host 192.168.1.100 -port 443 \
    -sni "secure.example.com" \
    -alpn "h2,http/1.1"]

# Verify connection details
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
set proto [tossl::ssl::alpn_selected -conn $conn]
set cipher_info [tossl::ssl::cipher_info -conn $conn]

puts "Connection established:"
puts "  Protocol: $proto"
puts "  Cipher: [dict get $cipher_info cipher]"
puts "  PFS: [dict get $cipher_info pfs]"

# Use the secure connection
tossl::ssl::write -conn $conn "Secure request"
set response [tossl::ssl::read -conn $conn -length 4096]

tossl::ssl::close -conn $conn
```

## Error Handling

The command may return the following errors:

| Error | Description | Resolution |
|-------|-------------|------------|
| `wrong # args` | Incorrect number of arguments | Provide required parameters: `-ctx`, `-host`, `-port` |
| `Missing required parameters` | Missing required parameters | Ensure `-ctx`, `-host`, and `-port` are provided |
| `SSL context not found` | Invalid context handle | Verify context was created with `::tossl::ssl::context create` |
| `Failed to create socket` | Socket creation failed | Check system resources and network configuration |
| `Failed to connect` | TCP connection failed | Verify host/port are correct and server is reachable |
| `Failed to create SSL connection` | SSL object creation failed | Check OpenSSL installation and memory availability |
| `SSL handshake failed` | SSL/TLS handshake failed | Check certificate validity, server compatibility, and network connectivity |

## Security Considerations

### Certificate Verification
- **CA Certificates**: Always provide CA certificates for proper server verification
- **Certificate Validation**: Use `-verify peer` or `-verify require` for certificate validation
- **Hostname Verification**: Verify that the server's certificate matches the expected hostname
- **Certificate Pinning**: Consider implementing certificate pinning for additional security

### Protocol Security
- **TLS Version**: Use TLS 1.2 or higher for security
- **Cipher Suites**: Configure strong cipher suites in the SSL context
- **Perfect Forward Secrecy**: Enable PFS cipher suites when possible
- **Certificate Revocation**: Implement OCSP stapling or CRL checking

### Best Practices
```tcl
# Secure client configuration
set ctx [tossl::ssl::context create \
    -ca ca.pem \
    -verify peer \
    -client_cert client.pem \
    -client_key client.key]

# Always verify peer certificates
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]

# Check certificate validity
if {[string length $peer_cert] == 0} {
    error "No server certificate received"
}

# Verify certificate pinning if needed
set pins "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
set pin_result [tossl::ssl::verify_cert_pinning -conn $conn -pins $pins]
```

### SNI Security
- **Hostname Validation**: Ensure SNI hostname matches the actual server hostname
- **Certificate Matching**: Verify that the server's certificate is valid for the SNI hostname
- **Virtual Hosting**: Be aware that SNI reveals the intended hostname to network observers

### ALPN Security
- **Protocol Validation**: Verify that the negotiated protocol is acceptable
- **Downgrade Protection**: Implement checks to prevent protocol downgrade attacks
- **Protocol Support**: Ensure the application supports all advertised protocols

## Performance Considerations

### Connection Management
- **Connection Pooling**: Reuse SSL contexts for multiple connections
- **Session Resumption**: Enable session resumption to reduce handshake overhead
- **Keep-Alive**: Use connection keep-alive when appropriate for your application

### Resource Management
- **Memory Usage**: SSL connections consume memory; monitor usage in high-traffic scenarios
- **File Descriptors**: Ensure proper cleanup of SSL connections
- **Context Reuse**: Reuse SSL contexts rather than creating new ones for each connection

### Network Optimization
- **Connection Timeouts**: Implement appropriate connection timeouts
- **Retry Logic**: Implement retry logic for transient connection failures
- **Load Balancing**: Consider connection distribution across multiple servers

## Integration with Other Commands

The SSL connection handle returned by `::tossl::ssl::connect` can be used with:

- `::tossl::ssl::read` - Read data from the SSL connection
- `::tossl::ssl::write` - Write data to the SSL connection
- `::tossl::ssl::close` - Close the SSL connection
- `::tossl::ssl::get_peer_cert` - Retrieve server certificate
- `::tossl::ssl::alpn_selected` - Get negotiated ALPN protocol
- `::tossl::ssl::protocol_version` - Get negotiated TLS version
- `::tossl::ssl::cipher_info` - Get cipher suite information
- `::tossl::ssl::verify_peer` - Verify peer certificate
- `::tossl::ssl::verify_cert_pinning` - Verify certificate pinning

## Troubleshooting

### Common Issues

1. **Connection Fails**
   - Check hostname and port are correct
   - Verify server is running and accessible
   - Check firewall and network connectivity
   - Ensure server supports the TLS version

2. **Certificate Verification Fails**
   - Verify CA certificate is correct and up-to-date
   - Check server certificate is valid and not expired
   - Ensure certificate matches the hostname
   - Check certificate chain is complete

3. **Handshake Fails**
   - Verify client and server support compatible TLS versions
   - Check cipher suite compatibility
   - Ensure certificates are properly formatted
   - Verify private key matches certificate

4. **SNI Issues**
   - Ensure server supports SNI
   - Verify SNI hostname matches server certificate
   - Check for SNI-related configuration issues

5. **ALPN Issues**
   - Verify server supports ALPN
   - Check protocol list format (comma-separated)
   - Ensure application supports negotiated protocol

### Debugging Tips

```tcl
# Enable detailed error reporting
set ctx [tossl::ssl::context create -ca ca.pem -verify peer]

# Test connection with error handling
if {[catch {
    set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]
    puts "Connection successful: $conn"
} err]} {
    puts "Connection failed: $err"
    # Check specific error conditions
    if {[string match "*SSL handshake failed*" $err]} {
        puts "Handshake issue - check certificates and protocols"
    } elseif {[string match "*Failed to connect*" $err]} {
        puts "Network issue - check host/port and connectivity"
    }
}
```

## Related Commands

- `::tossl::ssl::context create` - Create SSL context for connections
- `::tossl::ssl::accept` - Accept SSL connections as server
- `::tossl::ssl::read` - Read data from SSL connection
- `::tossl::ssl::write` - Write data to SSL connection
- `::tossl::ssl::close` - Close SSL connection
- `::tossl::ssl::get_peer_cert` - Get peer certificate
- `::tossl::ssl::alpn_selected` - Get negotiated ALPN protocol
- `::tossl::ssl::cipher_info` - Get cipher information
- `::tossl::ssl::verify_peer` - Verify peer certificate 