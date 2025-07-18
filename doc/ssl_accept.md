# ::tossl::ssl::accept

## Overview

The `::tossl::ssl::accept` command performs SSL/TLS handshake as a server on an existing TCP socket. This command is used to establish secure connections when acting as an SSL/TLS server, accepting incoming client connections and negotiating the cryptographic parameters for secure communication.

## Syntax

```tcl
::tossl::ssl::accept -ctx context -socket socket
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-socket` | string | Yes | Tcl socket channel name to wrap with SSL/TLS |

## Return Value

Returns an SSL connection handle (e.g., `sslconn1`) that can be used with other SSL commands like `::tossl::ssl::read`, `::tossl::ssl::write`, and `::tossl::ssl::close`.

## Description

The `::tossl::ssl::accept` command performs the server-side SSL/TLS handshake process:

1. **Context Validation**: Verifies that the provided SSL context exists and is valid
2. **Socket Extraction**: Extracts the file descriptor from the Tcl socket channel
3. **SSL Object Creation**: Creates a new SSL object using the provided context
4. **Socket Association**: Associates the SSL object with the socket file descriptor
5. **Handshake Execution**: Performs the SSL/TLS handshake using `SSL_accept()`
6. **Connection Handle**: Returns a connection handle for subsequent SSL operations

This command is typically used in server applications after accepting a TCP connection and before performing any data exchange.

## Examples

### Basic SSL Server

```tcl
# Create SSL context for server
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -verify peer]

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Configure socket for SSL
    fconfigure $sock -blocking 1
    
    # Perform SSL accept
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Now communicate securely
    set data [tossl::ssl::read -conn $ssl_conn -length 1024]
    tossl::ssl::write -conn $ssl_conn "Hello, secure client!"
    
    # Clean up
    tossl::ssl::close -conn $ssl_conn
    close $sock
}
```

### SSL Server with Certificate Verification

```tcl
# Create context with strict verification
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -ca ca.pem \
    -verify require]

proc secure_accept {sock addr port} {
    global ctx
    
    fconfigure $sock -blocking 1
    
    # Accept SSL connection
    set conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Verify peer certificate
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    if {[string length $peer_cert] > 0} {
        puts "Client certificate verified"
    } else {
        puts "No client certificate provided"
    }
    
    # Handle secure communication
    set request [tossl::ssl::read -conn $conn -length 4096]
    tossl::ssl::write -conn $conn "Secure response"
    
    tossl::ssl::close -conn $conn
    close $sock
}
```

### SSL Server with ALPN Support

```tcl
# Create context with ALPN callback
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Set ALPN callback
proc alpn_select {protos} {
    if {"h2" in $protos} {
        return "h2"
    }
    return [lindex $protos 0]
}

tossl::ssl::set_alpn_callback -ctx $ctx -callback alpn_select

proc alpn_accept {sock addr port} {
    global ctx
    
    fconfigure $sock -blocking 1
    set conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Check negotiated protocol
    set proto [tossl::ssl::alpn_selected -conn $conn]
    puts "Negotiated protocol: $proto"
    
    # Handle based on protocol
    if {$proto eq "h2"} {
        puts "Handling HTTP/2 connection"
    } else {
        puts "Handling HTTP/1.1 connection"
    }
    
    tossl::ssl::close -conn $conn
    close $sock
}
```

### Error Handling Example

```tcl
proc safe_ssl_accept {ctx sock} {
    if {[catch {
        fconfigure $sock -blocking 1
        set conn [tossl::ssl::accept -ctx $ctx -socket $sock]
        return $conn
    } err]} {
        puts "SSL accept failed: $err"
        close $sock
        return ""
    }
}

# Usage
set conn [safe_ssl_accept $ctx $client_socket]
if {$conn ne ""} {
    # Handle successful connection
    puts "SSL connection established: $conn"
} else {
    puts "Failed to establish SSL connection"
}
```

## Error Handling

The command may return the following errors:

| Error | Description | Resolution |
|-------|-------------|------------|
| `wrong # args` | Incorrect number of arguments | Provide both `-ctx` and `-socket` parameters |
| `Missing required parameters` | Missing required parameters | Ensure both `-ctx` and `-socket` are provided |
| `SSL context not found` | Invalid context handle | Verify context was created with `::tossl::ssl::context create` |
| `Failed to get socket file descriptor` | Invalid socket channel | Ensure socket is a valid Tcl channel |
| `Failed to create SSL connection` | SSL object creation failed | Check OpenSSL installation and memory availability |
| `SSL accept failed` | Handshake failed | Check certificate validity, client compatibility, and network connectivity |

## Security Considerations

### Certificate Management
- **Valid Certificates**: Ensure server certificates are valid and not expired
- **Private Key Security**: Protect private keys with appropriate permissions
- **Certificate Chain**: Include complete certificate chain for proper validation
- **Subject Alternative Names**: Include appropriate SANs for the server's hostname

### Verification Levels
- **No Verification**: `-verify 0` - Accepts any client (insecure)
- **Peer Verification**: `-verify peer` - Requests but doesn't require client certificates
- **Required Verification**: `-verify require` - Requires valid client certificates

### Protocol Security
- **TLS Version**: Use TLS 1.2 or higher for security
- **Cipher Suites**: Configure strong cipher suites
- **Perfect Forward Secrecy**: Enable PFS cipher suites when possible

### Best Practices
```tcl
# Secure server configuration
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -ca ca.pem \
    -verify require \
    -protocols {TLSv1.2 TLSv1.3} \
    -ciphers "ECDHE+AESGCM:ECDHE+CHACHA20"]

# Always verify peer certificates in production
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
if {[string length $peer_cert] == 0} {
    puts "Warning: No client certificate provided"
}
```

## Performance Considerations

### Connection Handling
- **Non-blocking Mode**: Consider using non-blocking sockets for high-performance servers
- **Connection Pooling**: Reuse SSL contexts for multiple connections
- **Session Resumption**: Enable session resumption to reduce handshake overhead

### Resource Management
- **Memory Usage**: SSL connections consume memory; monitor usage in high-traffic scenarios
- **File Descriptors**: Ensure proper cleanup of SSL connections and underlying sockets
- **Context Reuse**: Reuse SSL contexts rather than creating new ones for each connection

## Integration with Other Commands

The SSL connection handle returned by `::tossl::ssl::accept` can be used with:

- `::tossl::ssl::read` - Read data from the SSL connection
- `::tossl::ssl::write` - Write data to the SSL connection
- `::tossl::ssl::close` - Close the SSL connection
- `::tossl::ssl::get_peer_cert` - Retrieve client certificate
- `::tossl::ssl::alpn_selected` - Get negotiated ALPN protocol
- `::tossl::ssl::protocol_version` - Get negotiated TLS version
- `::tossl::ssl::cipher_info` - Get cipher suite information

## Troubleshooting

### Common Issues

1. **Handshake Fails**
   - Check certificate validity and expiration
   - Verify private key matches certificate
   - Ensure client supports server's TLS version

2. **Certificate Verification Errors**
   - Verify CA certificate is properly loaded
   - Check certificate chain completeness
   - Ensure hostname matches certificate

3. **Performance Issues**
   - Monitor SSL handshake timing
   - Check for certificate validation bottlenecks
   - Consider session resumption for repeated connections

### Debugging Tips

```tcl
# Enable SSL debugging (if available)
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Check connection details after accept
set conn [tossl::ssl::accept -ctx $ctx -socket $sock]
set version [tossl::ssl::protocol_version -conn $conn]
set cipher [tossl::ssl::cipher_info -conn $conn]
puts "TLS Version: $version"
puts "Cipher Suite: $cipher"
```

## See Also

- `::tossl::ssl::context create` - Create SSL context
- `::tossl::ssl::connect` - Client-side SSL connection
- `::tossl::ssl::read` - Read from SSL connection
- `::tossl::ssl::write` - Write to SSL connection
- `::tossl::ssl::close` - Close SSL connection
- `::tossl::ssl::get_peer_cert` - Get peer certificate
- `::tossl::x509::parse` - Parse X.509 certificates 