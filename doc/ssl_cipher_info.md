# ::tossl::ssl::cipher_info

## Overview

The `::tossl::ssl::cipher_info` command retrieves detailed information about the cipher suite currently in use for an SSL/TLS connection. This command provides essential cryptographic information including the cipher name, protocol version, and whether the connection provides Perfect Forward Secrecy (PFS). This information is crucial for security auditing, compliance checking, and understanding the cryptographic strength of SSL connections.

## Syntax

```tcl
::tossl::ssl::cipher_info -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns a Tcl list containing key-value pairs with the following information:

- `cipher`: The name of the cipher suite (e.g., "ECDHE-RSA-AES256-GCM-SHA384")
- `protocol`: The SSL/TLS protocol version (e.g., "TLSv1.2", "TLSv1.3")
- `pfs`: Either "yes" or "no" indicating whether the connection provides Perfect Forward Secrecy

## Description

The `::tossl::ssl::cipher_info` command analyzes the current SSL/TLS connection and extracts comprehensive information about the cryptographic parameters being used. This is essential for:

- **Security Auditing**: Verifying that connections use appropriate cipher suites
- **Compliance Checking**: Ensuring connections meet security policy requirements
- **Troubleshooting**: Diagnosing connection issues related to cipher negotiation
- **Performance Analysis**: Understanding the cryptographic overhead of connections

The command performs the following analysis:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Cipher Retrieval**: Gets the current cipher suite from the SSL connection
3. **Protocol Detection**: Determines the SSL/TLS protocol version in use
4. **PFS Assessment**: Checks if the cipher suite provides Perfect Forward Secrecy
5. **Information Compilation**: Returns structured information about the connection

### Cipher Suite Information

Cipher suites are identified by names that follow the pattern:
`KeyExchange-Authentication-Encryption-MAC`

Examples:
- `ECDHE-RSA-AES256-GCM-SHA384`: Elliptic Curve Diffie-Hellman Ephemeral with RSA authentication, AES-256-GCM encryption, SHA-384 MAC
- `DHE-RSA-AES128-CBC-SHA256`: Diffie-Hellman Ephemeral with RSA authentication, AES-128-CBC encryption, SHA-256 MAC
- `RSA-AES256-CBC-SHA`: RSA key exchange and authentication, AES-256-CBC encryption, SHA MAC

## Examples

### Basic Cipher Information Retrieval

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Get cipher information
set cipher_info [tossl::ssl::cipher_info -conn $conn]

# Parse the results
set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]

puts "Cipher Suite: $cipher"
puts "Protocol: $protocol"
puts "Perfect Forward Secrecy: $pfs"

tossl::ssl::close -conn $conn
```

### Security Policy Enforcement

```tcl
proc validate_cipher_security {conn} {
    set cipher_info [tossl::ssl::cipher_info -conn $conn]
    set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
    set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
    set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]
    
    # Check protocol version
    if {[string match "SSLv*" $protocol]} {
        error "Insecure protocol detected: $protocol"
    }
    
    # Check for PFS
    if {$pfs eq "no"} {
        error "Connection does not provide Perfect Forward Secrecy"
    }
    
    # Check for weak ciphers
    if {[string match "*RC4*" $cipher] || [string match "*DES*" $cipher] || [string match "*3DES*" $cipher]} {
        error "Weak cipher detected: $cipher"
    }
    
    puts "✓ Connection meets security requirements"
    puts "  - Cipher: $cipher"
    puts "  - Protocol: $protocol"
    puts "  - PFS: $pfs"
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

if {[catch {validate_cipher_security $conn} err]} {
    puts "Security policy violation: $err"
    tossl::ssl::close -conn $conn
    exit 1
}

tossl::ssl::close -conn $conn
```

### Server-Side Cipher Monitoring

```tcl
# Create SSL context for server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Wrap socket with SSL
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Get cipher information
    set cipher_info [tossl::ssl::cipher_info -conn $ssl_conn]
    set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
    set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
    set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]
    
    puts "Client connection from $addr:$port"
    puts "  Cipher: $cipher"
    puts "  Protocol: $protocol"
    puts "  PFS: $pfs"
    
    # Log security status
    if {$pfs eq "yes" && ![string match "SSLv*" $protocol]} {
        puts "✓ Secure connection"
    } else {
        puts "⚠ Security warning: $protocol, PFS=$pfs"
    }
    
    # Continue with normal processing
    set data [tossl::ssl::read -conn $ssl_conn -length 1024]
    tossl::ssl::write -conn $ssl_conn "Hello from secure server!"
    
    tossl::ssl::close -conn $ssl_conn
    close $sock
}

vwait forever
```

### Cipher Suite Audit Tool

```tcl
proc audit_cipher_suites {hosts} {
    set ctx [tossl::ssl::context create]
    set results {}
    
    foreach host $hosts {
        if {[catch {
            set conn [tossl::ssl::connect -ctx $ctx -host $host -port 443]
            set cipher_info [tossl::ssl::cipher_info -conn $conn]
            
            set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
            set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
            set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]
            
            lappend results [dict create host $host cipher $cipher protocol $protocol pfs $pfs]
            
            tossl::ssl::close -conn $conn
        } err]} {
            lappend results [dict create host $host error $err]
        }
    }
    
    return $results
}

# Usage
set hosts {example.com google.com github.com}
set audit_results [audit_cipher_suites $hosts]

foreach result $audit_results {
    if {[dict exists $result error]} {
        puts "[dict get $result host]: ERROR - [dict get $result error]"
    } else {
        set host [dict get $result host]
        set cipher [dict get $result cipher]
        set protocol [dict get $result protocol]
        set pfs [dict get $result pfs]
        
        puts "$host: $protocol, $cipher, PFS=$pfs"
    }
}
```

### Integration with Certificate Validation

```tcl
proc comprehensive_ssl_audit {conn} {
    # Get cipher information
    set cipher_info [tossl::ssl::cipher_info -conn $conn]
    set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
    set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
    set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]
    
    # Check certificate status
    set cert_status [tossl::ssl::check_cert_status -conn $conn]
    
    # Check PFS status
    set pfs_info [tossl::ssl::check_pfs -conn $conn]
    set pfs_detailed [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
    set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
    
    # Compile comprehensive report
    set report [dict create]
    dict set report cipher $cipher
    dict set report protocol $protocol
    dict set report pfs $pfs
    dict set report pfs_detailed $pfs_detailed
    dict set report key_exchange $key_exchange
    dict set report cert_status $cert_status
    
    return $report
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

set audit_report [comprehensive_ssl_audit $conn]
puts "SSL Audit Report:"
puts "  Cipher: [dict get $audit_report cipher]"
puts "  Protocol: [dict get $audit_report protocol]"
puts "  PFS: [dict get $audit_report pfs]"
puts "  Key Exchange: [dict get $audit_report key_exchange]"
puts "  Certificate Status: [dict get $audit_report cert_status]"

tossl::ssl::close -conn $conn
```

### Real-time Cipher Monitoring

```tcl
proc monitor_cipher_changes {conn interval} {
    set last_cipher ""
    
    while {1} {
        if {[catch {
            set cipher_info [tossl::ssl::cipher_info -conn $conn]
            set current_cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
            
            if {$current_cipher ne $last_cipher} {
                puts "[clock format [clock seconds]]: Cipher changed from '$last_cipher' to '$current_cipher'"
                set last_cipher $current_cipher
            }
        } err]} {
            puts "[clock format [clock seconds]]: Error monitoring cipher: $err"
            break
        }
        
        after [expr {$interval * 1000}]
    }
}

# Usage (monitor every 5 seconds)
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Start monitoring in background
after 0 [list monitor_cipher_changes $conn 5]

# Continue with other operations...
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL connection not found` | The specified connection handle is invalid or doesn't exist | Ensure the connection was created successfully and is still active |
| `No cipher` | No cipher information is available for the connection | Check if the SSL handshake completed successfully |
| `wrong # args` | Missing required parameters | Ensure the `-conn` parameter is specified |

## Security Considerations

### Cipher Suite Security

The security of cipher suites depends on several factors:

- **Key Exchange**: ECDHE and DHE provide Perfect Forward Secrecy, RSA does not
- **Authentication**: RSA, DSA, and ECDSA provide strong authentication
- **Encryption**: AES-GCM, ChaCha20-Poly1305 provide authenticated encryption
- **MAC**: SHA-256 and SHA-384 provide strong message authentication

### Protocol Version Security

- **TLS 1.3**: Most secure, mandatory PFS, modern cipher suites only
- **TLS 1.2**: Secure when configured properly, supports PFS
- **TLS 1.1/1.0**: Deprecated, should be avoided
- **SSLv3 and earlier**: Insecure, should never be used

### Security Policy Recommendations

```tcl
proc check_security_policy {conn} {
    set cipher_info [tossl::ssl::cipher_info -conn $conn]
    set cipher [lindex $cipher_info [expr {[lsearch $cipher_info "cipher"] + 1}]]
    set protocol [lindex $cipher_info [expr {[lsearch $cipher_info "protocol"] + 1}]]
    set pfs [lindex $cipher_info [expr {[lsearch $cipher_info "pfs"] + 1}]]
    
    set violations {}
    
    # Check protocol version
    if {[string match "SSLv*" $protocol] || [string match "TLSv1.0" $protocol] || [string match "TLSv1.1" $protocol]} {
        lappend violations "Insecure protocol: $protocol"
    }
    
    # Check for PFS
    if {$pfs eq "no"} {
        lappend violations "No Perfect Forward Secrecy"
    }
    
    # Check for weak ciphers
    if {[string match "*RC4*" $cipher] || [string match "*DES*" $cipher] || [string match "*3DES*" $cipher]} {
        lappend violations "Weak cipher: $cipher"
    }
    
    return $violations
}
```

## Performance Considerations

### Cipher Information Retrieval

- **Fast Operation**: Cipher information retrieval is a lightweight operation
- **No Network Overhead**: Information is retrieved from the local SSL connection
- **Minimal CPU Impact**: Uses OpenSSL's efficient cipher information APIs

### Monitoring Overhead

```tcl
# Efficient cipher monitoring
proc efficient_cipher_monitor {conn} {
    set start_time [clock milliseconds]
    set cipher_info [tossl::ssl::cipher_info -conn $conn]
    set end_time [clock milliseconds]
    
    set duration [expr {$end_time - $start_time}]
    puts "Cipher info retrieval completed in ${duration}ms"
    
    return $cipher_info
}
```

## Integration

This command integrates well with other TOSSL SSL commands:

- **`::tossl::ssl::connect`**: Establish SSL connections for cipher analysis
- **`::tossl::ssl::accept`**: Accept SSL connections for server-side cipher monitoring
- **`::tossl::ssl::check_pfs`**: Get detailed PFS information
- **`::tossl::ssl::check_cert_status`**: Combine with certificate status checking
- **`::tossl::ssl::verify_peer`**: Combine with peer certificate verification

## Troubleshooting

### Common Issues

1. **Connection not found**: Ensure the SSL connection is established before checking cipher info
2. **No cipher information**: Verify that the SSL handshake completed successfully
3. **Unexpected cipher**: Check server configuration for supported cipher suites

### Debugging

```tcl
# Debug cipher information retrieval
proc debug_cipher_info {conn} {
    puts "Retrieving cipher info for connection: $conn"
    
    if {[catch {
        set cipher_info [tossl::ssl::cipher_info -conn $conn]
        puts "Cipher info retrieval successful: $cipher_info"
        return $cipher_info
    } error]} {
        puts "Cipher info retrieval failed: $error"
        return ""
    }
}
```

## See Also

- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::ssl::check_pfs` - Check Perfect Forward Secrecy status
- `::tossl::ssl::check_cert_status` - Check certificate status
- `::tossl::ssl::verify_peer` - Verify peer certificate 