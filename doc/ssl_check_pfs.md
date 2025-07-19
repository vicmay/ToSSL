# ::tossl::ssl::check_pfs

## Overview

The `::tossl::ssl::check_pfs` command checks whether an SSL/TLS connection provides Perfect Forward Secrecy (PFS). This command analyzes the key exchange algorithm used in the SSL connection and determines if it supports forward secrecy, which is a critical security feature that protects past communications even if the private key is compromised in the future.

## Syntax

```tcl
::tossl::ssl::check_pfs -conn connection
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |

## Return Value

Returns a Tcl list containing key-value pairs with the following information:

- `pfs`: Either "yes" or "no" indicating whether the connection provides Perfect Forward Secrecy
- `key_exchange`: The key exchange algorithm used ("ECDHE", "DHE", or "RSA")
- `cipher_bits`: The strength of the cipher in bits

## Description

Perfect Forward Secrecy (PFS) is a security property that ensures that if a private key is compromised, it cannot be used to decrypt past communications. This is achieved through ephemeral key exchange methods.

The command performs the following analysis:

1. **Connection Validation**: Verifies that the specified SSL connection exists and is valid
2. **Cipher Analysis**: Retrieves the current cipher information from the SSL connection
3. **Key Exchange Detection**: Determines the key exchange algorithm used
4. **PFS Assessment**: Checks if the key exchange method provides forward secrecy
5. **Strength Analysis**: Evaluates the cryptographic strength of the cipher

### Key Exchange Methods

- **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)**: Provides PFS, uses elliptic curve cryptography
- **DHE (Diffie-Hellman Ephemeral)**: Provides PFS, uses traditional Diffie-Hellman
- **RSA**: Does not provide PFS, uses static RSA key exchange

## Examples

### Basic PFS Check

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Check if the connection provides PFS
set pfs_info [tossl::ssl::check_pfs -conn $conn]

# Parse the results
set pfs [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
set cipher_bits [lindex $pfs_info [expr {[lsearch $pfs_info "cipher_bits"] + 1}]]

puts "PFS enabled: $pfs"
puts "Key exchange: $key_exchange"
puts "Cipher strength: $cipher_bits bits"

tossl::ssl::close -conn $conn
```

### Security Policy Enforcement

```tcl
proc enforce_pfs_policy {conn} {
    set pfs_info [tossl::ssl::check_pfs -conn $conn]
    set pfs [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
    set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
    set cipher_bits [lindex $pfs_info [expr {[lsearch $pfs_info "cipher_bits"] + 1}]]
    
    if {$pfs eq "no"} {
        error "Connection does not provide Perfect Forward Secrecy"
    }
    
    if {$cipher_bits < 128} {
        error "Cipher strength too weak: $cipher_bits bits"
    }
    
    puts "✓ Connection meets security requirements"
    puts "  - PFS: $pfs"
    puts "  - Key exchange: $key_exchange"
    puts "  - Cipher strength: $cipher_bits bits"
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

if {[catch {enforce_pfs_policy $conn} err]} {
    puts "Security policy violation: $err"
    tossl::ssl::close -conn $conn
    exit 1
}

tossl::ssl::close -conn $conn
```

### Server-Side PFS Monitoring

```tcl
# Create SSL context for server
set ctx [tossl::ssl::context create -cert server.pem -key server.key]

# Create TCP server
set server [socket -server accept_connection 8443]

proc accept_connection {sock addr port} {
    global ctx
    
    # Wrap socket with SSL
    set ssl_conn [tossl::ssl::accept -ctx $ctx -socket $sock]
    
    # Check PFS status
    set pfs_info [tossl::ssl::check_pfs -conn $ssl_conn]
    set pfs [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
    set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
    
    puts "Client connection from $addr:$port"
    puts "  PFS: $pfs"
    puts "  Key exchange: $key_exchange"
    
    # Log security status
    if {$pfs eq "yes"} {
        puts "✓ Secure connection with PFS"
    } else {
        puts "⚠ Warning: Connection without PFS"
    }
    
    # Continue with normal processing
    set data [tossl::ssl::read -conn $ssl_conn -length 1024]
    tossl::ssl::write -conn $ssl_conn "Hello from secure server!"
    
    tossl::ssl::close -conn $ssl_conn
    close $sock
}

vwait forever
```

### PFS Audit Tool

```tcl
proc audit_pfs_connections {hosts} {
    set ctx [tossl::ssl::context create]
    set results {}
    
    foreach host $hosts {
        if {[catch {
            set conn [tossl::ssl::connect -ctx $ctx -host $host -port 443]
            set pfs_info [tossl::ssl::check_pfs -conn $conn]
            
            set pfs [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
            set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
            set cipher_bits [lindex $pfs_info [expr {[lsearch $pfs_info "cipher_bits"] + 1}]]
            
            lappend results [dict create host $host pfs $pfs key_exchange $key_exchange cipher_bits $cipher_bits]
            
            tossl::ssl::close -conn $conn
        } err]} {
            lappend results [dict create host $host error $err]
        }
    }
    
    return $results
}

# Usage
set hosts {example.com google.com github.com}
set audit_results [audit_pfs_connections $hosts]

foreach result $audit_results {
    if {[dict exists $result error]} {
        puts "[dict get $result host]: ERROR - [dict get $result error]"
    } else {
        set host [dict get $result host]
        set pfs [dict get $result pfs]
        set key_exchange [dict get $result key_exchange]
        set cipher_bits [dict get $result cipher_bits]
        
        puts "$host: PFS=$pfs, KeyExchange=$key_exchange, Strength=${cipher_bits}bits"
    }
}
```

### Integration with Certificate Validation

```tcl
proc comprehensive_security_check {conn} {
    # Check PFS
    set pfs_info [tossl::ssl::check_pfs -conn $conn]
    set pfs [lindex $pfs_info [expr {[lsearch $pfs_info "pfs"] + 1}]]
    set key_exchange [lindex $pfs_info [expr {[lsearch $pfs_info "key_exchange"] + 1}]]
    set cipher_bits [lindex $pfs_info [expr {[lsearch $pfs_info "cipher_bits"] + 1}]]
    
    # Check certificate status
    set cert_status [tossl::ssl::check_cert_status -conn $conn]
    
    # Check certificate pinning (if configured)
    set expected_pins "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    set pin_result [tossl::ssl::verify_cert_pinning -conn $conn -pins $expected_pins]
    set pin_match [lindex $pin_result [expr {[lsearch $pin_result "pin_match"] + 1}]]
    
    # Compile security report
    set report [dict create]
    dict set report pfs $pfs
    dict set report key_exchange $key_exchange
    dict set report cipher_bits $cipher_bits
    dict set report cert_status $cert_status
    dict set report pin_match $pin_match
    
    return $report
}

# Usage
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

set security_report [comprehensive_security_check $conn]
puts "Security Report:"
puts "  PFS: [dict get $security_report pfs]"
puts "  Key Exchange: [dict get $security_report key_exchange]"
puts "  Cipher Strength: [dict get $security_report cipher_bits] bits"
puts "  Certificate Status: [dict get $security_report cert_status]"
puts "  Certificate Pinning: [dict get $security_report pin_match]"

tossl::ssl::close -conn $conn
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL connection not found` | The specified connection handle is invalid or doesn't exist | Ensure the connection was created successfully and is still active |
| `No cipher` | No cipher information is available for the connection | Check if the SSL handshake completed successfully |
| `wrong # args` | Missing required parameters | Ensure the `-conn` parameter is specified |

## Security Considerations

### Perfect Forward Secrecy Importance

PFS is critical for security because:

- **Key Compromise Protection**: Even if a server's private key is compromised, past communications remain secure
- **Long-term Security**: Protects against future key compromise scenarios
- **Compliance**: Many security standards and regulations require PFS
- **Best Practice**: Industry standard for secure communications

### Key Exchange Algorithm Security

- **ECDHE**: Most secure, provides PFS with elliptic curve cryptography
- **DHE**: Secure, provides PFS with traditional Diffie-Hellman
- **RSA**: Less secure, does not provide PFS

### Cipher Strength Requirements

- **Minimum 128 bits**: Acceptable for most applications
- **256 bits**: Recommended for high-security environments
- **Below 128 bits**: Considered weak and should be avoided

## Performance Considerations

### PFS Overhead

- **ECDHE**: Minimal performance impact, recommended for most applications
- **DHE**: Slightly higher computational cost than ECDHE
- **RSA**: Fastest but provides no forward secrecy

### Monitoring and Logging

```tcl
# Efficient PFS monitoring
proc monitor_pfs_usage {conn} {
    set start_time [clock milliseconds]
    set pfs_info [tossl::ssl::check_pfs -conn $conn]
    set end_time [clock milliseconds]
    
    set duration [expr {$end_time - $start_time}]
    puts "PFS check completed in ${duration}ms"
    
    return $pfs_info
}
```

## Integration

This command integrates well with other TOSSL SSL commands:

- **`::tossl::ssl::connect`**: Establish SSL connections for PFS checking
- **`::tossl::ssl::accept`**: Accept SSL connections for server-side PFS monitoring
- **`::tossl::ssl::check_cert_status`**: Combine with certificate status checking
- **`::tossl::ssl::verify_cert_pinning`**: Combine with certificate pinning verification

## Troubleshooting

### Common Issues

1. **Connection not found**: Ensure the SSL connection is established before checking PFS
2. **No cipher information**: Verify that the SSL handshake completed successfully
3. **Unexpected key exchange**: Check server configuration for supported cipher suites

### Debugging

```tcl
# Debug PFS checking
proc debug_pfs_check {conn} {
    puts "Checking PFS for connection: $conn"
    
    if {[catch {
        set pfs_info [tossl::ssl::check_pfs -conn $conn]
        puts "PFS check successful: $pfs_info"
        return $pfs_info
    } error]} {
        puts "PFS check failed: $error"
        return ""
    }
}
```

## See Also

- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::accept` - Accept SSL connections
- `::tossl::ssl::check_cert_status` - Check certificate status
- `::tossl::ssl::verify_cert_pinning` - Verify certificate pinning
- `::tossl::pfs::test` - Test PFS cipher suite support 