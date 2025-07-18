# ::tossl::ssl::verify_cert_pinning

## Overview

The `::tossl::ssl::verify_cert_pinning` command verifies that the peer certificate of an SSL/TLS connection matches one of the provided certificate pins. This implements certificate pinning (similar to HTTP Public Key Pinning - HPKP) to provide an additional layer of security against certificate authority compromises and man-in-the-middle attacks.

## Syntax

```tcl
::tossl::ssl::verify_cert_pinning -conn connection -pins pins
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-conn` | string | Yes | SSL connection handle returned by `::tossl::ssl::connect` or `::tossl::ssl::accept` |
| `-pins` | string | Yes | Space-separated list of base64-encoded SHA-256 certificate fingerprints to match against |

## Return Value

Returns a Tcl list with two elements:
- `pin_match`: Either "yes" or "no" indicating whether the certificate matches any of the provided pins
- The actual match result

## Description

Certificate pinning is a security technique that validates the peer certificate against a predefined set of trusted certificate fingerprints. This provides protection against:

- **Certificate Authority (CA) compromises**: Even if a CA is compromised, the attacker cannot issue valid certificates for your domain
- **Man-in-the-middle attacks**: Attackers cannot use certificates from other CAs to intercept traffic
- **Misissued certificates**: Protection against accidentally or maliciously misissued certificates

The command calculates the SHA-256 hash of the peer certificate's DER encoding and compares it against the provided pins. If any pin matches, the verification succeeds.

## Examples

### Basic Certificate Pinning

```tcl
# Create SSL context and connect
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Define expected certificate pins (base64-encoded SHA-256 fingerprints)
set expected_pins "abc123def456 ghi789jkl012 mno345pqr678"

# Verify certificate pinning
set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $expected_pins]
set pin_match [lindex $result 1]

if {$pin_match eq "yes"} {
    puts "Certificate pinning verification successful"
} else {
    puts "Certificate pinning verification failed"
}

tossl::ssl::close -conn $conn
```

### Dynamic Pin Generation and Verification

```tcl
proc verify_certificate_pinning {hostname port expected_pins} {
    # Create SSL context
    set ctx [tossl::ssl::context create]
    
    # Connect to server
    set conn [tossl::ssl::connect -ctx $ctx -host $hostname -port $port]
    
    # Get peer certificate
    set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
    
    if {[string length $peer_cert] > 0} {
        # Calculate current certificate fingerprint
        set current_fingerprint [tossl::x509::fingerprint $peer_cert sha256]
        puts "Current certificate fingerprint: $current_fingerprint"
        
        # Verify against expected pins
        set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $expected_pins]
        set pin_match [lindex $result 1]
        
        tossl::ssl::close -conn $conn
        
        return [list $pin_match $current_fingerprint]
    } else {
        tossl::ssl::close -conn $conn
        return [list "no_cert" ""]
    }
}

# Usage example
set pins "abc123def456 ghi789jkl012"
set result [verify_certificate_pinning "google.com" 443 $pins]
set match [lindex $result 0]
set fingerprint [lindex $result 1]

if {$match eq "yes"} {
    puts "Certificate pinning successful"
} elseif {$match eq "no"} {
    puts "Certificate pinning failed - fingerprint: $fingerprint"
} else {
    puts "No certificate available"
}
```

### Multiple Pin Support

```tcl
# Support multiple certificate pins for redundancy
set primary_pin "abc123def456"    ;# Primary certificate
set backup_pin "ghi789jkl012"     ;# Backup certificate
set pins "$primary_pin $backup_pin"

set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $pins]
set pin_match [lindex $result 1]

if {$pin_match eq "yes"} {
    puts "Certificate matches one of the expected pins"
} else {
    puts "Certificate does not match any expected pin"
}

tossl::ssl::close -conn $conn
```

### Integration with Certificate Fingerprint

```tcl
# Generate pin from current certificate for future use
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host trusted.example.com -port 443]

# Get and store the certificate fingerprint
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
if {[string length $peer_cert] > 0} {
    set fingerprint [tossl::x509::fingerprint $peer_cert sha256]
    puts "Store this fingerprint for future pinning: $fingerprint"
    
    # Verify it matches itself
    set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $fingerprint]
    set pin_match [lindex $result 1]
    
    if {$pin_match eq "yes"} {
        puts "Self-verification successful"
    }
}

tossl::ssl::close -conn $conn
```

### Error Handling

```tcl
proc safe_cert_pinning {conn pins} {
    if {[catch {
        set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $pins]
        return [lindex $result 1]
    } error]} {
        puts "Certificate pinning error: $error"
        return "error"
    }
}

# Usage with error handling
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

set pin_result [safe_cert_pinning $conn "abc123def456"]

switch $pin_result {
    "yes" {
        puts "Certificate pinning successful"
    }
    "no" {
        puts "Certificate pinning failed"
    }
    "error" {
        puts "Certificate pinning encountered an error"
    }
}

tossl::ssl::close -conn $conn
```

## Error Handling

The command may return the following errors:

| Error | Description | Solution |
|-------|-------------|----------|
| `SSL connection not found` | The specified connection handle is invalid or doesn't exist | Ensure the connection was created successfully and is still active |
| `no_cert` | No peer certificate is available for the connection | Check if the peer provided a certificate during the SSL handshake |
| `Failed to encode certificate` | Internal error encoding the certificate | This is typically an OpenSSL internal error |
| `wrong # args` | Missing required parameters | Ensure both `-conn` and `-pins` parameters are provided |

## Security Considerations

### Pin Management

- **Store pins securely**: Certificate pins should be stored securely and not exposed in client-side code
- **Use multiple pins**: Always provide backup pins to handle certificate renewals
- **Regular updates**: Update pins when certificates are renewed or changed
- **Pin format**: Use base64-encoded SHA-256 fingerprints for consistency

### Pin Generation

```tcl
# Generate pin from certificate file
set cert_data [read [open "certificate.pem" r]]
set fingerprint [tossl::x509::fingerprint $cert_data sha256]
puts "Certificate pin: $fingerprint"
```

### Security Best Practices

1. **Use strong pins**: Always use SHA-256 fingerprints
2. **Implement backup pins**: Provide multiple pins for redundancy
3. **Monitor pin failures**: Log and monitor pin verification failures
4. **Graceful degradation**: Have a fallback mechanism for pin failures
5. **Regular audits**: Regularly audit and update certificate pins

## Performance

- **Efficient comparison**: The command uses efficient string comparison for pin matching
- **Single hash calculation**: Certificate fingerprint is calculated once per verification
- **Memory efficient**: Minimal memory overhead for pin storage and comparison

## Integration

This command integrates well with other TOSSL SSL commands:

- **`::tossl::ssl::connect`**: Establish SSL connections for pinning verification
- **`::tossl::ssl::get_peer_cert`**: Retrieve peer certificates for analysis
- **`::tossl::x509::fingerprint`**: Generate certificate fingerprints for pin creation
- **`::tossl::ssl::verify_peer`**: Combine with standard certificate verification

## Troubleshooting

### Common Issues

1. **Pin mismatch**: Ensure the pin format is correct (base64-encoded SHA-256)
2. **Connection errors**: Verify the SSL connection is established and active
3. **Certificate issues**: Check that the peer provided a valid certificate

### Debugging

```tcl
# Debug certificate pinning
set ctx [tossl::ssl::context create]
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Get peer certificate for analysis
set peer_cert [tossl::ssl::get_peer_cert -conn $conn]
if {[string length $peer_cert] > 0} {
    set fingerprint [tossl::x509::fingerprint $peer_cert sha256]
    puts "Debug: Certificate fingerprint: $fingerprint"
    
    # Test with the actual fingerprint
    set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $fingerprint]
    puts "Debug: Pinning result: $result"
}

tossl::ssl::close -conn $conn
```

## See Also

- `::tossl::ssl::connect` - Establish SSL connections
- `::tossl::ssl::get_peer_cert` - Retrieve peer certificates
- `::tossl::x509::fingerprint` - Generate certificate fingerprints
- `::tossl::ssl::verify_peer` - Standard certificate verification
- `::tossl::ssl::set_cert_pinning` - Configure certificate pinning for SSL contexts 