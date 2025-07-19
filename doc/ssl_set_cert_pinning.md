# ::tossl::ssl::set_cert_pinning

## Overview

The `::tossl::ssl::set_cert_pinning` command configures certificate pinning for an SSL context. This command is designed to set up certificate pins that can be used for automatic verification of peer certificates during SSL/TLS connections.

**⚠️ Important Note**: This command is currently implemented as a stub that accepts parameters and validates the SSL context, but does not actually store the pins for later verification. The pins parameter is accepted but not used in the current implementation.

## Syntax

```tcl
::tossl::ssl::set_cert_pinning -ctx context -pins pins
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ctx` | string | Yes | SSL context handle created with `::tossl::ssl::context create` |
| `-pins` | string | Yes | Space-separated list of certificate pins (currently not stored) |

## Return Value

Returns `"ok"` on success, indicating that the command executed without errors. Note that this does not mean the pins are actually stored or will be used for verification.

## Description

The `::tossl::ssl::set_cert_pinning` command is designed to configure certificate pinning for SSL contexts. Certificate pinning is a security technique that validates peer certificates against predefined trusted certificate fingerprints, providing protection against:

- **Certificate Authority (CA) compromises**: Even if a CA is compromised, attackers cannot issue valid certificates for your domain
- **Man-in-the-middle attacks**: Attackers cannot use certificates from other CAs to intercept traffic
- **Misissued certificates**: Protection against accidentally or maliciously misissued certificates

### Current Implementation Status

The current implementation performs the following operations:

1. **Parameter Validation**: Verifies that both `-ctx` and `-pins` parameters are provided
2. **Context Validation**: Ensures the specified SSL context exists and is valid
3. **Return Success**: Returns `"ok"` to indicate successful parameter processing

**Limitations of Current Implementation**:
- Pins are not actually stored in the SSL context
- No automatic verification occurs during SSL connections
- The `-pins` parameter is accepted but ignored
- Manual verification must be performed using `::tossl::ssl::verify_cert_pinning`

## Examples

### Basic Certificate Pinning Setup

```tcl
# Create SSL context
set ctx [tossl::ssl::context create]

# Set certificate pins (currently a stub - pins are not stored)
set pins "abc123def456 ghi789jkl012"
set result [tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins]

if {$result eq "ok"} {
    puts "Certificate pinning setup completed"
} else {
    puts "Certificate pinning setup failed"
}
```

### Integration with SSL Context Creation

```tcl
# Create comprehensive SSL context
set ctx [tossl::ssl::context create \
    -cert server.pem \
    -key server.key \
    -ca ca.pem \
    -verify peer]

# Set certificate pinning
set pins "dGVzdHBpbjEyMw== dGVzdHBpbjQ1Ng=="
set result [tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins]

puts "SSL context with certificate pinning: $result"
```

### Multiple Pin Support

```tcl
# Support multiple certificate pins for redundancy
set primary_pin "abc123def456"    ;# Primary certificate
set backup_pin "ghi789jkl012"     ;# Backup certificate
set pins "$primary_pin $backup_pin"

set ctx [tossl::ssl::context create]
set result [tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins]

if {$result eq "ok"} {
    puts "Multiple pins configured successfully"
} else {
    puts "Failed to configure multiple pins"
}
```

### Error Handling Example

```tcl
proc safe_set_cert_pinning {ctx pins} {
    if {[catch {
        set result [tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins]
        return $result
    } err]} {
        puts "Certificate pinning setup error: $err"
        return "error"
    }
}

# Usage
set ctx [tossl::ssl::context create]
set pins "test_pin_123 backup_pin_456"

set result [safe_set_cert_pinning $ctx $pins]

switch $result {
    "ok" {
        puts "Certificate pinning setup successful"
    }
    "error" {
        puts "Certificate pinning setup failed"
    }
    default {
        puts "Unexpected result: $result"
    }
}
```

### Manual Verification Workflow

Since the current implementation doesn't store pins, manual verification is required:

```tcl
# Create SSL context and set pins (stub)
set ctx [tossl::ssl::context create]
set expected_pins "abc123def456 ghi789jkl012"
tossl::ssl::set_cert_pinning -ctx $ctx -pins $expected_pins

# Connect to server
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Manually verify certificate pinning
set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $expected_pins]
set pin_match [lindex $result 1]

if {$pin_match eq "yes"} {
    puts "Certificate pinning verification successful"
} else {
    puts "Certificate pinning verification failed"
}

tossl::ssl::close -conn $conn
```

### Context Reuse Example

```tcl
# Create context and set pins multiple times
set ctx [tossl::ssl::context create]

# Set initial pins
set result1 [tossl::ssl::set_cert_pinning -ctx $ctx -pins "initial_pin"]

# Update pins (overwrites previous setting in stub implementation)
set result2 [tossl::ssl::set_cert_pinning -ctx $ctx -pins "updated_pin1 updated_pin2"]

# Set final pins
set result3 [tossl::ssl::set_cert_pinning -ctx $ctx -pins "final_pin"]

puts "Context reuse results: $result1, $result2, $result3"
```

## Error Handling

The command may return the following errors:

| Error | Description | Resolution |
|-------|-------------|------------|
| `wrong # args` | Incorrect number of arguments | Provide both `-ctx` and `-pins` parameters |
| `SSL context not found` | Invalid context handle | Verify context was created with `::tossl::ssl::context create` |

## Security Considerations

### Current Limitations

Since this is a stub implementation, consider the following security implications:

1. **No Automatic Verification**: Certificate pins are not automatically verified during SSL connections
2. **Manual Verification Required**: Use `::tossl::ssl::verify_cert_pinning` for manual verification
3. **No Storage**: Pins are not persisted in the SSL context
4. **No Integration**: The command doesn't integrate with the SSL handshake process

### Recommended Workflow

For secure certificate pinning with the current implementation:

```tcl
# 1. Create SSL context
set ctx [tossl::ssl::context create -ca ca.pem -verify peer]

# 2. Set certificate pins (stub - for future implementation)
set pins "expected_certificate_pin backup_certificate_pin"
tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins

# 3. Establish SSL connection
set conn [tossl::ssl::connect -ctx $ctx -host secure.example.com -port 443]

# 4. Manually verify certificate pinning
set result [tossl::ssl::verify_cert_pinning -conn $conn -pins $pins]
set pin_match [lindex $result 1]

# 5. Handle verification result
if {$pin_match eq "yes"} {
    puts "Certificate pinning verification successful"
    # Proceed with secure communication
} else {
    puts "Certificate pinning verification failed"
    tossl::ssl::close -conn $conn
    error "Certificate pin mismatch - connection aborted"
}
```

### Best Practices

1. **Always Verify Manually**: Since pins are not stored, always use `::tossl::ssl::verify_cert_pinning`
2. **Use Multiple Pins**: Provide backup pins for certificate renewal scenarios
3. **Secure Pin Storage**: Store pins securely in your application configuration
4. **Regular Updates**: Update pins when certificates are renewed
5. **Error Handling**: Implement proper error handling for pin verification failures

## Performance Considerations

### Current Implementation
- **Fast Execution**: The stub implementation executes quickly
- **No Storage Overhead**: No memory is used to store pins
- **No Verification Overhead**: No computational cost for pin verification

### Future Implementation Considerations
When the command is fully implemented, consider:
- **Memory Usage**: Pin storage will consume memory proportional to the number of pins
- **Verification Overhead**: Certificate fingerprint calculation during verification
- **Context Association**: Efficient pin lookup during SSL handshake

## Integration with Other Commands

The `::tossl::ssl::set_cert_pinning` command integrates with:

- `::tossl::ssl::context create` - Create SSL contexts for pinning configuration
- `::tossl::ssl::connect` - Establish SSL connections for pinning verification
- `::tossl::ssl::verify_cert_pinning` - Manual verification of certificate pins
- `::tossl::ssl::get_peer_cert` - Retrieve peer certificates for analysis
- `::tossl::x509::fingerprint` - Generate certificate fingerprints for pin creation

## Future Implementation

The planned full implementation should include:

1. **Pin Storage**: Store pins in the SSL context structure
2. **Automatic Verification**: Integrate pin verification into SSL handshake
3. **Pin Management**: Support for adding, removing, and updating pins
4. **Error Handling**: Proper error handling for pin verification failures
5. **Performance Optimization**: Efficient pin lookup and verification

### Proposed Enhanced Syntax

```tcl
# Future implementation might support:
tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins -auto_verify 1
tossl::ssl::set_cert_pinning -ctx $ctx -add_pin $new_pin
tossl::ssl::set_cert_pinning -ctx $ctx -remove_pin $old_pin
tossl::ssl::set_cert_pinning -ctx $ctx -list_pins
```

## Troubleshooting

### Common Issues

1. **Pins Not Verified**: Remember that pins are not automatically verified
2. **Context Not Found**: Ensure the SSL context was created successfully
3. **Manual Verification Required**: Use `::tossl::ssl::verify_cert_pinning` for verification

### Debugging

```tcl
# Debug certificate pinning setup
set ctx [tossl::ssl::context create]
puts "Context created: $ctx"

set pins "debug_pin_123"
set result [tossl::ssl::set_cert_pinning -ctx $ctx -pins $pins]
puts "Pinning setup result: $result"

# Note: Pins are not actually stored in current implementation
puts "Note: Pins are not stored in current stub implementation"
```

## Related Commands

- `::tossl::ssl::context create` - Create SSL contexts for pinning configuration
- `::tossl::ssl::verify_cert_pinning` - Verify certificate pins manually
- `::tossl::ssl::connect` - Establish SSL connections for pinning verification
- `::tossl::ssl::get_peer_cert` - Retrieve peer certificates
- `::tossl::x509::fingerprint` - Generate certificate fingerprints 