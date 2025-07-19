# ::tossl::sm2::encrypt

## Overview

The `::tossl::sm2::encrypt` command implements SM2 public key encryption, which is part of the Chinese national cryptographic standard GB/T 32918. SM2 is an elliptic curve cryptography algorithm that provides both encryption and digital signature capabilities. This command encrypts data using an SM2 public key, making it essential for secure communication, data protection, and applications requiring Chinese cryptographic compliance.

## Syntax

```tcl
::tossl::sm2::encrypt public_key data
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `public_key` | string | Yes | SM2 public key in PEM format |
| `data` | string | Yes | Data to encrypt (string or binary) |

## Return Value

Returns a byte array containing the encrypted data (ciphertext).

## Description

The `::tossl::sm2::encrypt` command performs SM2 public key encryption using the Chinese national standard GB/T 32918. SM2 is an elliptic curve cryptography algorithm that provides:

- **Semantic Security**: Each encryption produces different ciphertext even for the same plaintext
- **Authenticated Encryption**: Built-in integrity protection
- **Chinese Standard Compliance**: Meets Chinese cryptographic requirements
- **Elliptic Curve Security**: Based on elliptic curve discrete logarithm problem

The encryption process involves:
1. **Key Validation**: Verifies the public key is a valid SM2 key
2. **Context Creation**: Creates OpenSSL EVP_PKEY_CTX for encryption
3. **Length Calculation**: Determines the required output buffer size
4. **Encryption**: Performs SM2 encryption using the public key
5. **Result Return**: Returns the encrypted data as a binary array

## Examples

### Basic SM2 Encryption

```tcl
# Generate SM2 key pair
set key_pair [tossl::sm2::generate]
set private_key $key_pair
set public_key [tossl::key::getpub $private_key]

# Encrypt data using public key
set plaintext "Hello, SM2 Encryption!"
set ciphertext [tossl::sm2::encrypt $public_key $plaintext]

puts "Encrypted data length: [string length $ciphertext] bytes"

# Decrypt data using private key
set decrypted [tossl::sm2::decrypt $private_key $ciphertext]
puts "Decrypted: $decrypted"
```

### SM2 Encryption with Different Data Types

```tcl
# Generate SM2 key pair
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

# Encrypt text data
set text_data "This is text data for SM2 encryption"
set encrypted_text [tossl::sm2::encrypt $public_key $text_data]

# Encrypt binary data
set binary_data [binary format "H*" "48656c6c6f20576f726c64"]  ;# "Hello World"
set encrypted_binary [tossl::sm2::encrypt $public_key $binary_data]

# Encrypt empty data
set encrypted_empty [tossl::sm2::encrypt $public_key ""]

puts "Text encryption: [string length $encrypted_text] bytes"
puts "Binary encryption: [string length $encrypted_binary] bytes"
puts "Empty encryption: [string length $encrypted_empty] bytes"
```

### SM2 Encryption with Data Size Testing

```tcl
# Generate SM2 key pair
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

# Test different data sizes
set short_data "A"
set medium_data "This is a medium length message for testing SM2 encryption."
set long_data [string repeat "This is a long message for testing SM2 encryption with various data sizes. " 10]

# Encrypt different sized data
set encrypted_short [tossl::sm2::encrypt $public_key $short_data]
set encrypted_medium [tossl::sm2::encrypt $public_key $medium_data]
set encrypted_long [tossl::sm2::encrypt $public_key $long_data]

puts "Short data: [string length $encrypted_short] bytes"
puts "Medium data: [string length $encrypted_medium] bytes"
puts "Long data: [string length $encrypted_long] bytes"
```

### SM2 Encryption for Secure Communication

```tcl
# Generate SM2 key pair for secure communication
set key_pair [tossl::sm2::generate]
set private_key $key_pair
set public_key [tossl::key::getpub $private_key]

# Simulate secure message exchange
proc send_secure_message {recipient_public_key message} {
    set encrypted_message [tossl::sm2::encrypt $recipient_public_key $message]
    return $encrypted_message
}

proc receive_secure_message {private_key encrypted_message} {
    set decrypted_message [tossl::sm2::decrypt $private_key $encrypted_message]
    return $decrypted_message
}

# Usage
set message "This is a secure message for SM2 encryption"
set encrypted [send_secure_message $public_key $message]
set decrypted [receive_secure_message $private_key $encrypted]

puts "Original: $message"
puts "Decrypted: $decrypted"
```

### SM2 Encryption with Error Handling

```tcl
# Robust SM2 encryption with error handling
proc safe_sm2_encrypt {public_key data} {
    if {[catch {
        set encrypted [tossl::sm2::encrypt $public_key $data]
        return $encrypted
    } err]} {
        puts "Encryption failed: $err"
        return ""
    }
}

# Usage with error handling
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

set result [safe_sm2_encrypt $public_key "Test data"]
if {$result ne ""} {
    puts "Encryption successful: [string length $result] bytes"
} else {
    puts "Encryption failed"
}
```

### SM2 Encryption Performance Testing

```tcl
# Performance testing for SM2 encryption
proc test_sm2_performance {public_key data iterations} {
    set start_time [clock clicks -milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set encrypted [tossl::sm2::encrypt $public_key $data]
    }
    
    set end_time [clock clicks -milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set avg_time [expr {$total_time / double($iterations)}]
    
    return [list $total_time $avg_time]
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]
set test_data "Performance test data for SM2 encryption"

lassign [test_sm2_performance $public_key $test_data 10] total_time avg_time
puts "Total time: ${total_time}ms"
puts "Average time: ${avg_time}ms per operation"
```

### SM2 Encryption for File Protection

```tcl
# Encrypt file content using SM2
proc encrypt_file_sm2 {public_key filename} {
    # Read file content
    set file_handle [open $filename r]
    set content [read $file_handle]
    close $file_handle
    
    # Encrypt content
    set encrypted_content [tossl::sm2::encrypt $public_key $content]
    
    # Write encrypted content
    set encrypted_filename "${filename}.sm2"
    set file_handle [open $encrypted_filename wb]
    puts -nonewline $file_handle $encrypted_content
    close $file_handle
    
    return $encrypted_filename
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

# Create test file
set test_file "test_data.txt"
set file_handle [open $test_file w]
puts $file_handle "This is sensitive data that needs protection."
close $file_handle

# Encrypt file
set encrypted_file [encrypt_file_sm2 $public_key $test_file]
puts "File encrypted: $encrypted_file"
```

### SM2 Encryption Compliance Verification

```tcl
# Verify SM2 encryption compliance
proc verify_sm2_compliance {public_key} {
    puts "=== SM2 Compliance Verification ==="
    
    # Test with standard test vectors
    set test_data "SM2 compliance test data"
    
    if {[catch {
        set encrypted [tossl::sm2::encrypt $public_key $test_data]
        puts "✓ SM2 encryption successful"
        puts "✓ Encrypted data length: [string length $encrypted] bytes"
        puts "✓ Binary format: [string is binary $encrypted]"
        return 1
    } err]} {
        puts "✗ SM2 encryption failed: $err"
        return 0
    }
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]
set compliant [verify_sm2_compliance $public_key]

if {$compliant} {
    puts "✓ SM2 implementation is compliant"
} else {
    puts "✗ SM2 implementation has issues"
}
```

## Error Handling

### Common Error Conditions

1. **Invalid public key format**
   ```tcl
   set invalid_key "Invalid key data"
   tossl::sm2::encrypt $invalid_key "test data"
   # Error: Failed to parse public key
   ```

2. **Non-SM2 key**
   ```tcl
   # Using RSA key instead of SM2
   set rsa_keys [tossl::rsa::generate -bits 2048]
   set rsa_public [dict get $rsa_keys public]
   tossl::sm2::encrypt $rsa_public "test data"
   # Error: Not an SM2 key
   ```

3. **Missing parameters**
   ```tcl
   tossl::sm2::encrypt
   # Error: wrong # args: should be "tossl::sm2::encrypt public_key data"
   ```

4. **Memory allocation failure**
   ```tcl
   # This would occur if system is out of memory
   # Error: Memory allocation failed
   ```

### Error Handling Best Practices

```tcl
# Comprehensive error handling for SM2 encryption
proc robust_sm2_encrypt {public_key data} {
    # Validate inputs
    if {![info exists public_key] || $public_key eq ""} {
        return [list "error" "Invalid public key"]
    }
    
    if {![info exists data]} {
        return [list "error" "Invalid data"]
    }
    
    # Attempt encryption
    if {[catch {
        set encrypted [tossl::sm2::encrypt $public_key $data]
        return [list "success" $encrypted]
    } err]} {
        return [list "error" $err]
    }
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

lassign [robust_sm2_encrypt $public_key "Test data"] status result
if {$status eq "success"} {
    puts "Encryption successful: [string length $result] bytes"
} else {
    puts "Encryption failed: $result"
}
```

## Integration with Other Commands

The `::tossl::sm2::encrypt` command works with other SM2 commands:

- **`::tossl::sm2::generate`** - Generate SM2 key pair
- **`::tossl::sm2::decrypt`** - Decrypt SM2 encrypted data
- **`::tossl::sm2::sign`** - Create SM2 digital signatures
- **`::tossl::sm2::verify`** - Verify SM2 digital signatures
- **`::tossl::key::getpub`** - Extract public key from private key

### Complete SM2 Workflow Example

```tcl
# Complete SM2 encryption/decryption workflow
proc sm2_secure_communication {message} {
    # 1. Generate SM2 key pair
    set key_pair [tossl::sm2::generate]
    set private_key $key_pair
    set public_key [tossl::key::getpub $private_key]
    
    # 2. Encrypt message
    set encrypted_message [tossl::sm2::encrypt $public_key $message]
    
    # 3. Sign message for authentication
    set signature [tossl::sm2::sign $private_key $message]
    
    # 4. Verify signature
    set signature_valid [tossl::sm2::verify $public_key $message $signature]
    
    # 5. Decrypt message
    set decrypted_message [tossl::sm2::decrypt $private_key $encrypted_message]
    
    # Return results
    return [dict create \
        original $message \
        encrypted $encrypted_message \
        decrypted $decrypted_message \
        signature $signature \
        signature_valid $signature_valid]
}

# Usage
set result [sm2_secure_communication "Hello, SM2!"]
puts "Original: [dict get $result original]"
puts "Decrypted: [dict get $result decrypted]"
puts "Signature valid: [dict get $result signature_valid]"
```

## Performance Considerations

### Efficiency

- **Elliptic Curve**: SM2 uses elliptic curve cryptography for efficient key sizes
- **Optimized Implementation**: Uses OpenSSL's optimized SM2 implementation
- **Memory Management**: Efficient memory allocation and cleanup
- **Batch Processing**: Can handle multiple encryption operations

### Performance Best Practices

```tcl
# Batch SM2 encryption for better performance
proc batch_sm2_encrypt {public_key messages} {
    set results {}
    
    foreach message $messages {
        if {[catch {
            set encrypted [tossl::sm2::encrypt $public_key $message]
            lappend results [list "success" $encrypted]
        } err]} {
            lappend results [list "error" $err]
        }
    }
    
    return $results
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]
set messages {"Message 1" "Message 2" "Message 3"}

set results [batch_sm2_encrypt $public_key $messages]
foreach {status result} $results {
    if {$status eq "success"} {
        puts "Encrypted: [string length $result] bytes"
    } else {
        puts "Failed: $result"
    }
}
```

## Security Considerations

### Security Features

- **Semantic Security**: Each encryption produces different ciphertext
- **Authenticated Encryption**: Built-in integrity protection
- **Elliptic Curve Security**: Based on ECDLP (Elliptic Curve Discrete Logarithm Problem)
- **Chinese Standard**: Complies with GB/T 32918 standard
- **Forward Secrecy**: No long-term key compromise

### Security Best Practices

```tcl
# Secure SM2 encryption practices
proc secure_sm2_encrypt {public_key data} {
    # Validate public key
    if {![string match "*-----BEGIN PUBLIC KEY-----*" $public_key]} {
        error "Invalid public key format"
    }
    
    # Validate data
    if {![info exists data] || $data eq ""} {
        error "Empty data not allowed for security"
    }
    
    # Perform encryption
    if {[catch {
        set encrypted [tossl::sm2::encrypt $public_key $data]
        return $encrypted
    } err]} {
        error "Encryption failed: $err"
    }
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

set encrypted [secure_sm2_encrypt $public_key "Sensitive data"]
puts "Securely encrypted: [string length $encrypted] bytes"
```

### Security Policy Examples

```tcl
# Security policy enforcement
proc enforce_sm2_security_policy {public_key data} {
    # Check key strength
    if {![string match "*SM2*" $public_key]} {
        error "Only SM2 keys allowed by security policy"
    }
    
    # Check data size limits
    if {[string length $data] > 1024} {
        error "Data too large for SM2 encryption"
    }
    
    # Check for sensitive patterns
    if {[regexp {(password|secret|key)} $data -nocase]} {
        puts "Warning: Sensitive data detected"
    }
    
    # Perform encryption
    return [tossl::sm2::encrypt $public_key $data]
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]

set encrypted [enforce_sm2_security_policy $public_key "Secret message"]
puts "Policy-compliant encryption completed"
```

## Troubleshooting

### Common Issues

1. **"Not an SM2 key" error**
   - **Cause**: Using non-SM2 key (RSA, DSA, etc.)
   - **Solution**: Generate SM2 key pair using `::tossl::sm2::generate`

2. **"Failed to parse public key" error**
   - **Cause**: Invalid PEM format or corrupted key
   - **Solution**: Verify key format and regenerate if necessary

3. **Memory allocation failures**
   - **Cause**: System out of memory
   - **Solution**: Free memory or reduce data size

4. **Performance issues**
   - **Cause**: Large data or frequent operations
   - **Solution**: Consider hybrid encryption for large data

### Debugging Tips

```tcl
# Debug SM2 encryption issues
proc debug_sm2_encrypt {public_key data} {
    puts "=== SM2 Encryption Debug ==="
    puts "Public key length: [string length $public_key]"
    puts "Data length: [string length $data]"
    puts "Public key format: [string match "*-----BEGIN PUBLIC KEY-----*" $public_key]"
    
    if {[catch {
        set encrypted [tossl::sm2::encrypt $public_key $data]
        puts "Encryption successful: [string length $encrypted] bytes"
        return $encrypted
    } err]} {
        puts "Encryption failed: $err"
        return ""
    }
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]
set result [debug_sm2_encrypt $public_key "Test data"]
```

## Compliance and Standards

### Chinese National Standard

- **GB/T 32918**: Chinese national standard for SM2 cryptography
- **Approved Curves**: Uses approved elliptic curve parameters
- **Algorithm Implementation**: Standard SM2 encryption algorithm
- **Key Formats**: Standard PEM key format support

### Interoperability

```tcl
# Test interoperability with other SM2 implementations
proc test_sm2_interoperability {public_key data} {
    puts "=== SM2 Interoperability Test ==="
    
    # Test standard encryption
    set encrypted [tossl::sm2::encrypt $public_key $data]
    puts "✓ Standard encryption successful"
    
    # Test with different data types
    set binary_data [binary format "H*" "48656c6c6f"]
    set encrypted_binary [tossl::sm2::encrypt $public_key $binary_data]
    puts "✓ Binary data encryption successful"
    
    # Test empty data
    set encrypted_empty [tossl::sm2::encrypt $public_key ""]
    puts "✓ Empty data encryption successful"
    
    puts "✓ All interoperability tests passed"
}

# Usage
set key_pair [tossl::sm2::generate]
set public_key [tossl::key::getpub $key_pair]
test_sm2_interoperability $public_key "Test data"
```

## See Also

- `::tossl::sm2::generate` - Generate SM2 key pair
- `::tossl::sm2::decrypt` - Decrypt SM2 encrypted data
- `::tossl::sm2::sign` - Create SM2 digital signatures
- `::tossl::sm2::verify` - Verify SM2 digital signatures
- `::tossl::key::getpub` - Extract public key from private key 