# ::tossl::rand::key

Generate a random key for a specific cipher algorithm.

## Syntax

    tossl::rand::key -alg <algorithm> ?-len <length>?

- `-alg <algorithm>`: The cipher algorithm name (e.g., `aes-256-cbc`, `chacha20-poly1305`)
- `-len <length>`: Optional custom key length in bytes (currently ignored - uses algorithm's required length)

## Description

Generates a cryptographically secure random key of the appropriate length for the specified cipher algorithm. The command automatically determines the correct key length based on the algorithm's requirements. The `-len` parameter is parsed but currently ignored in the implementation.

This command is essential for cryptographic operations that require properly sized keys for specific cipher algorithms. It ensures that the generated key meets the algorithm's security requirements.

## Output

Returns a byte array containing the randomly generated key with the appropriate length for the specified algorithm.

## Examples

### Basic Key Generation

```tcl
# Generate AES-256-CBC key (32 bytes)
set key [tossl::rand::key -alg aes-256-cbc]
puts "AES-256 key: [binary encode hex $key]"
puts "Key length: [string length $key] bytes"
```

### Different Algorithm Keys

```tcl
# Generate keys for different algorithms
set aes128_key [tossl::rand::key -alg aes-128-cbc]
set aes256_key [tossl::rand::key -alg aes-256-cbc]
set chacha_key [tossl::rand::key -alg chacha20-poly1305]

puts "AES-128 key: [string length $aes128_key] bytes"
puts "AES-256 key: [string length $aes256_key] bytes"
puts "ChaCha20 key: [string length $chacha_key] bytes"
```

### Custom Key Length (Note: Currently Ignored)

```tcl
# Generate AES-256-CBC key with custom length
# Note: The -len parameter is currently ignored by the implementation
set key [tossl::rand::key -alg aes-256-cbc -len 48]
puts "Key length: [string length $key] bytes"  # Will be 32, not 48
```

### Complete Encryption Workflow

```tcl
# Generate key and IV for AES-256-GCM
set key [tossl::rand::key -alg aes-256-gcm]
set iv [tossl::rand::iv -alg aes-256-gcm]
set plaintext "Secret message"

# Encrypt the data
set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $iv $plaintext]
puts "Encrypted successfully"
```

### Multiple Key Generation

```tcl
# Generate multiple keys for different purposes
set keys {}
set algorithms {aes-128-cbc aes-256-cbc chacha20-poly1305}

foreach algorithm $algorithms {
    set key [tossl::rand::key -alg $algorithm]
    lappend keys $key
    puts "$algorithm: [string length $key] bytes"
}

# Verify all keys are different
set unique_keys [lsort -unique $keys]
if {[llength $unique_keys] == [llength $keys]} {
    puts "✓ All keys are unique"
} else {
    puts "✗ Some keys are identical"
}
```

### Key Length Validation

```tcl
# Verify key lengths for different algorithms
set test_cases {
    {"aes-128-cbc" 16}
    {"aes-256-cbc" 32}
    {"aes-128-gcm" 16}
    {"aes-256-gcm" 32}
    {"chacha20-poly1305" 32}
    {"des-cbc" 8}
    {"bf-cbc" 16}
}

foreach {algorithm expected_length} $test_cases {
    set key [tossl::rand::key -alg $algorithm]
    set actual_length [string length $key]
    
    if {$actual_length == $expected_length} {
        puts "✓ $algorithm: $actual_length bytes (correct)"
    } else {
        puts "✗ $algorithm: $actual_length bytes (expected $expected_length)"
    }
}
```

### Error Handling

```tcl
# Handle invalid algorithms
if {[catch {tossl::rand::key -alg "invalid-algorithm"} result]} {
    puts "Error: $result"
}

# Handle missing algorithm
if {[catch {tossl::rand::key -len 32} result]} {
    puts "Error: $result"
}

# Handle invalid length
if {[catch {tossl::rand::key -alg "aes-256-cbc" -len -1} result]} {
    puts "Error: $result"
}
```

### Performance Testing

```tcl
# Test key generation performance
set start_time [clock milliseconds]
set algorithm "aes-256-cbc"

for {set i 0} {$i < 1000} {incr i} {
    set key [tossl::rand::key -alg $algorithm]
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "Generated 1000 keys in ${duration}ms"
puts "Rate: [expr {1000.0 / ($duration / 1000.0)}] keys/second"
```

### Key Quality Validation

```tcl
# Validate key quality
proc validate_key {key} {
    set length [string length $key]
    puts "Key length: $length bytes"
    
    # Check for all zeros
    set all_zeros 1
    for {set i 0} {$i < $length} {incr i} {
        if {[string index $key $i] ne "\x00"} {
            set all_zeros 0
            break
        }
    }
    
    if {$all_zeros} {
        puts "✗ Key is all zeros (suspicious)"
        return 0
    } else {
        puts "✓ Key is not all zeros"
    }
    
    # Check for all ones
    set all_ones 1
    for {set i 0} {$i < $length} {incr i} {
        if {[string index $key $i] ne "\xff"} {
            set all_ones 0
            break
        }
    }
    
    if {$all_ones} {
        puts "✗ Key is all ones (suspicious)"
        return 0
    } else {
        puts "✓ Key is not all ones"
    }
    
    puts "✓ Key appears to be random"
    return 1
}

# Test key quality
set key [tossl::rand::key -alg aes-256-cbc]
validate_key $key
```

## Supported Algorithms

The following cipher algorithms are supported (availability may vary by OpenSSL build):

### AES (Advanced Encryption Standard)
- `aes-128-cbc` - AES-128 in CBC mode (16-byte key)
- `aes-192-cbc` - AES-192 in CBC mode (24-byte key)
- `aes-256-cbc` - AES-256 in CBC mode (32-byte key)
- `aes-128-gcm` - AES-128 in GCM mode (16-byte key)
- `aes-256-gcm` - AES-256 in GCM mode (32-byte key)

### ChaCha20
- `chacha20` - ChaCha20 stream cipher (32-byte key)
- `chacha20-poly1305` - ChaCha20-Poly1305 authenticated encryption (32-byte key)

### Legacy Algorithms
- `des-cbc` - DES in CBC mode (8-byte key)
- `des-ede3-cbc` - Triple DES in CBC mode (24-byte key)
- `bf-cbc` - Blowfish in CBC mode (16-byte key)
- `cast5-cbc` - CAST5 in CBC mode (16-byte key)

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::rand::key
# Error: wrong # args: should be "tossl::rand::key -alg cipher ?-len length?"
```

- If the algorithm is not specified, an error is returned:

```tcl
tossl::rand::key -len 32
# Error: Cipher algorithm is required
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::rand::key -alg "invalid-algorithm"
# Error: Unknown cipher algorithm
```

- If the length parameter is invalid, an error is returned:

```tcl
tossl::rand::key -alg "aes-256-cbc" -len -1
# Error: expected integer but got "-1"
```

- If memory allocation fails, an error is returned:

```tcl
tossl::rand::key -alg "aes-256-cbc" -len 1000000
# Error: OpenSSL: memory allocation failed
```

- If random number generation fails, an error is returned:

```tcl
tossl::rand::key -alg "aes-256-cbc"
# Error: OpenSSL: random generation failed
```

## Key Length Requirements

### Standard Key Lengths

- **AES-128**: 16 bytes (128 bits)
- **AES-192**: 24 bytes (192 bits)
- **AES-256**: 32 bytes (256 bits)
- **ChaCha20**: 32 bytes (256 bits)
- **DES**: 8 bytes (64 bits, but only 56 bits are used)
- **Triple DES**: 24 bytes (192 bits, but only 168 bits are used)
- **Blowfish**: 16 bytes (128 bits)
- **CAST5**: 16 bytes (128 bits)

### Custom Key Lengths

**Note:** The `-len` parameter is currently parsed but ignored by the implementation. The key length is always determined by the algorithm's requirements.

When the `-len` parameter is properly implemented, you will be able to specify a custom key length. However, be aware that:

- Some algorithms may not work correctly with non-standard key lengths
- Using shorter keys than recommended reduces security
- Using longer keys than necessary may not provide additional security

## Security Considerations

### Key Generation Security

- **Cryptographic Quality**: Keys are generated using OpenSSL's `RAND_bytes()` function
- **Entropy Source**: Depends on the system's entropy pool and OpenSSL's random number generator
- **Key Length**: Always use the recommended key length for the algorithm
- **Key Uniqueness**: Each call generates a unique key (unless the random number generator fails)

### Best Practices

- **Use Recommended Lengths**: Stick to the algorithm's default key length unless you have specific requirements
- **Validate Keys**: Check that generated keys are not all zeros or other obvious patterns
- **Secure Storage**: Store keys securely and never expose them in logs or error messages
- **Key Rotation**: Generate new keys regularly for long-term security
- **Algorithm Selection**: Use modern algorithms like AES-256-GCM or ChaCha20-Poly1305

### Common Mistakes

```tcl
# Bad: Using weak algorithm
set key [tossl::rand::key -alg des-cbc]  # Only 56-bit effective key

# Bad: Using custom length that's too short
set key [tossl::rand::key -alg aes-256-cbc -len 8]  # Too short for AES-256

# Good: Using strong algorithm with recommended length
set key [tossl::rand::key -alg aes-256-gcm]

# Good: Using custom length that's appropriate
set key [tossl::rand::key -alg aes-256-cbc -len 32]  # Correct for AES-256
```

### Key Management

- **Never Reuse Keys**: Generate a new key for each encryption operation
- **Secure Transmission**: Use secure channels to transmit keys
- **Key Derivation**: Consider using key derivation functions for password-based encryption
- **Hardware Security**: Use hardware security modules (HSMs) for high-security applications

## Performance Characteristics

- **Time Complexity**: O(1) for key generation
- **Memory Usage**: O(key_length) for storing the generated key
- **Typical Performance**: ~10,000-100,000 keys/second on modern hardware
- **Random Number Generation**: Depends on system entropy availability

## Notes

- The command uses OpenSSL's `RAND_bytes()` function internally
- Key generation speed depends on the system's entropy pool
- The `-len` parameter overrides the algorithm's default key length
- All generated keys are cryptographically secure random bytes
- The command automatically handles key length requirements for each algorithm
- Use `tossl::rand::iv` to generate corresponding initialization vectors
- The command is designed to work seamlessly with `tossl::encrypt` and `tossl::decrypt` 