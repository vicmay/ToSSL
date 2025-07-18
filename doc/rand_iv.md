# ::tossl::rand::iv

Generate a random initialization vector (IV) for a specific cipher algorithm.

## Syntax

    tossl::rand::iv -alg <algorithm>

- `-alg <algorithm>`: The cipher algorithm name (e.g., `aes-256-cbc`, `aes-128-gcm`)

## Description

Generates a cryptographically secure random initialization vector (IV) of the appropriate length for the specified cipher algorithm. The IV length is determined by the algorithm's block size and mode of operation.

This command is essential for cryptographic operations that require properly sized IVs for specific cipher algorithms. It ensures that the generated IV meets the algorithm's security requirements and provides the necessary randomness for secure encryption.

## Output

Returns a byte array containing the randomly generated IV with the appropriate length for the specified algorithm.

## Examples

### Basic IV Generation

```tcl
# Generate AES-256-CBC IV (16 bytes)
set iv [tossl::rand::iv -alg aes-256-cbc]
puts "AES-256 IV: [binary encode hex $iv]"
puts "IV length: [string length $iv] bytes"
```

### Different Algorithm IVs

```tcl
# Generate IVs for different algorithms
set aes_iv [tossl::rand::iv -alg aes-128-cbc]
set gcm_nonce [tossl::rand::iv -alg aes-128-gcm]
set des_iv [tossl::rand::iv -alg des-cbc]

puts "AES-128-CBC IV: [string length $aes_iv] bytes"
puts "AES-128-GCM nonce: [string length $gcm_nonce] bytes"
puts "DES-CBC IV: [string length $des_iv] bytes"
```

### Complete Encryption Workflow

```tcl
# Generate key and IV for AES-256-CBC
set key [tossl::rand::key -alg aes-256-cbc]
set iv [tossl::rand::iv -alg aes-256-cbc]
set plaintext "Secret message"

# Encrypt the data
set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $plaintext]
puts "Encrypted successfully"
```

### Multiple IV Generation

```tcl
# Generate multiple IVs for different purposes
set ivs {}
set algorithms {aes-128-cbc aes-256-cbc aes-128-gcm}

foreach algorithm $algorithms {
    set iv [tossl::rand::iv -alg $algorithm]
    lappend ivs $iv
    puts "$algorithm: [string length $iv] bytes"
}

# Verify all IVs are different
set unique_ivs [lsort -unique $ivs]
if {[llength $unique_ivs] == [llength $ivs]} {
    puts "✓ All IVs are unique"
} else {
    puts "✗ Some IVs are identical"
}
```

### IV Length Validation

```tcl
# Verify IV lengths for different algorithms
set test_cases {
    {"aes-128-cbc" 16}
    {"aes-256-cbc" 16}
    {"aes-128-gcm" 12}
    {"aes-256-gcm" 12}
    {"des-cbc" 8}
    {"bf-cbc" 8}
    {"cast5-cbc" 8}
}

foreach {algorithm expected_length} $test_cases {
    set iv [tossl::rand::iv -alg $algorithm]
    set actual_length [string length $iv]
    
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
if {[catch {tossl::rand::iv -alg "invalid-algorithm"} result]} {
    puts "Error: $result"
}

# Handle algorithms that don't require IVs
if {[catch {tossl::rand::iv -alg "aes-128-ecb"} result]} {
    puts "Error: $result"
}

# Handle missing algorithm
if {[catch {tossl::rand::iv -unknown "value"} result]} {
    puts "Error: $result"
}
```

### Performance Testing

```tcl
# Test IV generation performance
set start_time [clock milliseconds]
set algorithm "aes-256-cbc"

for {set i 0} {$i < 1000} {incr i} {
    set iv [tossl::rand::iv -alg $algorithm]
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "Generated 1000 IVs in ${duration}ms"
puts "Rate: [expr {1000.0 / ($duration / 1000.0)}] IVs/second"
```

### IV Quality Validation

```tcl
# Validate IV quality
proc validate_iv {iv} {
    set length [string length $iv]
    puts "IV length: $length bytes"
    
    # Check for all zeros
    set all_zeros 1
    for {set i 0} {$i < $length} {incr i} {
        if {[string index $iv $i] ne "\x00"} {
            set all_zeros 0
            break
        }
    }
    
    if {$all_zeros} {
        puts "✗ IV is all zeros (suspicious)"
        return 0
    } else {
        puts "✓ IV is not all zeros"
    }
    
    # Check for all ones
    set all_ones 1
    for {set i 0} {$i < $length} {incr i} {
        if {[string index $iv $i] ne "\xff"} {
            set all_ones 0
            break
        }
    }
    
    if {$all_ones} {
        puts "✗ IV is all ones (suspicious)"
        return 0
    } else {
        puts "✓ IV is not all ones"
    }
    
    puts "✓ IV appears to be random"
    return 1
}

# Test IV quality
set iv [tossl::rand::iv -alg aes-256-cbc]
validate_iv $iv
```

### GCM Mode Workflow

```tcl
# GCM mode uses nonce instead of IV
set algorithm "aes-256-gcm"
set plaintext "Secret message for GCM"

# Generate key and nonce
set key [tossl::rand::key -alg $algorithm]
set nonce [tossl::rand::iv -alg $algorithm]  ;# Actually a nonce for GCM

puts "Key length: [string length $key] bytes"
puts "Nonce length: [string length $nonce] bytes"

# Encrypt with GCM (returns dict with ciphertext and tag)
set encrypted [tossl::encrypt -alg $algorithm -key $key -iv $nonce $plaintext]
set ciphertext [dict get $encrypted ciphertext]
set tag [dict get $encrypted tag]

# Decrypt GCM mode
set decrypted [tossl::decrypt -alg $algorithm -key $key -iv $nonce $ciphertext -tag $tag]
puts "Decrypted: $decrypted"
```

## Supported Algorithms

The following cipher algorithms are supported (availability may vary by OpenSSL build):

### AES (Advanced Encryption Standard)
- `aes-128-cbc` - AES-128 in CBC mode (16-byte IV)
- `aes-192-cbc` - AES-192 in CBC mode (16-byte IV)
- `aes-256-cbc` - AES-256 in CBC mode (16-byte IV)
- `aes-128-gcm` - AES-128 in GCM mode (12-byte nonce)
- `aes-256-gcm` - AES-256 in GCM mode (12-byte nonce)
- `aes-128-ccm` - AES-128 in CCM mode (12-byte nonce)
- `aes-256-ccm` - AES-256 in CCM mode (12-byte nonce)

### Legacy Algorithms
- `des-cbc` - DES in CBC mode (8-byte IV)
- `des-cfb` - DES in CFB mode (8-byte IV)
- `des-ofb` - DES in OFB mode (8-byte IV)
- `des-ede3-cbc` - Triple DES in CBC mode (8-byte IV)
- `bf-cbc` - Blowfish in CBC mode (8-byte IV)
- `cast5-cbc` - CAST5 in CBC mode (8-byte IV)

### Algorithms Without IVs
The following algorithms do not require IVs and will return an error:
- `aes-128-ecb` - AES-128 in ECB mode (not recommended)
- `aes-256-ecb` - AES-256 in ECB mode (not recommended)

### Algorithms With IV Support
The following algorithms support IVs (including ChaCha20 variants):
- `chacha20` - ChaCha20 stream cipher (16-byte IV)
- `chacha20-poly1305` - ChaCha20-Poly1305 authenticated encryption (12-byte nonce)

## IV Length Requirements

### Standard IV Lengths

- **AES-CBC**: 16 bytes (128 bits)
- **AES-GCM/CCM**: 12 bytes (96 bits) - called "nonce"
- **DES variants**: 8 bytes (64 bits)
- **Blowfish**: 8 bytes (64 bits)
- **CAST5**: 8 bytes (64 bits)

### IV vs Nonce

- **IV (Initialization Vector)**: Used in CBC, CFB, OFB modes
- **Nonce (Number used once)**: Used in GCM, CCM, ChaCha20-Poly1305 modes
- Both serve the same purpose but have different security requirements

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::rand::iv
# Error: wrong # args: should be "tossl::rand::iv -alg cipher"
```

- If the algorithm is not specified, an error is returned:

```tcl
tossl::rand::iv -unknown "value"
# Error: Expected -alg option
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::rand::iv -alg "invalid-algorithm"
# Error: Unknown cipher algorithm
```

- If the algorithm does not require an IV, an error is returned:

```tcl
tossl::rand::iv -alg "aes-128-ecb"
# Error: Cipher does not require IV
```

- If memory allocation fails, an error is returned:

```tcl
tossl::rand::iv -alg "aes-256-cbc"
# Error: OpenSSL: memory allocation failed
```

- If random number generation fails, an error is returned:

```tcl
tossl::rand::iv -alg "aes-256-cbc"
# Error: OpenSSL: random generation failed
```

## Security Considerations

### IV Generation Security

- **Cryptographic Quality**: IVs are generated using OpenSSL's `RAND_bytes()` function
- **Entropy Source**: Depends on the system's entropy pool and OpenSSL's random number generator
- **IV Length**: Always use the recommended IV length for the algorithm
- **IV Uniqueness**: Each call generates a unique IV (unless the random number generator fails)

### Best Practices

- **Use Recommended Lengths**: Always use the algorithm's default IV length
- **Validate IVs**: Check that generated IVs are not all zeros or other obvious patterns
- **Secure Storage**: Store IVs securely and never expose them in logs or error messages
- **IV Uniqueness**: Never reuse IVs for different encryption operations
- **Algorithm Selection**: Use modern algorithms like AES-GCM or ChaCha20-Poly1305

### Common Mistakes

```tcl
# Bad: Using static IV
set iv "static_iv_123"  # Don't do this

# Bad: Reusing IV
set iv [tossl::rand::iv -alg aes-256-cbc]
set ciphertext1 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $data1]
set ciphertext2 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $data2]  # Don't reuse IV

# Good: Generate fresh IV for each operation
set iv1 [tossl::rand::iv -alg aes-256-cbc]
set iv2 [tossl::rand::iv -alg aes-256-cbc]
set ciphertext1 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv1 $data1]
set ciphertext2 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv2 $data2]
```

### IV Management

- **Never Reuse IVs**: Generate a new IV for each encryption operation
- **Secure Transmission**: Use secure channels to transmit IVs
- **IV Storage**: Store IVs alongside ciphertext for decryption
- **Hardware Security**: Use hardware security modules (HSMs) for high-security applications

## Performance Characteristics

- **Time Complexity**: O(1) for IV generation
- **Memory Usage**: O(iv_length) for storing the generated IV
- **Typical Performance**: ~10,000-100,000 IVs/second on modern hardware
- **Random Number Generation**: Depends on system entropy availability

## Notes

- The command uses OpenSSL's `RAND_bytes()` function internally
- IV generation speed depends on the system's entropy pool
- All generated IVs are cryptographically secure random bytes
- The command automatically handles IV length requirements for each algorithm
- Use `tossl::rand::key` to generate corresponding encryption keys
- The command is designed to work seamlessly with `tossl::encrypt` and `tossl::decrypt`
- For GCM/CCM modes, the IV is technically called a "nonce" but serves the same purpose 