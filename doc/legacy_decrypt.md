# ::tossl::legacy::decrypt

Decrypt data using a legacy cipher algorithm.

## Syntax

    tossl::legacy::decrypt <algorithm> <key> <iv> <data>

- `<algorithm>`: The legacy cipher algorithm name (e.g., `des-cbc`, `bf-cbc`, `rc4`)
- `<key>`: The decryption key (byte array)
- `<iv>`: The initialization vector (byte array, empty string for stream ciphers/ECB mode)
- `<data>`: The data to decrypt (ciphertext as byte array)

## Description

Decrypts data using legacy cipher algorithms that are not recommended for new applications but may be needed for compatibility with older systems. The command supports various legacy algorithms including DES, Blowfish, CAST5, and RC4.

The decryption process uses the specified algorithm, key, and initialization vector to transform the ciphertext back into plaintext. The resulting plaintext is returned as a byte array.

## Output

Returns a byte array containing the decrypted data (plaintext).

## Examples

### Basic Legacy Decryption

```tcl
# Generate key and IV for DES-CBC
set key [tossl::legacy::keygen "des-cbc"]
set iv [tossl::legacy::ivgen "des-cbc"]
set plaintext "Secret message"

# Encrypt the data first
set ciphertext [tossl::legacy::encrypt "des-cbc" $key $iv $plaintext]

# Decrypt the data
set decrypted [tossl::legacy::decrypt "des-cbc" $key $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### Complete Legacy Decryption Workflow

```tcl
# Complete workflow for legacy encryption and decryption
set algorithm "bf-cbc"
set plaintext "Hello, World! This is a test message."

# Generate key and IV
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

puts "Algorithm: $algorithm"
puts "Key: [binary encode hex $key]"
puts "IV: [binary encode hex $iv]"
puts "Plaintext: $plaintext"

# Encrypt
set ciphertext [tossl::legacy::encrypt $algorithm $key $iv $plaintext]
puts "Ciphertext: [binary encode hex $ciphertext]"

# Decrypt (round-trip test)
set decrypted [tossl::legacy::decrypt $algorithm $key $iv $ciphertext]
puts "Decrypted: $decrypted"

if {$decrypted eq $plaintext} {
    puts "✓ Encryption/decryption round-trip successful"
} else {
    puts "✗ Encryption/decryption round-trip failed"
}
```

### Stream Cipher Decryption (RC4)

```tcl
# RC4 is a stream cipher that doesn't require an IV
set algorithm "rc4"
set key [tossl::legacy::keygen $algorithm]
set plaintext "Stream cipher test message"

# For stream ciphers, use empty IV
set iv ""

# Encrypt first
set ciphertext [tossl::legacy::encrypt $algorithm $key $iv $plaintext]

# Decrypt
set decrypted [tossl::legacy::decrypt $algorithm $key $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### ECB Mode Decryption (No IV Required)

```tcl
# ECB mode doesn't require an IV
set algorithm "des-ecb"
set key [tossl::legacy::keygen $algorithm]
set plaintext "ECB mode test"

# For ECB mode, use empty IV
set iv ""

# Encrypt first
set ciphertext [tossl::legacy::encrypt $algorithm $key $iv $plaintext]

# Decrypt
set decrypted [tossl::legacy::decrypt $algorithm $key $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### Multiple Algorithm Testing

```tcl
# Test multiple legacy algorithms
set algorithms {
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "cast5-cbc"
    "rc4"
}

set test_data "Test message for multiple algorithms"
set results {}

foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    
    # Get algorithm info
    set info [tossl::legacy::info $algorithm]
    set iv_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key_name [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key_name eq "iv_length"} {
            set iv_length $value
            break
        }
    }
    
    # Generate key and IV
    set key [tossl::legacy::keygen $algorithm]
    if {$iv_length > 0} {
        set iv [tossl::legacy::ivgen $algorithm]
    } else {
        set iv ""
    }
    
    # Encrypt
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Test decryption
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0 && $decrypted eq $test_data} {
            puts "  ✓ Decryption successful"
            lappend results "$algorithm: OK"
        } else {
            puts "  ✗ Decryption failed"
            lappend results "$algorithm: FAIL"
        }
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
        lappend results "$algorithm: FAIL"
    }
}

puts "\nResults:"
foreach result $results {
    puts "  $result"
}
```

### Error Handling

```tcl
# Handle invalid algorithms
set rc [catch {tossl::legacy::decrypt "invalid-algorithm" "key" "iv" "data"} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle wrong key/IV lengths
set algorithm "des-cbc"
set short_key "short"
set short_iv "short"
set data "test"

set rc [catch {tossl::legacy::decrypt $algorithm $short_key $short_iv $data} result]
if {$rc != 0} {
    puts "Error with wrong lengths: $result"
}
```

### Data Size Testing

```tcl
# Test with different data sizes
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

set test_cases {
    ""                    ;# Empty string
    "A"                   ;# Single character
    "Hello"               ;# Short string
    "This is a longer test message."
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
}

foreach test_data $test_cases {
    puts "Testing data size: [string length $test_data] bytes"
    
    # Encrypt first
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Then decrypt
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            if {$decrypted eq $test_data} {
                puts "  ✓ Decryption round-trip successful"
            } else {
                puts "  ✗ Decryption round-trip failed"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
        }
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
    }
}
```

### Invalid Ciphertext Handling

```tcl
# Test with invalid ciphertext
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

# Test with random data as ciphertext
set random_ciphertext [tossl::randbytes 32]
set rc [catch {tossl::legacy::decrypt $algorithm $key $iv $random_ciphertext} result]
if {$rc != 0} {
    puts "✓ Correctly failed with random ciphertext: $result"
} else {
    puts "WARNING: Decryption succeeded with random ciphertext"
}

# Test with empty ciphertext
set rc [catch {tossl::legacy::decrypt $algorithm $key $iv ""} result]
if {$rc != 0} {
    puts "✓ Correctly failed with empty ciphertext: $result"
} else {
    puts "WARNING: Decryption succeeded with empty ciphertext"
}
```

### Multiple Round-Trip Testing

```tcl
# Test multiple encryption/decryption round-trips
set algorithm "bf-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]
set original_data "Multiple round-trip test data"

puts "Testing multiple round-trips with $algorithm..."

for {set i 0} {$i < 5} {incr i} {
    puts "  Round-trip $i..."
    
    # Encrypt
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $original_data} ciphertext]
    if {$rc == 0} {
        puts "    ✓ Encryption successful"
        
        # Decrypt
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            if {$decrypted eq $original_data} {
                puts "    ✓ Decryption successful"
            } else {
                puts "    ✗ Decryption failed - data mismatch"
            }
        } else {
            puts "    ✗ Decryption failed: $decrypted"
        }
    } else {
        puts "    ✗ Encryption failed: $ciphertext"
    }
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::legacy::decrypt
# Error: wrong # args: should be "tossl::legacy::decrypt algorithm key iv data"
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::legacy::decrypt "invalid-algorithm" "key" "iv" "data"
# Error: Unsupported legacy cipher algorithm
```

- If the key or IV length is incorrect for the algorithm, an error may be returned:

```tcl
tossl::legacy::decrypt "des-cbc" "short-key" "short-iv" "data"
# Error: Failed to initialize decryption
```

- If the ciphertext is invalid or corrupted, an error may be returned:

```tcl
tossl::legacy::decrypt "des-cbc" "key" "iv" "invalid-data"
# Error: Failed to decrypt data
```

- If memory allocation fails, an error is returned:

```tcl
tossl::legacy::decrypt "des-cbc" "key" "iv" "very-large-data"
# Error: Memory allocation failed
```

## Supported Algorithms

The following legacy algorithms are supported (availability may vary by OpenSSL build):

### DES (Data Encryption Standard)
- `des-ecb` - DES in ECB mode (no IV required)
- `des-cbc` - DES in CBC mode (8-byte IV)
- `des-cfb` - DES in CFB mode (8-byte IV)
- `des-ofb` - DES in OFB mode (8-byte IV)
- `des-ede-cbc` - DES-EDE in CBC mode (8-byte IV)
- `des-ede3-cbc` - DES-EDE3 in CBC mode (8-byte IV)

### Blowfish
- `bf-ecb` - Blowfish in ECB mode (no IV required)
- `bf-cbc` - Blowfish in CBC mode (8-byte IV)
- `bf-cfb` - Blowfish in CFB mode (8-byte IV)
- `bf-ofb` - Blowfish in OFB mode (8-byte IV)

### CAST5
- `cast5-ecb` - CAST5 in ECB mode (no IV required)
- `cast5-cbc` - CAST5 in CBC mode (8-byte IV)
- `cast5-cfb` - CAST5 in CFB mode (8-byte IV)
- `cast5-ofb` - CAST5 in OFB mode (8-byte IV)

### RC4 (Stream Ciphers)
- `rc4` - RC4 stream cipher (no IV required)
- `rc4-40` - RC4 with 40-bit key (no IV required)

## Security Notes

⚠️ **WARNING: Legacy algorithms are considered cryptographically weak and should not be used for new applications.**

### Security Issues with Legacy Algorithms

- **DES**: Considered cryptographically broken due to its small key size (56 bits)
- **Blowfish**: While not broken, it has a small block size (64 bits) making it vulnerable to birthday attacks
- **CAST5**: Similar issues to Blowfish with small block size
- **RC4**: Known vulnerabilities and should not be used
- **ECB Mode**: Deterministic encryption that reveals patterns in plaintext

### When to Use Legacy Algorithms

Legacy algorithms should only be used for:
- Interoperability with legacy systems
- Decrypting old data that was encrypted with these algorithms
- Testing and educational purposes
- Compliance with specific legacy requirements

### Decryption Security

- **Key Management**: Ensure the same key used for encryption is used for decryption
- **IV Management**: Ensure the same IV used for encryption is used for decryption
- **Ciphertext Integrity**: Verify that ciphertext has not been corrupted or tampered with
- **Padding Oracle Attacks**: Be aware that some legacy algorithms may be vulnerable to padding oracle attacks

### Recommendations

- Use modern algorithms like AES-256-GCM, ChaCha20-Poly1305, or AES-256-CBC for new applications
- Migrate away from legacy algorithms as soon as possible
- Always use strong, randomly generated keys and IVs
- Implement proper key management and rotation
- Consider using the `tossl::decrypt` command for modern algorithm decryption
- Validate ciphertext integrity before decryption

### Key and IV Requirements

- **Key length**: Must match the algorithm's required key length
- **IV length**: Must match the algorithm's required IV length (0 for stream ciphers and ECB mode)
- **Key/IV pairing**: Must use the same key/IV combination that was used for encryption
- **Ciphertext format**: Must be in the correct format for the algorithm

## Notes

- The command requires the OpenSSL legacy provider to be loaded
- Algorithm availability depends on the OpenSSL build configuration
- Some legacy algorithms may be disabled in hardened OpenSSL builds
- The command uses OpenSSL's EVP interface for decryption
- Plaintext is returned as a byte array
- Use `tossl::legacy::info <algorithm>` to determine key and IV requirements
- Use `tossl::legacy::keygen <algorithm>` and `tossl::legacy::ivgen <algorithm>` to generate appropriate keys and IVs
- The command is designed to work with ciphertext produced by `tossl::legacy::encrypt` 