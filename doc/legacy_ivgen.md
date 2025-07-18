# ::tossl::legacy::ivgen

Generate a random initialization vector (IV) for a legacy cipher algorithm.

## Syntax

    tossl::legacy::ivgen <algorithm>

- `<algorithm>`: The legacy cipher algorithm name (e.g., `des-cbc`, `bf-cbc`, `cast5-cbc`)

## Description

Generates a cryptographically secure random initialization vector (IV) of the appropriate length for the specified legacy cipher algorithm. The IV length is determined by the algorithm's block size and mode of operation.

This command is specifically designed for legacy/obsolete cipher algorithms that are not recommended for new applications but may be needed for compatibility with older systems.

## Output

Returns a byte array containing the randomly generated IV. The length of the IV depends on the algorithm:

- **DES variants**: 8 bytes (64 bits)
- **Blowfish variants**: 8 bytes (64 bits)  
- **CAST5 variants**: 8 bytes (64 bits)
- **Stream ciphers**: Error (no IV required)

## Examples

### Basic IV Generation

```tcl
# Generate IV for DES-CBC
set iv [tossl::legacy::ivgen "des-cbc"]
puts "Generated IV: [binary encode hex $iv]"
puts "IV length: [string length $iv] bytes"
```

### IV Generation for Different Algorithms

```tcl
# Generate IVs for different legacy algorithms
set algorithms {
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "cast5-cbc"
}

foreach algorithm $algorithms {
    set rc [catch {tossl::legacy::ivgen $algorithm} iv]
    if {$rc == 0} {
        puts "$algorithm: [binary encode hex $iv] ([string length $iv] bytes)"
    } else {
        puts "$algorithm: $iv"
    }
}
```

### Complete Legacy Encryption Workflow

```tcl
# Complete workflow for legacy encryption
set algorithm "des-cbc"
set plaintext "Secret message"

# Generate key and IV
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

puts "Algorithm: $algorithm"
puts "Key: [binary encode hex $key]"
puts "IV: [binary encode hex $iv]"

# Encrypt the data
set ciphertext [tossl::legacy::encrypt $algorithm $key $iv $plaintext]
puts "Ciphertext: [binary encode hex $ciphertext]"

# Decrypt the data
set decrypted [tossl::legacy::decrypt $algorithm $key $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### IV Validation

```tcl
# Validate that generated IVs have correct length
proc validate_iv {algorithm iv} {
    set info [tossl::legacy::info $algorithm]
    set expected_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key eq "iv_length"} {
            set expected_length $value
            break
        }
    }
    
    set actual_length [string length $iv]
    if {$actual_length == $expected_length} {
        puts "✓ IV length correct: $actual_length bytes"
        return 1
    } else {
        puts "✗ IV length mismatch: expected $expected_length, got $actual_length"
        return 0
    }
}

# Test IV generation and validation
set algorithm "des-cbc"
set rc [catch {tossl::legacy::ivgen $algorithm} iv]
if {$rc == 0} {
    validate_iv $algorithm $iv
} else {
    puts "Failed to generate IV: $iv"
}
```

### Multiple IV Generation

```tcl
# Generate multiple IVs and check uniqueness
set algorithm "bf-cbc"
set ivs {}

for {set i 0} {$i < 5} {incr i} {
    set rc [catch {tossl::legacy::ivgen $algorithm} iv]
    if {$rc == 0} {
        lappend ivs $iv
        puts "IV $i: [binary encode hex $iv]"
    } else {
        puts "Failed to generate IV $i: $iv"
    }
}

# Check for duplicates
set unique_ivs [lsort -unique $ivs]
if {[llength $unique_ivs] == [llength $ivs]} {
    puts "✓ All IVs are unique"
} else {
    puts "✗ Some IVs are duplicates"
}
```

### Error Handling

```tcl
# Handle algorithms that don't require IVs
set stream_ciphers {"rc4" "rc4-40"}

foreach cipher $stream_ciphers {
    set rc [catch {tossl::legacy::ivgen $cipher} result]
    if {$rc != 0} {
        puts "$cipher: $result (expected - no IV required)"
    } else {
        puts "$cipher: Unexpectedly generated IV"
    }
}

# Handle invalid algorithms
set rc [catch {tossl::legacy::ivgen "invalid-algorithm"} result]
if {$rc != 0} {
    puts "Invalid algorithm: $result"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::legacy::ivgen
# Error: wrong # args: should be "tossl::legacy::ivgen algorithm"
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::legacy::ivgen "invalid-algorithm"
# Error: Unsupported legacy cipher algorithm
```

- If the algorithm does not require an IV (e.g., stream ciphers, ECB mode), an error is returned:

```tcl
tossl::legacy::ivgen "rc4"
# Error: This cipher does not require an IV

tossl::legacy::ivgen "des-ecb"
# Error: This cipher does not require an IV
```

- If random number generation fails, an error is returned:

```tcl
tossl::legacy::ivgen "des-cbc"
# Error: Failed to generate random IV
```

## Supported Algorithms

The following legacy algorithms support IV generation (availability may vary by OpenSSL build):

### DES (Data Encryption Standard)
- `des-cbc` - DES in CBC mode (8-byte IV)
- `des-cfb` - DES in CFB mode (8-byte IV)
- `des-ofb` - DES in OFB mode (8-byte IV)
- `des-ede-cbc` - DES-EDE in CBC mode (8-byte IV)
- `des-ede3-cbc` - DES-EDE3 in CBC mode (8-byte IV)

### Blowfish
- `bf-cbc` - Blowfish in CBC mode (8-byte IV)
- `bf-cfb` - Blowfish in CFB mode (8-byte IV)
- `bf-ofb` - Blowfish in OFB mode (8-byte IV)

### CAST5
- `cast5-cbc` - CAST5 in CBC mode (8-byte IV)
- `cast5-cfb` - CAST5 in CFB mode (8-byte IV)
- `cast5-ofb` - CAST5 in OFB mode (8-byte IV)

### Algorithms That Don't Require IVs
- `des-ecb` - DES in ECB mode
- `bf-ecb` - Blowfish in ECB mode
- `cast5-ecb` - CAST5 in ECB mode
- `rc4` - RC4 stream cipher
- `rc4-40` - RC4 with 40-bit key

## Security Notes

⚠️ **WARNING: Legacy algorithms are considered cryptographically weak and should not be used for new applications.**

### IV Requirements

- **Never reuse IVs**: Each encryption operation must use a unique IV
- **Random IVs**: IVs must be cryptographically random, not predictable
- **Proper length**: IVs must match the algorithm's required length
- **Secure generation**: Use cryptographically secure random number generation

### When to Use Legacy Algorithms

Legacy algorithms should only be used for:
- Interoperability with legacy systems
- Decrypting old data that was encrypted with these algorithms
- Testing and educational purposes
- Compliance with specific legacy requirements

### Recommendations

- Use modern algorithms like AES-256-GCM, ChaCha20-Poly1305, or AES-256-CBC for new applications
- Migrate away from legacy algorithms as soon as possible
- Always use strong, randomly generated IVs
- Implement proper key management and rotation
- Consider using the `tossl::rand::iv` command for modern algorithm IV generation

## Notes

- The command requires the OpenSSL legacy provider to be loaded
- Algorithm availability depends on the OpenSSL build configuration
- Some legacy algorithms may be disabled in hardened OpenSSL builds
- The command uses OpenSSL's `RAND_bytes()` function for secure random generation
- IVs are returned as byte arrays for direct use with encryption commands
- Use `tossl::legacy::info <algorithm>` to determine if an algorithm requires an IV 