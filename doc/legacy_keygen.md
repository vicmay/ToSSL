# ::tossl::legacy::keygen

Generate a random key for a legacy cipher algorithm.

## Syntax

    tossl::legacy::keygen <algorithm>

- `<algorithm>`: The legacy cipher algorithm name (e.g., `des-cbc`, `bf-cbc`, `rc4`)

## Description

Generates a cryptographically secure random key of the appropriate length for the specified legacy cipher algorithm. The key length is determined by the algorithm's requirements.

This command is specifically designed for legacy/obsolete cipher algorithms that are not recommended for new applications but may be needed for compatibility with older systems.

## Output

Returns a byte array containing the randomly generated key. The length of the key depends on the algorithm:

- **DES variants**: 8 bytes (64 bits, but only 56 bits are actually used)
- **Blowfish variants**: 16 bytes (128 bits, variable key length up to 448 bits)
- **CAST5 variants**: 16 bytes (128 bits, variable key length up to 128 bits)
- **RC4 variants**: 16 bytes (128 bits) for `rc4`, 5 bytes (40 bits) for `rc4-40`
- **Triple DES**: 16 bytes (128 bits) for `des-ede-cbc`, 24 bytes (192 bits) for `des-ede3-cbc`

## Examples

### Basic Key Generation

```tcl
# Generate key for DES-CBC
set key [tossl::legacy::keygen "des-cbc"]
puts "Generated key: [binary encode hex $key]"
puts "Key length: [string length $key] bytes"
```

### Key Generation for Different Algorithms

```tcl
# Generate keys for different legacy algorithms
set algorithms {
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "cast5-cbc"
    "rc4"
}

foreach algorithm $algorithms {
    set rc [catch {tossl::legacy::keygen $algorithm} key]
    if {$rc == 0} {
        puts "$algorithm: [binary encode hex $key] ([string length $key] bytes)"
    } else {
        puts "$algorithm: $key"
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

# Decrypt (round-trip test)
set decrypted [tossl::legacy::decrypt $algorithm $key $iv $ciphertext]
puts "Decrypted: $decrypted"

if {$decrypted eq $plaintext} {
    puts "✓ Encryption/decryption round-trip successful"
} else {
    puts "✗ Encryption/decryption round-trip failed"
}
```

### Multiple Key Generation

```tcl
# Generate multiple keys to verify randomness
set algorithm "bf-cbc"
set keys {}

for {set i 0} {$i < 5} {incr i} {
    set key [tossl::legacy::keygen $algorithm]
    lappend keys $key
    puts "Key $i: [binary encode hex $key]"
}

# Check that all keys are unique
set unique_keys [lsort -unique $keys]
if {[llength $unique_keys] == [llength $keys]} {
    puts "✓ All generated keys are unique"
} else {
    puts "✗ Some keys are duplicates"
}
```

### Stream Cipher Key Generation

```tcl
# RC4 is a stream cipher with different key length options
set rc4_key [tossl::legacy::keygen "rc4"]
set rc4_40_key [tossl::legacy::keygen "rc4-40"]

puts "RC4 key: [binary encode hex $rc4_key] ([string length $rc4_key] bytes)"
puts "RC4-40 key: [binary encode hex $rc4_40_key] ([string length $rc4_40_key] bytes)"
```

### Triple DES Key Generation

```tcl
# Triple DES variants have different key length requirements
set des_ede_key [tossl::legacy::keygen "des-ede-cbc"]
set des_ede3_key [tossl::legacy::keygen "des-ede3-cbc"]

puts "DES-EDE key: [binary encode hex $des_ede_key] ([string length $des_ede_key] bytes)"
puts "DES-EDE3 key: [binary encode hex $des_ede3_key] ([string length $des_ede3_key] bytes)"
```

### Key Validation

```tcl
# Test that generated keys work with encryption
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]
set test_data "test message"

set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
if {$rc == 0} {
    puts "✓ Generated key works with encryption"
    puts "Ciphertext length: [string length $ciphertext] bytes"
} else {
    puts "✗ Generated key does not work with encryption: $ciphertext"
}
```

### Algorithm Information Integration

```tcl
# Get algorithm info and generate appropriate key
set algorithm "bf-cbc"
set info [tossl::legacy::info $algorithm]

# Extract key length from info
set key_length 0
for {set i 0} {$i < [llength $info]} {incr i 2} {
    set key_name [lindex $info $i]
    set value [lindex $info [expr {$i + 1}]]
    if {$key_name eq "key_length"} {
        set key_length $value
        break
    }
}

puts "Algorithm: $algorithm"
puts "Expected key length: $key_length bytes"

# Generate key and verify length
set key [tossl::legacy::keygen $algorithm]
puts "Generated key length: [string length $key] bytes"

if {[string length $key] == $key_length} {
    puts "✓ Key length matches expected"
} else {
    puts "✗ Key length mismatch"
}
```

### Error Handling

```tcl
# Handle invalid algorithms
set rc [catch {tossl::legacy::keygen "invalid-algorithm"} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle empty algorithm
set rc [catch {tossl::legacy::keygen ""} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle missing arguments
set rc [catch {tossl::legacy::keygen} result]
if {$rc != 0} {
    puts "Error: $result"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::legacy::keygen
# Error: wrong # args: should be "tossl::legacy::keygen algorithm"
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::legacy::keygen "invalid-algorithm"
# Error: Unsupported legacy cipher algorithm
```

- If memory allocation fails, an error is returned:

```tcl
tossl::legacy::keygen "des-cbc"
# Error: Memory allocation failed
```

- If random number generation fails, an error is returned:

```tcl
tossl::legacy::keygen "des-cbc"
# Error: Failed to generate random key
```

## Supported Algorithms

The following legacy algorithms are supported (availability may vary by OpenSSL build):

### DES (Data Encryption Standard)
- `des-ecb` - DES in ECB mode (8-byte key)
- `des-cbc` - DES in CBC mode (8-byte key)
- `des-cfb` - DES in CFB mode (8-byte key)
- `des-ofb` - DES in OFB mode (8-byte key)
- `des-ede-cbc` - DES-EDE in CBC mode (16-byte key)
- `des-ede3-cbc` - DES-EDE3 in CBC mode (24-byte key)

### Blowfish
- `bf-ecb` - Blowfish in ECB mode (16-byte key)
- `bf-cbc` - Blowfish in CBC mode (16-byte key)
- `bf-cfb` - Blowfish in CFB mode (16-byte key)
- `bf-ofb` - Blowfish in OFB mode (16-byte key)

### CAST5
- `cast5-ecb` - CAST5 in ECB mode (16-byte key)
- `cast5-cbc` - CAST5 in CBC mode (16-byte key)
- `cast5-cfb` - CAST5 in CFB mode (16-byte key)
- `cast5-ofb` - CAST5 in OFB mode (16-byte key)

### RC4 (Stream Ciphers)
- `rc4` - RC4 stream cipher (16-byte key)
- `rc4-40` - RC4 with 40-bit key (5-byte key)

## Security Notes

⚠️ **WARNING: Legacy algorithms are considered cryptographically weak and should not be used for new applications.**

### Security Issues with Legacy Algorithms

- **DES**: Considered cryptographically broken due to its small key size (56 bits)
- **Blowfish**: While not broken, it has a small block size (64 bits) making it vulnerable to birthday attacks
- **CAST5**: Similar issues to Blowfish with small block size
- **RC4**: Known vulnerabilities and should not be used

### When to Use Legacy Algorithms

Legacy algorithms should only be used for:
- Interoperability with legacy systems
- Decrypting old data that was encrypted with these algorithms
- Testing and educational purposes
- Compliance with specific legacy requirements

### Key Generation Security

- **Randomness**: Keys are generated using OpenSSL's cryptographically secure random number generator
- **Length**: Key lengths are automatically determined by the algorithm requirements
- **Uniqueness**: Each call generates a new, unique key
- **Entropy**: Keys have full entropy based on the algorithm's key length

### Recommendations

- Use modern algorithms like AES-256-GCM, ChaCha20-Poly1305, or AES-256-CBC for new applications
- Migrate away from legacy algorithms as soon as possible
- Always use strong, randomly generated keys
- Implement proper key management and rotation
- Consider using the `tossl::rand::key` command for modern algorithm key generation

### Key Requirements

- **Key length**: Must match the algorithm's required key length
- **Randomness**: Keys should be cryptographically random
- **Uniqueness**: Never reuse the same key for different encryption operations
- **Secrecy**: Keys must be kept secret and secure

## Notes

- The command requires the OpenSSL legacy provider to be loaded
- Algorithm availability depends on the OpenSSL build configuration
- Some legacy algorithms may be disabled in hardened OpenSSL builds
- The command uses OpenSSL's EVP interface for key generation
- Keys are returned as byte arrays for direct use with encryption commands
- Use `tossl::legacy::info <algorithm>` to determine key length requirements
- Use `tossl::legacy::ivgen <algorithm>` to generate appropriate IVs for block ciphers 