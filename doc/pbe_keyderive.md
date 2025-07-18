# ::tossl::pbe::keyderive

## Overview

The `::tossl::pbe::keyderive` command implements Password-Based Key Derivation Function 2 (PBKDF2) for deriving cryptographic keys from passwords. This command is essential for secure password-based encryption, key storage, and authentication systems. PBKDF2 is a standardized key derivation function that uses a password, salt, iteration count, and hash algorithm to produce a cryptographically strong key.

## Syntax

```tcl
::tossl::pbe::keyderive algorithm password salt iterations key_length
```

## Parameters

- **algorithm** (required): The hash algorithm to use for key derivation. Supported algorithms include:
  - `sha256` - SHA-256 (recommended)
  - `sha512` - SHA-512 (higher security)
  - `sha1` - SHA-1 (legacy, not recommended)
  - `md5` - MD5 (legacy, not recommended)

- **password** (required): The password string to derive the key from

- **salt** (required): The salt value used to prevent rainbow table attacks. Should be random and unique for each password

- **iterations** (required): The number of iterations to perform. Higher values increase security but slow down the process. Recommended minimum is 1000, with 10000+ for high-security applications

- **key_length** (required): The length of the derived key in bytes. Must be positive

## Return Value

Returns a byte array containing the derived key of the specified length.

## Examples

### Basic Key Derivation

```tcl
# Generate a random salt
set salt [tossl::pbe::saltgen 16]

# Derive a 32-byte key using SHA-256
set key [tossl::pbe::keyderive sha256 "my_password" $salt 1000 32]
puts "Derived key length: [string length $key] bytes"
```

### Different Hash Algorithms

```tcl
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set iterations 1000
set key_length 32

# SHA-256 (recommended)
set key_sha256 [tossl::pbe::keyderive sha256 $password $salt $iterations $key_length]

# SHA-512 (higher security)
set key_sha512 [tossl::pbe::keyderive sha512 $password $salt $iterations $key_length]

# SHA-1 (legacy)
set key_sha1 [tossl::pbe::keyderive sha1 $password $salt $iterations $key_length]
```

### Different Key Lengths

```tcl
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set iterations 1000

# Different key lengths for different purposes
set key_16 [tossl::pbe::keyderive sha256 $password $salt $iterations 16]  ;# 128-bit key
set key_32 [tossl::pbe::keyderive sha256 $password $salt $iterations 32]  ;# 256-bit key
set key_64 [tossl::pbe::keyderive sha256 $password $salt $iterations 64]  ;# 512-bit key

puts "16-byte key: [string length $key_16] bytes"
puts "32-byte key: [string length $key_32] bytes"
puts "64-byte key: [string length $key_64] bytes"
```

### High-Security Configuration

```tcl
# High-security settings for sensitive applications
set password "very_secure_password"
set salt [tossl::pbe::saltgen 32]  ;# Larger salt
set iterations 100000              ;# High iteration count
set key_length 64                  ;# Longer key

set key [tossl::pbe::keyderive sha512 $password $salt $iterations $key_length]
puts "High-security key derived: [string length $key] bytes"
```

### Deterministic Key Derivation

```tcl
# Same parameters always produce the same key
set password "test_password"
set salt "fixed_salt_value"
set iterations 1000
set key_length 32

set key1 [tossl::pbe::keyderive sha256 $password $salt $iterations $key_length]
set key2 [tossl::pbe::keyderive sha256 $password $salt $iterations $key_length]

if {$key1 eq $key2} {
    puts "Deterministic key derivation: OK"
} else {
    puts "ERROR: Keys differ"
}
```

## Error Handling

- **Missing arguments**: Returns an error if any required parameter is not provided
- **Empty parameters**: Returns an error if algorithm, password, or salt is empty
- **Invalid algorithm**: Returns an error if the hash algorithm is not supported
- **Invalid iterations**: Returns an error if iterations is not positive
- **Invalid key length**: Returns an error if key_length is not positive

### Error Examples

```tcl
# Missing arguments
tossl::pbe::keyderive sha256 password salt 1000
# Error: wrong # args: should be "tossl::pbe::keyderive algorithm password salt iterations key_length"

# Empty password
tossl::pbe::keyderive sha256 "" salt 1000 32
# Error: Password cannot be empty

# Empty salt
tossl::pbe::keyderive sha256 password "" 1000 32
# Error: Salt cannot be empty

# Invalid algorithm
tossl::pbe::keyderive invalid-algorithm password salt 1000 32
# Error: Unsupported digest algorithm

# Invalid iterations
tossl::pbe::keyderive sha256 password salt 0 32
# Error: Invalid iterations or key length

# Invalid key length
tossl::pbe::keyderive sha256 password salt 1000 0
# Error: Invalid iterations or key length
```

## Security Considerations

### Algorithm Selection

- **SHA-256**: Recommended for most applications
- **SHA-512**: Use for higher security requirements
- **SHA-1**: Avoid for new applications (legacy support only)
- **MD5**: Avoid for new applications (legacy support only)

### Salt Requirements

- **Random**: Use `::tossl::pbe::saltgen` to generate random salts
- **Unique**: Each password should have a unique salt
- **Length**: Minimum 16 bytes, 32 bytes recommended for high security
- **Storage**: Store salt alongside the derived key

### Iteration Count

- **Minimum**: 1000 iterations for basic security
- **Recommended**: 10000+ iterations for sensitive data
- **High security**: 100000+ iterations for critical applications
- **Balance**: Higher iterations increase security but slow down key derivation

### Password Security

- **Strength**: Use strong, complex passwords
- **Length**: Longer passwords are more secure
- **Uniqueness**: Use different passwords for different applications
- **Storage**: Never store passwords in plain text

### Example: Secure Implementation

```tcl
proc derive_secure_key {password} {
    # Generate a large random salt
    set salt [tossl::pbe::saltgen 32]
    
    # Use high iteration count for security
    set iterations 100000
    
    # Use SHA-512 for maximum security
    set key_length 64
    
    # Derive the key
    set key [tossl::pbe::keyderive sha512 $password $salt $iterations $key_length]
    
    # Return both key and salt (salt must be stored with the key)
    return [list $key $salt]
}

# Usage
set result [derive_secure_key "my_secure_password"]
set key [lindex $result 0]
set salt [lindex $result 1]

puts "Key length: [string length $key] bytes"
puts "Salt length: [string length $salt] bytes"
```

## Performance Considerations

### Iteration Count Impact

```tcl
# Performance test with different iteration counts
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set key_length 32

foreach iterations {100 1000 10000 100000} {
    set start_time [clock milliseconds]
    set key [tossl::pbe::keyderive sha256 $password $salt $iterations $key_length]
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "$iterations iterations: ${duration}ms"
}
```

### Algorithm Performance

- **SHA-256**: Fast, good balance of security and performance
- **SHA-512**: Slightly slower but higher security
- **SHA-1**: Fastest but less secure
- **MD5**: Fastest but least secure

## Best Practices

### 1. Use Strong Parameters

```tcl
# Good: Strong parameters
set key [tossl::pbe::keyderive sha256 $password $salt 10000 32]

# Avoid: Weak parameters
set key [tossl::pbe::keyderive md5 $password $salt 100 16]
```

### 2. Generate Random Salts

```tcl
# Good: Use saltgen for random salts
set salt [tossl::pbe::saltgen 16]

# Avoid: Fixed or predictable salts
set salt "fixed_salt"
```

### 3. Store Salt with Key

```tcl
# Store both key and salt together
set key_data [list $key $salt]
# Save $key_data to storage
```

### 4. Validate Inputs

```tcl
proc safe_key_derive {password salt iterations key_length} {
    # Validate inputs
    if {[string length $password] == 0} {
        error "Password cannot be empty"
    }
    if {[string length $salt] == 0} {
        error "Salt cannot be empty"
    }
    if {$iterations < 1000} {
        error "Iterations must be at least 1000"
    }
    if {$key_length < 16} {
        error "Key length must be at least 16 bytes"
    }
    
    return [tossl::pbe::keyderive sha256 $password $salt $iterations $key_length]
}
```

## Troubleshooting

### Common Issues

1. **"Unsupported digest algorithm"**
   - **Cause**: Algorithm name is incorrect or not supported
   - **Solution**: Use one of: sha256, sha512, sha1, md5

2. **"Password cannot be empty"**
   - **Cause**: Empty password string
   - **Solution**: Provide a non-empty password

3. **"Salt cannot be empty"**
   - **Cause**: Empty salt string
   - **Solution**: Use `::tossl::pbe::saltgen` to generate a salt

4. **"Invalid iterations or key length"**
   - **Cause**: Non-positive values for iterations or key_length
   - **Solution**: Use positive integers

### Debugging Example

```tcl
proc debug_key_derive {algorithm password salt iterations key_length} {
    puts "Debugging key derivation:"
    puts "  Algorithm: $algorithm"
    puts "  Password length: [string length $password]"
    puts "  Salt length: [string length $salt]"
    puts "  Iterations: $iterations"
    puts "  Key length: $key_length"
    
    set rc [catch {tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length} result]
    if {$rc == 0} {
        puts "  Success: [string length $result] bytes derived"
        return $result
    } else {
        puts "  Error: $result"
        return ""
    }
}
```

## Related Commands

- `::tossl::pbe::saltgen` - Generate random salts for key derivation
- `::tossl::pbe::algorithms` - List supported hash algorithms
- `::tossl::pbe::encrypt` - Encrypt data using password-based encryption
- `::tossl::pbe::decrypt` - Decrypt data using password-based encryption
- `::tossl::pbkdf2` - Alternative PBKDF2 implementation
- `::tossl::scrypt` - Alternative key derivation function
- `::tossl::argon2` - Alternative key derivation function

## Implementation Notes

- **OpenSSL API**: Uses `PKCS5_PBKDF2_HMAC()` from OpenSSL
- **Algorithm Support**: Depends on OpenSSL build configuration
- **Memory Safety**: Properly allocates and frees memory
- **Input Validation**: Validates all parameters before processing
- **Error Handling**: Returns descriptive error messages

## Version Compatibility

- **OpenSSL 3.0+**: Full support for all algorithms
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers 