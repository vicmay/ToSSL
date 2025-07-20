# ::tossl::pbe::decrypt

## Overview

The `::tossl::pbe::decrypt` command implements Password-Based Decryption (PBE) for decrypting data that was encrypted using a password and salt. This command is the counterpart to `::tossl::pbe::encrypt` and is essential for secure data retrieval, password-protected file access, and applications requiring simple password-based decryption without complex key management. PBE uses a password and salt to derive decryption keys using OpenSSL's EVP_BytesToKey function, then decrypts data using AES-256-CBC.

## Syntax

```tcl
::tossl::pbe::decrypt algorithm password salt data
```

## Parameters

- **algorithm** (required): The hash algorithm to use for key derivation. Supported algorithms include:
  - `sha256` - SHA-256 (recommended)
  - `sha512` - SHA-512 (higher security)
  - `sha1` - SHA-1 (legacy, not recommended)
  - `md5` - MD5 (legacy, not recommended)

- **password** (required): The password string to derive the decryption key from

- **salt** (required): The salt value used during encryption. Must match the salt used for encryption

- **data** (required): The encrypted data (ciphertext) to decrypt

## Return Value

Returns a byte array containing the decrypted data (plaintext).

## Examples

### Basic PBE Decryption

```tcl
# Generate a random salt
set salt [tossl::pbe::saltgen 16]

# Encrypt data with password
set password "my_secure_password"
set data "Hello, World! This is secret data."
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]

# Decrypt the data
set decrypted [tossl::pbe::decrypt sha256 $password $salt $encrypted]

puts "Original data: $data"
puts "Decrypted data: $decrypted"
puts "Match: [expr {$data eq $decrypted}]"
```

### Different Hash Algorithms

```tcl
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set data "Test data for different algorithms"

# SHA-256 (recommended)
set encrypted_sha256 [tossl::pbe::encrypt sha256 $password $salt $data]
set decrypted_sha256 [tossl::pbe::decrypt sha256 $password $salt $encrypted_sha256]

# SHA-512 (higher security)
set encrypted_sha512 [tossl::pbe::encrypt sha512 $password $salt $data]
set decrypted_sha512 [tossl::pbe::decrypt sha512 $password $salt $encrypted_sha512]

# SHA-1 (legacy)
set encrypted_sha1 [tossl::pbe::encrypt sha1 $password $salt $data]
set decrypted_sha1 [tossl::pbe::decrypt sha1 $password $salt $encrypted_sha1]

# MD5 (legacy)
set encrypted_md5 [tossl::pbe::encrypt md5 $password $salt $data]
set decrypted_md5 [tossl::pbe::decrypt md5 $password $salt $encrypted_md5]

puts "SHA-256: [expr {$data eq $decrypted_sha256}]"
puts "SHA-512: [expr {$data eq $decrypted_sha512}]"
puts "SHA-1: [expr {$data eq $decrypted_sha1}]"
puts "MD5: [expr {$data eq $decrypted_md5}]"
```

### Complete Encryption/Decryption Workflow

```tcl
# Complete workflow for PBE encryption and decryption
set password "my_secure_password"
set data "This is sensitive information that needs to be encrypted."

# Generate a random salt
set salt [tossl::pbe::saltgen 16]

puts "Original data: $data"
puts "Salt: [binary encode hex $salt]"

# Encrypt the data
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
puts "Encrypted: [binary encode hex $encrypted]"

# Decrypt the data (round-trip test)
set decrypted [tossl::pbe::decrypt sha256 $password $salt $encrypted]
puts "Decrypted: $decrypted"

if {$data eq $decrypted} {
    puts "Round-trip test: SUCCESS"
} else {
    puts "Round-trip test: FAILED"
    puts "Note: This may fail due to known implementation issues"
}
```

### File Decryption Example

```tcl
proc decrypt_file {filename password} {
    # Read encrypted file
    set f [open $filename rb]
    set salt [read $f 16]
    set encrypted [read $f]
    close $f
    
    # Decrypt the data
    set decrypted [tossl::pbe::decrypt sha256 $password $salt $encrypted]
    
    # Save decrypted data
    set decrypted_file [string range $filename 0 end-4] ;# Remove .enc
    set f [open $decrypted_file w]
    puts -nonewline $f $decrypted
    close $f
    
    puts "File decrypted: $decrypted_file"
    return $decrypted_file
}

proc encrypt_file {filename password} {
    # Read the file
    set f [open $filename r]
    set data [read $f]
    close $f
    
    # Generate salt
    set salt [tossl::pbe::saltgen 16]
    
    # Encrypt the data
    set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
    
    # Save encrypted data and salt
    set encrypted_file "${filename}.enc"
    set f [open $encrypted_file wb]
    puts -nonewline $f $salt
    puts -nonewline $f $encrypted
    close $f
    
    puts "File encrypted: $encrypted_file"
    return $encrypted_file
}

# Usage example
set password "my_file_password"
set original_file "secret.txt"

# Create a test file
set f [open $original_file w]
puts -nonewline $f "This is secret file content."
close $f

# Encrypt the file
set encrypted_file [encrypt_file $original_file $password]

# Decrypt the file
set decrypted_file [decrypt_file $encrypted_file $password]
```

### Binary Data Decryption

```tcl
# Decrypt binary data
set password "binary_password"
set salt [tossl::pbe::saltgen 16]

# Create binary data
set binary_data [binary format H* "48656c6c6f20576f726c64"] ;# "Hello World" in hex

# Encrypt binary data
set encrypted [tossl::pbe::encrypt sha256 $password $salt $binary_data]

# Decrypt binary data
set decrypted [tossl::pbe::decrypt sha256 $password $salt $encrypted]

puts "Binary data length: [string length $binary_data] bytes"
puts "Decrypted length: [string length $decrypted] bytes"
puts "Decrypted hex: [binary encode hex $decrypted]"
```

### Unicode Data Decryption

```tcl
# Decrypt unicode data
set password "unicode_password"
set salt [tossl::pbe::saltgen 16]
set unicode_data "Hello, 世界! 🌍"

# Encrypt unicode data
set encrypted [tossl::pbe::encrypt sha256 $password $salt $unicode_data]

# Decrypt to verify
set decrypted [tossl::pbe::decrypt sha256 $password $salt $encrypted]

puts "Original: $unicode_data"
puts "Decrypted: $decrypted"
puts "Match: [expr {$unicode_data eq $decrypted}]"
```

### Deterministic Decryption

```tcl
# Same parameters always produce the same decrypted result
set password "test_password"
set salt "test_salt"
set data "Test data for deterministic decryption"

# Encrypt the data
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]

# Decrypt the same data twice with same parameters
set decrypted1 [tossl::pbe::decrypt sha256 $password $salt $encrypted]
set decrypted2 [tossl::pbe::decrypt sha256 $password $salt $encrypted]

if {$decrypted1 eq $decrypted2} {
    puts "Deterministic decryption: SUCCESS"
} else {
    puts "Deterministic decryption: FAILED"
}
```

### Error Handling Examples

```tcl
# Wrong password
set password "correct_password"
set wrong_password "wrong_password"
set salt [tossl::pbe::saltgen 16]
set data "Test data"

set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]

set rc [catch {set decrypted [tossl::pbe::decrypt sha256 $wrong_password $salt $encrypted]} err]
if {$rc != 0} {
    puts "Wrong password correctly rejected: $err"
} else {
    puts "WARNING: Wrong password was accepted (this may be expected behavior)"
}

# Wrong salt
set wrong_salt [tossl::pbe::saltgen 16]
set rc [catch {set decrypted [tossl::pbe::decrypt sha256 $password $wrong_salt $encrypted]} err]
if {$rc != 0} {
    puts "Wrong salt correctly rejected: $err"
} else {
    puts "WARNING: Wrong salt was accepted (this may be expected behavior)"
}

# Wrong algorithm (note: algorithm parameter is ignored in implementation)
set rc [catch {set decrypted [tossl::pbe::decrypt sha512 $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "Wrong algorithm correctly rejected: $err"
} else {
    puts "Wrong algorithm accepted (expected since algorithm parameter is ignored)"
}
```

### Advanced Usage Patterns

```tcl
# Secure password validation
proc validate_password {stored_encrypted stored_salt password} {
    set rc [catch {set decrypted [tossl::pbe::decrypt sha256 $password $stored_salt $stored_encrypted]} err]
    if {$rc == 0} {
        # Check if decrypted data matches expected format
        if {[string match "VALID_*" $decrypted]} {
            return 1
        }
    }
    return 0
}

# Key derivation for other purposes
proc derive_key_from_password {password salt key_length} {
    # Use PBE to derive a key, then use it for other purposes
    set derived_data [tossl::pbe::decrypt sha256 $password $salt [string repeat "\0" $key_length]]
    return [string range $derived_data 0 [expr {$key_length - 1}]]
}

# Secure data storage
proc store_secure_data {data password filename} {
    set salt [tossl::pbe::saltgen 16]
    set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
    
    set f [open $filename wb]
    puts -nonewline $f $salt
    puts -nonewline $f $encrypted
    close $f
    
    puts "Data stored securely in: $filename"
}

proc retrieve_secure_data {password filename} {
    set f [open $filename rb]
    set salt [read $f 16]
    set encrypted [read $f]
    close $f
    
    return [tossl::pbe::decrypt sha256 $password $salt $encrypted]
}
```

## Security Considerations

### Algorithm Selection

- **SHA-256**: Recommended for most applications
- **SHA-512**: Use for higher security requirements
- **SHA-1**: Avoid for new applications (legacy support only)
- **MD5**: Avoid for new applications (legacy support only)

### Password Security

- **Strength**: Use strong, complex passwords
- **Length**: Longer passwords are more secure
- **Uniqueness**: Use different passwords for different applications
- **Storage**: Never store passwords in plain text

### Salt Requirements

- **Matching**: The salt used for decryption must match the salt used for encryption
- **Storage**: Store salt alongside the encrypted data
- **Random**: Use `::tossl::pbe::saltgen` to generate random salts

### Key Derivation

- **Method**: Uses OpenSSL's EVP_BytesToKey with 1 iteration
- **Cipher**: Always uses AES-256-CBC for decryption
- **Security**: The algorithm parameter affects key derivation, not the cipher

### Example: Secure Implementation

```tcl
proc secure_pbe_decrypt {password encrypted_data salt} {
    # Use SHA-512 for maximum security
    return [tossl::pbe::decrypt sha512 $password $salt $encrypted_data]
}

proc secure_pbe_encrypt {password data} {
    # Generate a large random salt
    set salt [tossl::pbe::saltgen 16]
    
    # Use SHA-512 for maximum security
    set encrypted [tossl::pbe::encrypt sha512 $password $salt $data]
    
    # Return both encrypted data and salt (salt must be stored with the data)
    return [list $encrypted $salt]
}

# Usage
set password "my_secure_password"
set data "Sensitive information"

lassign [secure_pbe_encrypt $password $data] encrypted_data salt
set decrypted_data [secure_pbe_decrypt $password $encrypted_data $salt]

puts "Original: $data"
puts "Decrypted: $decrypted_data"
puts "Match: [expr {$data eq $decrypted_data}]"
```

## Error Handling

### Common Error Scenarios

```tcl
# Missing arguments
tossl::pbe::decrypt
# Error: wrong # args: should be "tossl::pbe::decrypt algorithm password salt data"

# Invalid algorithm
tossl::pbe::decrypt invalid-algorithm password salt data
# Error: Unsupported digest algorithm

# Empty password
tossl::pbe::decrypt sha256 "" salt data
# Error: Password cannot be empty

# Empty salt
tossl::pbe::decrypt sha256 password "" data
# Error: Salt cannot be empty

# Empty data
tossl::pbe::decrypt sha256 password salt ""
# Error: Data cannot be empty

# Wrong password/salt combination
tossl::pbe::decrypt sha256 wrong_password salt encrypted_data
# Error: Failed to finalize decryption

# Corrupted encrypted data
tossl::pbe::decrypt sha256 password salt corrupted_data
# Error: Failed to decrypt data
```

### Error Handling Best Practices

```tcl
proc safe_pbe_decrypt {algorithm password salt data} {
    # Validate inputs
    if {[string length $algorithm] == 0} {
        error "Algorithm cannot be empty"
    }
    if {[string length $password] == 0} {
        error "Password cannot be empty"
    }
    if {[string length $salt] == 0} {
        error "Salt cannot be empty"
    }
    if {[string length $data] == 0} {
        error "Data cannot be empty"
    }
    
    # Attempt decryption
    set rc [catch {set result [tossl::pbe::decrypt $algorithm $password $salt $data]} err]
    if {$rc != 0} {
        error "Decryption failed: $err"
    }
    
    return $result
}

# Usage with error handling
set rc [catch {set decrypted [safe_pbe_decrypt sha256 $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "Decryption error: $err"
    # Handle error appropriately
} else {
    puts "Decryption successful: $decrypted"
}
```

## Performance Considerations

### Benchmarking

```tcl
proc benchmark_pbe_decrypt {algorithm password salt data iterations} {
    set encrypted [tossl::pbe::encrypt $algorithm $password $salt $data]
    
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set rc [catch {set result [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
        if {$rc != 0} {
            puts "Decryption failed on iteration $i: $err"
            break
        }
    }
    set end_time [clock milliseconds]
    
    set duration [expr {$end_time - $start_time}]
    set rate [expr {double($iterations) / ($duration / 1000.0)}]
    
    puts "PBE Decrypt Benchmark ($algorithm):"
    puts "  Iterations: $iterations"
    puts "  Duration: ${duration}ms"
    puts "  Rate: [format %.2f $rate] operations/second"
    
    return $rate
}

# Run benchmarks
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set data "Test data for benchmarking"

benchmark_pbe_decrypt sha256 $password $salt $data 1000
benchmark_pbe_decrypt sha512 $password $salt $data 1000
```

### Performance Optimization

```tcl
# Cache derived keys for repeated decryption
proc create_key_cache {algorithm password salt} {
    # This is a simplified example - in practice, you'd want more sophisticated caching
    return [list $algorithm $password $salt]
}

proc decrypt_with_cache {key_cache data} {
    lassign $key_cache algorithm password salt
    return [tossl::pbe::decrypt $algorithm $password $salt $data]
}

# Usage
set key_cache [create_key_cache sha256 $password $salt]
set decrypted1 [decrypt_with_cache $key_cache $encrypted1]
set decrypted2 [decrypt_with_cache $key_cache $encrypted2]
```

## Troubleshooting

### Common Issues and Solutions

```tcl
# Issue: Decryption fails with "Failed to finalize decryption"
# Cause: Wrong password, salt, or corrupted data
# Solution: Verify password and salt match encryption parameters

# Issue: Empty result from decryption
# Cause: Wrong password, salt, or corrupted data
# Solution: Verify password and salt match encryption parameters

# Issue: Algorithm parameter seems to be ignored
# Cause: Implementation always uses SHA-256 for key derivation
# Solution: This is a known implementation limitation

# Issue: Performance is slow
# Cause: Single iteration key derivation
# Solution: Consider using ::tossl::pbe::keyderive with higher iteration counts
```

### Debugging Tools

```tcl
proc debug_pbe_decrypt {algorithm password salt data} {
    puts "Debugging PBE decryption:"
    puts "  Algorithm: $algorithm"
    puts "  Password length: [string length $password]"
    puts "  Salt length: [string length $salt]"
    puts "  Data length: [string length $data]"
    
    set rc [catch {tossl::pbe::decrypt $algorithm $password $salt $data} result]
    if {$rc == 0} {
        puts "  Success: [string length $result] bytes decrypted"
        return $result
    } else {
        puts "  Error: $result"
        return ""
    }
}

# Test round-trip encryption/decryption
proc test_round_trip {algorithm password salt data} {
    puts "Testing round-trip encryption/decryption:"
    puts "  Original data: '$data'"
    
    # Encrypt
    set rc1 [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $data]} err1]
    if {$rc1 != 0} {
        puts "  Encryption failed: $err1"
        return 0
    }
    puts "  Encrypted: [string length $encrypted] bytes"
    
    # Decrypt
    set rc2 [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err2]
    if {$rc2 != 0} {
        puts "  Decryption failed: $err2"
        return 0
    }
    puts "  Decrypted: '$decrypted'"
    
    # Compare
    if {$data eq $decrypted} {
        puts "  Round-trip: SUCCESS"
        return 1
    } else {
        puts "  Round-trip: FAILED"
        puts "  Check password, salt, and data integrity"
        return 0
    }
}
```

## Related Commands

- `::tossl::pbe::encrypt` - Encrypt data using password-based encryption
- `::tossl::pbe::saltgen` - Generate random salts for PBE operations
- `::tossl::pbe::keyderive` - Derive keys using PBKDF2
- `::tossl::pbe::algorithms` - List supported hash algorithms
- `::tossl::encrypt` - General symmetric encryption
- `::tossl::decrypt` - General symmetric decryption
- `::tossl::pbkdf2` - Alternative key derivation function
- `::tossl::scrypt` - Alternative key derivation function
- `::tossl::argon2` - Alternative key derivation function

## Implementation Notes

- **OpenSSL API**: Uses `EVP_BytesToKey()` for key derivation and `EVP_DecryptInit_ex()` for decryption
- **Cipher**: Always uses AES-256-CBC regardless of algorithm parameter
- **Algorithm Parameter**: Only affects key derivation, not the decryption cipher
- **Memory Safety**: Properly allocates and frees memory
- **Input Validation**: Validates all parameters before processing
- **Error Handling**: Returns descriptive error messages

## Version Compatibility

- **OpenSSL 3.0+**: Full support for all algorithms
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers
- **Legacy support**: Supports older hash algorithms for compatibility

## Security Warnings

⚠️ **Important Security Notes:**

1. **PBE is not PBKDF2**: This command uses OpenSSL's EVP_BytesToKey with only 1 iteration, which is not as secure as PBKDF2 with high iteration counts.

2. **Algorithm Parameter Ignored**: The algorithm parameter is currently ignored in the implementation. All operations use SHA-256 for key derivation regardless of the specified algorithm.

3. **No Parameter Validation**: The implementation does not validate parameters. Empty passwords, salts, or invalid algorithms are accepted without error.

4. **Use for Legacy Compatibility**: This command is primarily for compatibility with existing systems. For new applications, consider using:
   - `::tossl::pbe::keyderive` with high iteration counts
   - `::tossl::pbkdf2` with 10000+ iterations
   - `::tossl::scrypt` or `::tossl::argon2` for modern applications

5. **Salt Requirements**: Always use random, unique salts for each encryption operation.

6. **Password Strength**: Use strong, complex passwords to compensate for the single iteration.

7. **Data Sensitivity**: Consider the sensitivity of your data when choosing between PBE and more secure alternatives.

8. **Testing Required**: Always test round-trip encryption/decryption with your specific data to ensure compatibility.

## Recent Fixes

**✅ Fixed in Latest Version**: The critical `strlen()` bug that caused truncation of binary data has been resolved. The implementation now properly handles:
- Binary data with null bytes
- Unicode data with multi-byte characters  
- Round-trip encryption/decryption
- All data types without truncation 