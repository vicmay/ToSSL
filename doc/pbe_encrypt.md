# ::tossl::pbe::encrypt

## Overview

The `::tossl::pbe::encrypt` command implements Password-Based Encryption (PBE) for encrypting data using a password and salt. This command is essential for secure data storage, password-protected files, and applications requiring simple password-based encryption without complex key management. PBE uses a password and salt to derive encryption keys using OpenSSL's EVP_BytesToKey function, then encrypts data using AES-256-CBC.

## Syntax

```tcl
::tossl::pbe::encrypt algorithm password salt data
```

## Parameters

- **algorithm** (required): The hash algorithm to use for key derivation. Supported algorithms include:
  - `sha256` - SHA-256 (recommended)
  - `sha512` - SHA-512 (higher security)
  - `sha1` - SHA-1 (legacy, not recommended)
  - `md5` - MD5 (legacy, not recommended)

- **password** (required): The password string to derive the encryption key from

- **salt** (required): The salt value used to prevent rainbow table attacks. Should be random and unique for each encryption operation

- **data** (required): The data to encrypt (string or binary data)

## Return Value

Returns a byte array containing the encrypted data (ciphertext).

## Examples

### Basic PBE Encryption

```tcl
# Generate a random salt
set salt [tossl::pbe::saltgen 16]

# Encrypt data with password
set password "my_secure_password"
set data "Hello, World! This is secret data."
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]

puts "Encrypted data length: [string length $encrypted] bytes"
```

### Different Hash Algorithms

```tcl
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set data "Test data for different algorithms"

# SHA-256 (recommended)
set encrypted_sha256 [tossl::pbe::encrypt sha256 $password $salt $data]

# SHA-512 (higher security)
set encrypted_sha512 [tossl::pbe::encrypt sha512 $password $salt $data]

# SHA-1 (legacy)
set encrypted_sha1 [tossl::pbe::encrypt sha1 $password $salt $data]

# MD5 (legacy)
set encrypted_md5 [tossl::pbe::encrypt md5 $password $salt $data]

puts "SHA-256: [string length $encrypted_sha256] bytes"
puts "SHA-512: [string length $encrypted_sha512] bytes"
puts "SHA-1: [string length $encrypted_sha1] bytes"
puts "MD5: [string length $encrypted_md5] bytes"
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
}
```

### File Encryption Example

```tcl
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

### Binary Data Encryption

```tcl
# Encrypt binary data
set password "binary_password"
set salt [tossl::pbe::saltgen 16]

# Create binary data
set binary_data [binary format H* "48656c6c6f20576f726c64"] ;# "Hello World" in hex

# Encrypt binary data
set encrypted [tossl::pbe::encrypt sha256 $password $salt $binary_data]

puts "Binary data length: [string length $binary_data] bytes"
puts "Encrypted length: [string length $encrypted] bytes"
puts "Encrypted hex: [binary encode hex $encrypted]"
```

### Unicode Data Encryption

```tcl
# Encrypt unicode data
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

### Deterministic Encryption

```tcl
# Same parameters always produce the same encrypted result
set password "test_password"
set salt "fixed_salt_value"
set data "Test data for deterministic encryption"

# Encrypt twice with same parameters
set encrypted1 [tossl::pbe::encrypt sha256 $password $salt $data]
set encrypted2 [tossl::pbe::encrypt sha256 $password $salt $data]

if {$encrypted1 eq $encrypted2} {
    puts "Deterministic encryption: OK"
} else {
    puts "ERROR: Non-deterministic encryption"
}
```

### Parameter Variation Test

```tcl
# Test that different parameters produce different results
set data "Test data for parameter variation"

# Different passwords
set encrypted1 [tossl::pbe::encrypt sha256 "password1" "salt" $data]
set encrypted2 [tossl::pbe::encrypt sha256 "password2" "salt" $data]

if {$encrypted1 ne $encrypted2} {
    puts "Different passwords: OK"
} else {
    puts "ERROR: Same result with different passwords"
}

# Different salts
set encrypted1 [tossl::pbe::encrypt sha256 "password" "salt1" $data]
set encrypted2 [tossl::pbe::encrypt sha256 "password" "salt2" $data]

if {$encrypted1 ne $encrypted2} {
    puts "Different salts: OK"
} else {
    puts "ERROR: Same result with different salts"
}

# Different algorithms
set encrypted1 [tossl::pbe::encrypt sha256 "password" "salt" $data]
set encrypted2 [tossl::pbe::encrypt sha512 "password" "salt" $data]

if {$encrypted1 ne $encrypted2} {
    puts "Different algorithms: OK"
} else {
    puts "ERROR: Same result with different algorithms"
}
```

## Error Handling

- **Missing arguments**: Returns an error if any required parameter is not provided
- **Invalid algorithm**: Returns an error if the hash algorithm is not supported
- **Empty parameters**: Returns an error if password, salt, or data is empty
- **Memory allocation failure**: Returns an error if memory allocation fails
- **OpenSSL errors**: Returns an error if OpenSSL operations fail

### Error Examples

```tcl
# Missing arguments
tossl::pbe::encrypt sha256 password salt
# Error: wrong # args: should be "tossl::pbe::encrypt algorithm password salt data"

# Invalid algorithm
tossl::pbe::encrypt invalid-algorithm password salt data
# Error: Unsupported digest algorithm

# Empty password
tossl::pbe::encrypt sha256 "" salt data
# Error: Password cannot be empty

# Empty salt
tossl::pbe::encrypt sha256 password "" data
# Error: Salt cannot be empty

# Empty data
tossl::pbe::encrypt sha256 password salt ""
# Error: Data cannot be empty
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

- **Random**: Use `::tossl::pbe::saltgen` to generate random salts
- **Unique**: Each encryption operation should have a unique salt
- **Length**: Minimum 8 bytes, 16 bytes recommended
- **Storage**: Store salt alongside the encrypted data

### Key Derivation

- **Method**: Uses OpenSSL's EVP_BytesToKey with 1 iteration
- **Cipher**: Always uses AES-256-CBC for encryption
- **Security**: The algorithm parameter affects key derivation, not the cipher

### Example: Secure Implementation

```tcl
proc secure_pbe_encrypt {password data} {
    # Generate a large random salt
    set salt [tossl::pbe::saltgen 16]
    
    # Use SHA-512 for maximum security
    set encrypted [tossl::pbe::encrypt sha512 $password $salt $data]
    
    # Return both encrypted data and salt (salt must be stored with the data)
    return [list $encrypted $salt]
}

proc secure_pbe_decrypt {password encrypted_data salt} {
    # Use SHA-512 for decryption
    return [tossl::pbe::decrypt sha512 $password $salt $encrypted_data]
}

# Usage
set result [secure_pbe_encrypt "my_secure_password" "sensitive data"]
set encrypted_data [lindex $result 0]
set salt [lindex $result 1]

puts "Encrypted length: [string length $encrypted_data] bytes"
puts "Salt length: [string length $salt] bytes"

# Decrypt
set decrypted [secure_pbe_decrypt "my_secure_password" $encrypted_data $salt]
puts "Decrypted: $decrypted"
```

## Performance Considerations

### Algorithm Performance

- **SHA-256**: Fast, good balance of security and performance
- **SHA-512**: Slightly slower but higher security
- **SHA-1**: Fastest but less secure
- **MD5**: Fastest but least secure

### Data Size Impact

```tcl
# Performance test with different data sizes
set password "test_password"
set salt [tossl::pbe::saltgen 16]

foreach size {100 1000 10000 100000} {
    set data [string repeat "A" $size]
    
    set start_time [clock milliseconds]
    set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "$size bytes: ${duration}ms"
}
```

### Batch Operations

```tcl
# Batch encryption for multiple data items
proc batch_encrypt {password data_list} {
    set salt [tossl::pbe::saltgen 16]
    set results {}
    
    foreach data $data_list {
        set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
        lappend results $encrypted
    }
    
    return [list $results $salt]
}

# Usage
set data_list {
    "First secret message"
    "Second secret message"
    "Third secret message"
}

set result [batch_encrypt "batch_password" $data_list]
set encrypted_list [lindex $result 0]
set salt [lindex $result 1]

puts "Batch encrypted [llength $encrypted_list] items"
```

## Best Practices

### 1. Use Strong Parameters

```tcl
# Good: Strong parameters
set encrypted [tossl::pbe::encrypt sha256 $strong_password $random_salt $data]

# Avoid: Weak parameters
set encrypted [tossl::pbe::encrypt md5 $weak_password $fixed_salt $data]
```

### 2. Generate Random Salts

```tcl
# Good: Use saltgen for random salts
set salt [tossl::pbe::saltgen 16]

# Avoid: Fixed or predictable salts
set salt "fixed_salt"
```

### 3. Store Salt with Encrypted Data

```tcl
# Store both encrypted data and salt together
set encrypted_data [tossl::pbe::encrypt sha256 $password $salt $data]
set storage_data [list $encrypted_data $salt]
# Save $storage_data to storage
```

### 4. Validate Inputs

```tcl
proc safe_pbe_encrypt {algorithm password salt data} {
    # Validate inputs
    if {[string length $password] == 0} {
        error "Password cannot be empty"
    }
    if {[string length $salt] == 0} {
        error "Salt cannot be empty"
    }
    if {[string length $data] == 0} {
        error "Data cannot be empty"
    }
    
    return [tossl::pbe::encrypt $algorithm $password $salt $data]
}
```

### 5. Handle Binary Data Properly

```tcl
# For binary data, ensure proper handling
set binary_data [binary format H* "48656c6c6f20576f726c64"]
set encrypted [tossl::pbe::encrypt sha256 $password $salt $binary_data]

# Store as binary
set f [open "encrypted.bin" wb]
puts -nonewline $f $encrypted
close $f
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

4. **"Data cannot be empty"**
   - **Cause**: Empty data string
   - **Solution**: Provide non-empty data to encrypt

5. **"Failed to derive key from password"**
   - **Cause**: OpenSSL key derivation failed
   - **Solution**: Check password and salt validity

### Debugging Example

```tcl
proc debug_pbe_encrypt {algorithm password salt data} {
    puts "Debugging PBE encryption:"
    puts "  Algorithm: $algorithm"
    puts "  Password length: [string length $password]"
    puts "  Salt length: [string length $salt]"
    puts "  Data length: [string length $data]"
    
    set rc [catch {tossl::pbe::encrypt $algorithm $password $salt $data} result]
    if {$rc == 0} {
        puts "  Success: [string length $result] bytes encrypted"
        return $result
    } else {
        puts "  Error: $result"
        return ""
    }
}
```

## Related Commands

- `::tossl::pbe::decrypt` - Decrypt data using password-based encryption
- `::tossl::pbe::saltgen` - Generate random salts for PBE operations
- `::tossl::pbe::keyderive` - Derive keys using PBKDF2
- `::tossl::pbe::algorithms` - List supported hash algorithms
- `::tossl::encrypt` - General symmetric encryption
- `::tossl::decrypt` - General symmetric decryption
- `::tossl::pbkdf2` - Alternative key derivation function
- `::tossl::scrypt` - Alternative key derivation function
- `::tossl::argon2` - Alternative key derivation function

## Implementation Notes

- **OpenSSL API**: Uses `EVP_BytesToKey()` for key derivation and `EVP_EncryptInit_ex()` for encryption
- **Cipher**: Always uses AES-256-CBC regardless of algorithm parameter
- **Algorithm Parameter**: Only affects key derivation, not the encryption cipher
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

## Recent Fixes

**✅ Fixed in Latest Version**: The corresponding `::tossl::pbe::decrypt` command has been fixed to properly handle binary data and Unicode strings. Round-trip encryption/decryption now works correctly for all data types. 