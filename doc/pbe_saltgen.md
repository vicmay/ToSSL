# ::tossl::pbe::saltgen

## Overview

The `::tossl::pbe::saltgen` command generates cryptographically secure random salt values for use with Password-Based Encryption (PBE) operations. This command is essential for secure password-based encryption, key derivation, and authentication systems. A salt is a random value that is combined with a password to prevent rainbow table attacks and ensure that the same password produces different results each time it's used.

## Syntax

```tcl
::tossl::pbe::saltgen length
```

## Parameters

- **length** (required): The length of the salt in bytes. Must be between 1 and 64 bytes inclusive.

## Return Value

Returns a byte array containing the randomly generated salt of the specified length.

## Examples

### Basic Salt Generation

```tcl
# Generate a 16-byte salt
set salt [tossl::pbe::saltgen 16]
puts "Salt length: [string length $salt] bytes"
puts "Salt hex: [binary encode hex $salt]"
```

### Different Salt Lengths

```tcl
# Generate salts of different lengths
set salt_8 [tossl::pbe::saltgen 8]   ;# 8 bytes (64 bits)
set salt_16 [tossl::pbe::saltgen 16] ;# 16 bytes (128 bits)
set salt_32 [tossl::pbe::saltgen 32] ;# 32 bytes (256 bits)
set salt_64 [tossl::pbe::saltgen 64] ;# 64 bytes (512 bits)

puts "8-byte salt: [binary encode hex $salt_8]"
puts "16-byte salt: [binary encode hex $salt_16]"
puts "32-byte salt: [binary encode hex $salt_32]"
puts "64-byte salt: [binary encode hex $salt_64]"
```

### Integration with PBE Operations

```tcl
# Generate salt for key derivation
set salt [tossl::pbe::saltgen 16]
set password "my_secure_password"
set key [tossl::pbe::keyderive sha256 $password $salt 1000 32]

puts "Generated key: [binary encode hex $key]"
```

### Salt for Encryption

```tcl
# Generate salt for PBE encryption
set salt [tossl::pbe::saltgen 16]
set password "encryption_password"
set data "Secret data to encrypt"
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]

puts "Encrypted data length: [string length $encrypted] bytes"
```

### Multiple Salt Generation

```tcl
# Generate multiple salts for different purposes
proc generate_salts {count length} {
    set salts {}
    for {set i 0} {$i < $count} {incr i} {
        lappend salts [tossl::pbe::saltgen $length]
    }
    return $salts
}

set salt_list [generate_salts 5 16]
puts "Generated [llength $salt_list] salts:"
foreach salt $salt_list {
    puts "  [binary encode hex $salt]"
}
```

### Salt Storage and Retrieval

```tcl
# Store salt with encrypted data
proc encrypt_with_salt {password data} {
    set salt [tossl::pbe::saltgen 16]
    set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
    
    # Return both encrypted data and salt
    return [list $encrypted $salt]
}

proc decrypt_with_salt {password encrypted_data salt} {
    return [tossl::pbe::decrypt sha256 $password $salt $encrypted_data]
}

# Usage
set result [encrypt_with_salt "my_password" "secret message"]
set encrypted_data [lindex $result 0]
set stored_salt [lindex $result 1]

puts "Encrypted: [binary encode hex $encrypted_data]"
puts "Salt: [binary encode hex $stored_salt]"

# Decrypt
set decrypted [decrypt_with_salt "my_password" $encrypted_data $stored_salt]
puts "Decrypted: $decrypted"
```

### Salt Validation

```tcl
# Validate that generated salt is suitable
proc validate_salt {salt} {
    set length [string length $salt]
    set hex_salt [binary encode hex $salt]
    
    # Check length
    if {$length < 8} {
        puts "WARNING: Salt is too short ($length bytes)"
        return 0
    }
    
    # Check for all zeros
    if {$hex_salt eq [string repeat "00" $length]} {
        puts "ERROR: Salt is all zeros"
        return 0
    }
    
    # Check for all same value
    set first_byte [string range $hex_salt 0 1]
    if {$hex_salt eq [string repeat $first_byte $length]} {
        puts "ERROR: Salt has no entropy (all bytes same)"
        return 0
    }
    
    puts "Salt validation: OK"
    return 1
}

# Test salt validation
set salt [tossl::pbe::saltgen 16]
validate_salt $salt
```

### Randomness Testing

```tcl
# Test that generated salts are unique
proc test_salt_uniqueness {count length} {
    set salts {}
    for {set i 0} {$i < $count} {incr i} {
        lappend salts [tossl::pbe::saltgen $length]
    }
    
    set unique_salts [lsort -unique $salts]
    set duplicates [expr {[llength $salts] - [llength $unique_salts]}]
    
    puts "Generated: [llength $salts] salts"
    puts "Unique: [llength $unique_salts] salts"
    puts "Duplicates: $duplicates"
    
    return [expr {$duplicates == 0}]
}

# Test uniqueness
if {[test_salt_uniqueness 100 16]} {
    puts "Salt uniqueness test: PASSED"
} else {
    puts "Salt uniqueness test: FAILED"
}
```

### Performance Testing

```tcl
# Test salt generation performance
proc benchmark_saltgen {iterations length} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set salt [tossl::pbe::saltgen $length]
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    set rate [expr {($iterations * 1000.0) / $duration}]
    
    puts "$iterations salts of $length bytes in ${duration}ms"
    puts "Rate: ${rate:.1f} salts/second"
}

# Run benchmark
benchmark_saltgen 1000 16
```

## Error Handling

- **Missing arguments**: Returns an error if no length parameter is provided
- **Invalid length**: Returns an error if length is not between 1 and 64 bytes
- **Non-numeric input**: Returns an error if length is not a valid number
- **Memory allocation failure**: Returns an error if memory allocation fails
- **Random number generation failure**: Returns an error if OpenSSL's random number generator fails

### Error Examples

```tcl
# Missing arguments
tossl::pbe::saltgen
# Error: wrong # args: should be "tossl::pbe::saltgen length"

# Invalid length (too small)
tossl::pbe::saltgen 0
# Error: Invalid salt length (1-64 bytes)

# Invalid length (too large)
tossl::pbe::saltgen 65
# Error: Invalid salt length (1-64 bytes)

# Non-numeric input
tossl::pbe::saltgen "invalid"
# Error: Invalid salt length (1-64 bytes)
```

## Security Considerations

### Salt Length Requirements

- **Minimum**: 8 bytes (64 bits) for basic security
- **Recommended**: 16 bytes (128 bits) for most applications
- **High security**: 32 bytes (256 bits) for sensitive data
- **Maximum**: 64 bytes (512 bits) as per implementation limit

### Randomness Quality

- **Source**: Uses OpenSSL's `RAND_bytes()` function
- **Quality**: Cryptographically secure random number generation
- **Entropy**: Each salt should have high entropy (randomness)
- **Uniqueness**: Each salt should be unique across all uses

### Salt Storage

- **Never reuse**: Each password or encryption operation should have a unique salt
- **Store with data**: Salt must be stored alongside the encrypted data or derived key
- **Secure storage**: Salt should be stored securely (same level as encrypted data)
- **No compression**: Salt should not be compressed or modified

### Example: Secure Implementation

```tcl
proc secure_salt_usage {password data} {
    # Generate a large random salt
    set salt [tossl::pbe::saltgen 32]
    
    # Use salt for key derivation
    set key [tossl::pbe::keyderive sha256 $password $salt 10000 32]
    
    # Use salt for encryption
    set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
    
    # Return all components (salt must be stored)
    return [list $key $encrypted $salt]
}

# Usage
set result [secure_salt_usage "my_password" "sensitive data"]
set key [lindex $result 0]
set encrypted [lindex $result 1]
set salt [lindex $result 2]

puts "Key: [binary encode hex $key]"
puts "Encrypted: [binary encode hex $encrypted]"
puts "Salt: [binary encode hex $salt]"
```

## Performance Considerations

### Generation Speed

- **Fast**: Salt generation is very fast (thousands per second)
- **Memory efficient**: Minimal memory overhead
- **Scalable**: Performance scales linearly with salt length

### Length Impact

```tcl
# Performance test with different lengths
foreach length {8 16 32 64} {
    set start_time [clock milliseconds]
    for {set i 0} {$i < 1000} {incr i} {
        set salt [tossl::pbe::saltgen $length]
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "$length bytes: ${duration}ms for 1000 salts"
}
```

### Batch Generation

```tcl
# Generate multiple salts efficiently
proc batch_saltgen {count length} {
    set salts {}
    for {set i 0} {$i < $count} {incr i} {
        lappend salts [tossl::pbe::saltgen $length]
    }
    return $salts
}

# Usage
set salt_batch [batch_saltgen 100 16]
puts "Generated [llength $salt_batch] salts"
```

## Best Practices

### 1. Use Appropriate Salt Length

```tcl
# Good: Appropriate salt lengths
set salt_16 [tossl::pbe::saltgen 16]  ;# General use
set salt_32 [tossl::pbe::saltgen 32]  ;# High security

# Avoid: Too short salts
set salt_short [tossl::pbe::saltgen 1]  ;# Too short
```

### 2. Generate Unique Salts

```tcl
# Good: Generate new salt for each operation
proc encrypt_data {password data} {
    set salt [tossl::pbe::saltgen 16]  ;# New salt each time
    return [list [tossl::pbe::encrypt sha256 $password $salt $data] $salt]
}

# Avoid: Reusing salts
set fixed_salt [tossl::pbe::saltgen 16]
# Don't reuse $fixed_salt for multiple operations
```

### 3. Store Salt with Data

```tcl
# Good: Store salt with encrypted data
set salt [tossl::pbe::saltgen 16]
set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
set storage_data [list $encrypted $salt]
# Save $storage_data to storage

# Avoid: Storing salt separately or not storing it
# set encrypted [tossl::pbe::encrypt sha256 $password $salt $data]
# # Don't forget to store $salt!
```

### 4. Validate Generated Salts

```tcl
# Good: Validate salt quality
proc generate_validated_salt {length} {
    set max_attempts 10
    for {set i 0} {$i < $max_attempts} {incr i} {
        set salt [tossl::pbe::saltgen $length]
        if {[validate_salt $salt]} {
            return $salt
        }
    }
    error "Failed to generate valid salt after $max_attempts attempts"
}
```

### 5. Handle Errors Gracefully

```tcl
# Good: Handle salt generation errors
proc safe_saltgen {length} {
    set rc [catch {tossl::pbe::saltgen $length} salt]
    if {$rc != 0} {
        error "Salt generation failed: $salt"
    }
    
    if {[string length $salt] != $length} {
        error "Generated salt has wrong length"
    }
    
    return $salt
}
```

## Troubleshooting

### Common Issues

1. **"Invalid salt length"**
   - **Cause**: Length parameter is outside the valid range (1-64)
   - **Solution**: Use a length between 1 and 64 bytes

2. **"wrong # args"**
   - **Cause**: Missing length parameter
   - **Solution**: Provide the required length parameter

3. **"Failed to generate random salt"**
   - **Cause**: OpenSSL random number generator failure
   - **Solution**: Check system entropy sources and OpenSSL configuration

4. **"Memory allocation failed"**
   - **Cause**: Insufficient memory
   - **Solution**: Check available system memory

### Debugging Example

```tcl
proc debug_saltgen {length} {
    puts "Debugging salt generation:"
    puts "  Requested length: $length"
    
    set rc [catch {tossl::pbe::saltgen $length} salt]
    if {$rc != 0} {
        puts "  Error: $salt"
        return ""
    }
    
    puts "  Generated length: [string length $salt]"
    puts "  Hex representation: [binary encode hex $salt]"
    
    return $salt
}

# Usage
set salt [debug_saltgen 16]
```

## Related Commands

- `::tossl::pbe::keyderive` - Derive keys using PBKDF2 with salt
- `::tossl::pbe::encrypt` - Encrypt data using password-based encryption
- `::tossl::pbe::decrypt` - Decrypt data using password-based encryption
- `::tossl::pbe::algorithms` - List supported hash algorithms
- `::tossl::randbytes` - Generate random bytes (general purpose)
- `::tossl::rand::key` - Generate random keys
- `::tossl::rand::iv` - Generate random initialization vectors

## Implementation Notes

- **OpenSSL API**: Uses `RAND_bytes()` from OpenSSL for random number generation
- **Memory Management**: Properly allocates and frees memory
- **Input Validation**: Validates length parameter before processing
- **Error Handling**: Returns descriptive error messages
- **Thread Safety**: Safe for concurrent use
- **Deterministic**: Same input always produces same length output (but different random values)

## Version Compatibility

- **OpenSSL 3.0+**: Full support
- **Provider-based**: Works with all OpenSSL providers
- **FIPS compatibility**: Works correctly in FIPS mode
- **Legacy support**: Compatible with older OpenSSL versions

## Salt Length Guidelines

### Security Recommendations

| Use Case | Recommended Length | Security Level |
|----------|-------------------|----------------|
| Basic applications | 16 bytes | Good |
| Web applications | 16-32 bytes | Better |
| Financial systems | 32 bytes | High |
| Government systems | 32-64 bytes | Very High |
| Legacy compatibility | 8 bytes | Minimum |

### Performance Impact

```tcl
# Performance comparison of different lengths
foreach length {8 16 32 64} {
    set start_time [clock milliseconds]
    for {set i 0} {$i < 10000} {incr i} {
        set salt [tossl::pbe::saltgen $length]
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "$length bytes: ${duration}ms for 10000 salts"
}
```

### Storage Considerations

```tcl
# Calculate storage requirements
set salt_length 16
set operations_per_day 1000
set days_per_year 365

set daily_storage [expr {$salt_length * $operations_per_day}]
set yearly_storage [expr {$daily_storage * $days_per_year}]

puts "Daily salt storage: $daily_storage bytes"
puts "Yearly salt storage: $yearly_storage bytes ([expr {$yearly_storage / 1024.0 / 1024.0}] MB)"
``` 