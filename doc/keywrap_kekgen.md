# ::tossl::keywrap::kekgen

Generate a key encryption key (KEK) for a specific algorithm.

## Overview

`::tossl::keywrap::kekgen` generates cryptographically secure key encryption keys (KEKs) for use in key wrapping operations. A KEK is a symmetric key used to encrypt and protect other cryptographic keys. This command automatically determines the appropriate key length based on the specified algorithm's requirements.

Key encryption keys are essential components in key management systems, providing a secure way to protect and transport other cryptographic keys without exposing them in plaintext.

## Syntax

```
tossl::keywrap::kekgen algorithm
```

### Parameters

- **algorithm**: The key wrapping algorithm name (e.g., `aes-128-ecb`, `aes-256-cbc`)

### Return Value

Returns a byte array containing the randomly generated key encryption key with the appropriate length for the specified algorithm.

## Supported Algorithms

The following algorithms are supported for KEK generation:

### AES Algorithms

| Algorithm | Key Length | Block Size | Mode | Security Level |
|-----------|------------|------------|------|----------------|
| `aes-128-ecb` | 16 bytes | 16 bytes | ECB | Standard |
| `aes-192-ecb` | 24 bytes | 16 bytes | ECB | Good |
| `aes-256-ecb` | 32 bytes | 16 bytes | ECB | High |
| `aes-128-cbc` | 16 bytes | 16 bytes | CBC | Standard |
| `aes-192-cbc` | 24 bytes | 16 bytes | CBC | Good |
| `aes-256-cbc` | 32 bytes | 16 bytes | CBC | High |

## Examples

### Basic KEK Generation

```tcl
# Generate AES-256-CBC KEK (32 bytes)
set kek [tossl::keywrap::kekgen aes-256-cbc]
puts "Generated KEK: [binary encode hex $kek]"
puts "Key length: [string length $kek] bytes"

# Generate AES-128-ECB KEK (16 bytes)
set kek [tossl::keywrap::kekgen aes-128-ecb]
puts "Generated KEK: [binary encode hex $kek]"
puts "Key length: [string length $kek] bytes"
```

### KEK Generation for Different Algorithms

```tcl
# Generate KEKs for different algorithms
set algorithms {
    aes-128-ecb
    aes-192-ecb
    aes-256-ecb
    aes-128-cbc
    aes-192-cbc
    aes-256-cbc
}

foreach algorithm $algorithms {
    set kek [tossl::keywrap::kekgen $algorithm]
    puts "$algorithm: [string length $kek] bytes"
}
```

### Complete Key Wrapping Workflow

```tcl
# Step 1: Generate KEK
set kek [tossl::keywrap::kekgen aes-256-cbc]
puts "Generated KEK: [binary encode hex $kek]"

# Step 2: Generate data to wrap
set sensitive_data "This is sensitive data that needs protection"

# Step 3: Wrap the data using the KEK
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $sensitive_data]
puts "Wrapped data: [string length $wrapped_data] bytes"

# Step 4: Store or transmit the wrapped data securely
# (The KEK should be stored separately and securely)
```

### Algorithm Information Integration

```tcl
# Get algorithm information and generate appropriate KEK
set algorithm "aes-256-cbc"
set info [tossl::keywrap::info $algorithm]

# Extract key length from algorithm info
if {[regexp {key_length (\d+)} $info -> key_length]} {
    set kek [tossl::keywrap::kekgen $algorithm]
    puts "Algorithm: $algorithm"
    puts "Expected key length: $key_length bytes"
    puts "Generated key length: [string length $kek] bytes"
    puts "Key: [binary encode hex $kek]"
}
```

### Error Handling

```tcl
# Handle invalid algorithm
if {[catch {
    set kek [tossl::keywrap::kekgen invalid-algorithm]
} err]} {
    puts "Error: $err"
}

# Handle missing arguments
if {[catch {
    set kek [tossl::keywrap::kekgen]
} err]} {
    puts "Error: $err"
}

# Handle too many arguments
if {[catch {
    set kek [tossl::keywrap::kekgen aes-256-cbc extra-arg]
} err]} {
    puts "Error: $err"
}
```

### Security Best Practices

```tcl
# Generate KEK with proper error handling
proc generate_secure_kek {algorithm} {
    # Validate algorithm first
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
    } err]} {
        error "Invalid algorithm '$algorithm': $err"
    }
    
    # Generate KEK
    if {[catch {
        set kek [tossl::keywrap::kekgen $algorithm]
    } err]} {
        error "Failed to generate KEK: $err"
    }
    
    # Verify key length
    if {[regexp {key_length (\d+)} $info -> expected_length]} {
        set actual_length [string length $kek]
        if {$actual_length != $expected_length} {
            error "Generated key length mismatch: expected $expected_length, got $actual_length"
        }
    }
    
    return $kek
}

# Usage
set kek [generate_secure_kek aes-256-cbc]
puts "Secure KEK generated: [string length $kek] bytes"
```

## Error Handling

The command may return the following errors:

- **"Unsupported KEK algorithm"**: The specified algorithm is not supported
- **"Missing value for parameter"**: No algorithm parameter provided
- **"Unknown parameter"**: Invalid parameter provided
- **"Failed to generate random KEK"**: Cryptographic random number generation failed
- **"Memory allocation failed"**: System memory allocation failed

### Common Error Scenarios

```tcl
# Invalid algorithm
if {[catch {tossl::keywrap::kekgen invalid-algorithm} err]} {
    puts "Invalid algorithm error: $err"
}

# Empty algorithm
if {[catch {tossl::keywrap::kekgen ""} err]} {
    puts "Empty algorithm error: $err"
}

# No arguments
if {[catch {tossl::keywrap::kekgen} err]} {
    puts "No arguments error: $err"
}

# Too many arguments
if {[catch {tossl::keywrap::kekgen aes-256-cbc extra} err]} {
    puts "Too many arguments error: $err"
}
```

## Security Considerations

### Key Generation Security

1. **Cryptographic Randomness**: The command uses OpenSSL's cryptographically secure random number generator (`RAND_bytes`)
2. **Key Length**: Generated keys match the algorithm's security requirements
3. **Uniqueness**: Each generated key is statistically unique

### Key Management Best Practices

1. **Secure Storage**: Store KEKs securely, separate from wrapped data
2. **Key Rotation**: Regularly rotate KEKs according to security policies
3. **Access Control**: Limit access to KEKs to authorized personnel only
4. **Key Destruction**: Securely destroy KEKs when no longer needed

### Algorithm Selection

1. **Security Level**: Choose algorithms based on required security level
   - AES-128: Standard security (128-bit)
   - AES-192: Good security (192-bit)
   - AES-256: High security (256-bit)

2. **Mode Selection**:
   - **ECB Mode**: Simpler but less secure, no IV required
   - **CBC Mode**: More secure, requires IV

### Performance Characteristics

- **Generation Speed**: Typically generates keys in microseconds
- **Memory Usage**: Minimal memory overhead
- **Scalability**: Can generate multiple keys rapidly

## Integration with Other Commands

### Key Wrapping Workflow

```tcl
# Complete secure key wrapping workflow
proc secure_key_wrapping {algorithm sensitive_data} {
    # Step 1: Generate KEK
    set kek [tossl::keywrap::kekgen $algorithm]
    
    # Step 2: Wrap the data
    set wrapped_data [tossl::keywrap::wrap $algorithm $kek $sensitive_data]
    
    # Step 3: Return both KEK and wrapped data
    return [dict create \
        algorithm $algorithm \
        kek $kek \
        wrapped_data $wrapped_data]
}

# Usage
set result [secure_key_wrapping aes-256-cbc "Sensitive data"]
puts "KEK: [binary encode hex [dict get $result kek]]"
puts "Wrapped data: [string length [dict get $result wrapped_data]] bytes"
```

### Algorithm Validation

```tcl
# Validate algorithm before KEK generation
proc validate_and_generate_kek {algorithm} {
    # Check if algorithm is supported
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
    } err]} {
        error "Algorithm '$algorithm' not supported: $err"
    }
    
    # Generate KEK
    set kek [tossl::keywrap::kekgen $algorithm]
    
    # Verify key properties
    if {[regexp {key_length (\d+)} $info -> expected_length]} {
        set actual_length [string length $kek]
        if {$actual_length != $expected_length} {
            error "Key length mismatch: expected $expected_length, got $actual_length"
        }
    }
    
    return [dict create \
        kek $kek \
        algorithm $algorithm \
        info $info]
}
```

## See Also

- `::tossl::keywrap::info` - Get information about key wrapping algorithms
- `::tossl::keywrap::algorithms` - List available key wrapping algorithms
- `::tossl::keywrap::wrap` - Wrap data using a KEK
- `::tossl::keywrap::unwrap` - Unwrap data using a KEK
- `::tossl::rand::key` - Generate random keys for general use
- `::tossl::encrypt` - General encryption operations

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions for algorithm validation
2. **Random Generation**: Uses OpenSSL's `RAND_bytes()` for cryptographically secure random key generation
3. **Memory Management**: Efficient memory allocation with proper cleanup
4. **Algorithm Validation**: Validates algorithm support before key generation

### Performance Characteristics

- **Time Complexity**: O(1) for algorithm lookup and key generation
- **Space Complexity**: O(1) for result storage
- **Memory Usage**: Minimal overhead beyond the generated key

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Algorithm Support**: Supports all AES variants available in the OpenSSL installation

### Key Generation Process

1. **Algorithm Validation**: Verify the algorithm is supported by OpenSSL
2. **Key Length Determination**: Extract required key length from algorithm
3. **Random Generation**: Generate cryptographically secure random bytes
4. **Key Formatting**: Return key as binary data
5. **Error Handling**: Provide meaningful error messages for failures 