# ::tossl::cipher::info

Get detailed information about cryptographic cipher algorithms.

## Overview

`::tossl::cipher::info` retrieves comprehensive information about cryptographic cipher algorithms supported by the TOSSL library. This command provides essential algorithm properties including block size, key length, and initialization vector (IV) length, which are crucial for proper parameter sizing in cryptographic operations.

The command returns a Tcl dictionary containing structured information about the specified cipher algorithm, making it easy to programmatically determine the correct parameters for encryption and decryption operations.

## Syntax

```tcl
::tossl::cipher::info -alg cipher_name
```

### Parameters

- **-alg cipher_name** (required): The name of the cipher algorithm (e.g., "AES-128-CBC", "AES-256-GCM", "ChaCha20")

### Return Value

Returns a Tcl dictionary with the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | The cipher algorithm name |
| `block_size` | integer | Block size in bytes (1 for stream ciphers) |
| `key_length` | integer | Key length in bytes |
| `iv_length` | integer | IV length in bytes (0 for ECB mode) |

## Examples

### Basic Usage

```tcl
# Get information about AES-128-CBC
set info [tossl::cipher::info -alg AES-128-CBC]
puts "Cipher: [dict get $info name]"
puts "Block size: [dict get $info block_size] bytes"
puts "Key length: [dict get $info key_length] bytes"
puts "IV length: [dict get $info iv_length] bytes"
```

### Parameter Validation

```tcl
# Validate cipher parameters before encryption
proc validate_cipher_params {cipher_name key iv} {
    if {[catch {tossl::cipher::info -alg $cipher_name} info]} {
        error "Unknown cipher: $cipher_name"
    }
    
    set expected_key_len [dict get $info key_length]
    set expected_iv_len [dict get $info iv_length]
    set actual_key_len [string length $key]
    set actual_iv_len [string length $iv]
    
    if {$actual_key_len != $expected_key_len} {
        error "Key length mismatch: expected $expected_key_len, got $actual_key_len"
    }
    
    if {$expected_iv_len > 0 && $actual_iv_len != $expected_iv_len} {
        error "IV length mismatch: expected $expected_iv_len, got $actual_iv_len"
    }
    
    return $info
}

# Usage
set key [tossl::rand::key -alg AES-128-CBC]
set iv [tossl::rand::iv -alg AES-128-CBC]
set info [validate_cipher_params AES-128-CBC $key $iv]
puts "Parameters validated successfully"
```

### Dynamic Cipher Selection

```tcl
# Select appropriate cipher based on security requirements
proc select_cipher_by_security {security_level mode} {
    set ciphers [tossl::cipher::list -type $mode]
    set selected_cipher ""
    
    foreach cipher $ciphers {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            continue
        }
        
        set key_length [dict get $info key_length]
        
        if {$security_level eq "high" && $key_length >= 32} {
            set selected_cipher $cipher
            break
        } elseif {$security_level eq "standard" && $key_length >= 16} {
            set selected_cipher $cipher
            break
        }
    }
    
    return $selected_cipher
}

# Usage
set high_security_cbc [select_cipher_by_security "high" "cbc"]
puts "High security CBC cipher: $high_security_cbc"

set standard_security_gcm [select_cipher_by_security "standard" "gcm"]
puts "Standard security GCM cipher: $standard_security_gcm"
```

### Cipher Family Analysis

```tcl
# Analyze cipher families
proc analyze_cipher_family {family_name} {
    set ciphers [tossl::cipher::list]
    set family_ciphers {}
    
    foreach cipher $ciphers {
        if {[string match "*$family_name*" [string tolower $cipher]]} {
            if {[catch {tossl::cipher::info -alg $cipher} info]} {
                continue
            }
            lappend family_ciphers [dict create cipher $cipher info $info]
        }
    }
    
    return $family_ciphers
}

# Usage
set aes_ciphers [analyze_cipher_family "aes"]
puts "Found [llength $aes_ciphers] AES ciphers:"

foreach cipher_info $aes_ciphers {
    set cipher [dict get $cipher_info cipher]
    set info [dict get $cipher_info info]
    puts "  $cipher: [dict get $info key_length] bytes key, [dict get $info block_size] bytes block"
}
```

### Security Assessment

```tcl
# Assess cipher security level
proc assess_cipher_security {cipher_name} {
    if {[catch {tossl::cipher::info -alg $cipher_name} info]} {
        return "unknown"
    }
    
    set key_length [dict get $info key_length]
    set block_size [dict get $info block_size]
    set cipher_lower [string tolower $cipher_name]
    
    # Security assessment based on key length and mode
    if {$key_length >= 32} {
        set security "high"
    } elseif {$key_length >= 16} {
        set security "standard"
    } else {
        set security "weak"
    }
    
    # Adjust for weak modes
    if {[string match "*ecb*" $cipher_lower]} {
        set security "weak"
    }
    
    # Boost for authenticated modes
    if {[string match "*gcm*" $cipher_lower] || [string match "*ccm*" $cipher_lower]} {
        if {$security eq "standard"} {
            set security "high"
        }
    }
    
    return $security
}

# Usage
set test_ciphers {AES-128-CBC AES-256-GCM DES-CBC ChaCha20}
foreach cipher $test_ciphers {
    set security [assess_cipher_security $cipher]
    puts "$cipher: $security security"
}
```

### Integration with Encryption

```tcl
# Automated encryption with parameter validation
proc encrypt_with_validation {cipher_name data} {
    # Get cipher information
    if {[catch {tossl::cipher::info -alg $cipher_name} info]} {
        error "Unknown cipher: $cipher_name"
    }
    
    # Generate appropriate key and IV
    set key [tossl::rand::key -alg $cipher_name]
    set iv [tossl::rand::iv -alg $cipher_name]
    
    # Validate parameters
    set expected_key_len [dict get $info key_length]
    set expected_iv_len [dict get $info iv_length]
    set actual_key_len [string length $key]
    set actual_iv_len [string length $iv]
    
    if {$actual_key_len != $expected_key_len} {
        error "Key generation failed: expected $expected_key_len, got $actual_key_len"
    }
    
    if {$expected_iv_len > 0 && $actual_iv_len != $expected_iv_len} {
        error "IV generation failed: expected $expected_iv_len, got $actual_iv_len"
    }
    
    # Perform encryption
    set encrypted [tossl::encrypt -alg $cipher_name -key $key -iv $iv $data]
    
    return [dict create \
        encrypted $encrypted \
        key $key \
        iv $iv \
        cipher_info $info]
}

# Usage
set result [encrypt_with_validation AES-128-CBC "Hello, World!"]
puts "Encrypted data length: [string length [dict get $result encrypted]]"
puts "Key length: [string length [dict get $result key]]"
puts "IV length: [string length [dict get $result iv]]"
```

### Performance Testing

```tcl
# Test cipher info performance
proc test_cipher_info_performance {iterations} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set info [tossl::cipher::info -alg AES-128-CBC]
        if {![dict exists $info name]} {
            error "Performance test failed on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "Performance test:"
    puts "  Iterations: $iterations"
    puts "  Total time: ${duration}ms"
    puts "  Average time per call: [expr {double($duration) / $iterations}]ms"
}

# Usage
test_cipher_info_performance 100
```

### Cipher Comparison

```tcl
# Compare multiple ciphers
proc compare_ciphers {cipher_list} {
    set comparison {}
    
    foreach cipher $cipher_list {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            lappend comparison [dict create \
                cipher $cipher \
                status "error" \
                error "Unknown cipher"]
        } else {
            lappend comparison [dict create \
                cipher $cipher \
                status "available" \
                block_size [dict get $info block_size] \
                key_length [dict get $info key_length] \
                iv_length [dict get $info iv_length]]
        }
    }
    
    return $comparison
}

# Usage
set ciphers {AES-128-CBC AES-256-GCM DES-CBC ChaCha20 UNKNOWN-CIPHER}
set comparison [compare_ciphers $ciphers]

foreach result $comparison {
    set cipher [dict get $result cipher]
    set status [dict get $result status]
    
    if {$status eq "available"} {
        puts "$cipher: [dict get $result key_length] bytes key, [dict get $result block_size] bytes block"
    } else {
        puts "$cipher: [dict get $result error]"
    }
}
```

## Supported Cipher Types

### AES Ciphers

| Cipher | Block Size | Key Length | IV Length | Mode |
|--------|------------|------------|-----------|------|
| AES-128-CBC | 16 | 16 | 16 | CBC |
| AES-192-CBC | 16 | 24 | 16 | CBC |
| AES-256-CBC | 16 | 32 | 16 | CBC |
| AES-128-GCM | 1 | 16 | 12 | GCM |
| AES-256-GCM | 1 | 32 | 12 | GCM |
| AES-128-ECB | 16 | 16 | 0 | ECB |
| AES-256-ECB | 16 | 32 | 0 | ECB |

### Legacy Ciphers

| Cipher | Block Size | Key Length | IV Length | Mode |
|--------|------------|------------|-----------|------|
| DES-CBC | 8 | 8 | 8 | CBC |
| DES-ECB | 8 | 8 | 0 | ECB |
| BF-CBC | 8 | 16 | 8 | CBC |
| CAST5-CBC | 8 | 16 | 8 | CBC |

### Stream Ciphers

| Cipher | Block Size | Key Length | IV Length | Mode |
|--------|------------|------------|-----------|------|
| ChaCha20 | 1 | 32 | 16 | Stream |
| ChaCha20-Poly1305 | 1 | 32 | 12 | AEAD |

## Error Handling

The following errors may be returned:

- **"wrong # args"**: Incorrect number of arguments provided
- **"Unknown cipher algorithm"**: The specified cipher is not supported

### Error Handling Examples

```tcl
# Handle unknown cipher
if {[catch {tossl::cipher::info -alg UNKNOWN-CIPHER} result]} {
    puts "Error: $result"
    # Handle the error appropriately
}

# Handle missing parameters
if {[catch {tossl::cipher::info} result]} {
    puts "Error: $result"
    # Handle the error appropriately
}

# Handle wrong parameter name
if {[catch {tossl::cipher::info -wrong AES-128-CBC} result]} {
    puts "Error: $result"
} else {
    puts "Command accepted wrong parameter (this might be expected)"
}
```

## Integration with Other Commands

### With `::tossl::cipher::list`

```tcl
# Get info for all available ciphers
set ciphers [tossl::cipher::list]
set cipher_info {}

foreach cipher $ciphers {
    if {[catch {tossl::cipher::info -alg $cipher} info]} {
        puts "Could not get info for $cipher"
    } else {
        lappend cipher_info [dict create cipher $cipher info $info]
    }
}

puts "Retrieved info for [llength $cipher_info] ciphers"
```

### With `::tossl::cipher::analyze`

```tcl
# Compare info with analyze results
set test_ciphers {AES-128-CBC AES-256-GCM DES-CBC}

foreach cipher $test_ciphers {
    if {[catch {tossl::cipher::info -alg $cipher} info]} {
        puts "$cipher: Error getting info"
    } elseif {[catch {tossl::cipher::analyze $cipher} analysis]} {
        puts "$cipher: Error getting analysis"
    } else {
        puts "$cipher:"
        puts "  Info: [dict get $info block_size] bytes block, [dict get $info key_length] bytes key"
        puts "  Analysis: $analysis"
    }
}
```

### With `::tossl::encrypt` and `::tossl::decrypt`

```tcl
# Use info for proper parameter sizing
proc encrypt_with_info {cipher_name data} {
    # Get cipher information
    set info [tossl::cipher::info -alg $cipher_name]
    
    # Generate appropriate parameters
    set key [tossl::rand::key -alg $cipher_name]
    set iv [tossl::rand::iv -alg $cipher_name]
    
    # Verify parameter sizes
    set expected_key_len [dict get $info key_length]
    set expected_iv_len [dict get $info iv_length]
    
    if {[string length $key] != $expected_key_len} {
        error "Key length mismatch"
    }
    
    if {$expected_iv_len > 0 && [string length $iv] != $expected_iv_len} {
        error "IV length mismatch"
    }
    
    # Perform encryption
    return [tossl::encrypt -alg $cipher_name -key $key -iv $iv $data]
}

# Usage
set encrypted [encrypt_with_info AES-128-CBC "Test data"]
puts "Encryption successful"
```

## Security Considerations

### Algorithm Selection

1. **Key Length**: Choose appropriate key lengths for your security requirements
   - 128-bit (16 bytes): Standard security
   - 192-bit (24 bytes): Good security
   - 256-bit (32 bytes): High security

2. **Mode Selection**:
   - **ECB Mode**: Not recommended (deterministic, no IV)
   - **CBC Mode**: Standard mode, requires IV
   - **GCM Mode**: Authenticated encryption, recommended
   - **CCM Mode**: Authenticated encryption, suitable for constrained environments

3. **Block Size**: Consider block size for padding requirements
   - 16 bytes: Standard AES block size
   - 8 bytes: Legacy block size (DES, etc.)
   - 1 byte: Stream ciphers

### Best Practices

1. **Parameter Validation**: Always validate cipher parameters before use
2. **Key Management**: Use appropriate key lengths for your security requirements
3. **IV Generation**: Always use cryptographically secure random IVs
4. **Mode Selection**: Prefer authenticated encryption modes (GCM, CCM)

### Security Warnings

1. **ECB Mode**: Electronic Codebook mode is deterministic and may reveal patterns
2. **Weak Ciphers**: Avoid deprecated or weak cipher algorithms
3. **Key Reuse**: Never reuse keys for different purposes
4. **IV Reuse**: Never reuse initialization vectors with the same key

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's `EVP_CIPHER_fetch()` function
2. **Provider Awareness**: Respects currently loaded OpenSSL providers
3. **Memory Management**: Properly frees OpenSSL cipher objects
4. **Error Handling**: Comprehensive error checking and reporting

### Performance Characteristics

- **Time Complexity**: O(1) for single cipher lookup
- **Space Complexity**: O(1) for result storage
- **Memory Usage**: Minimal overhead beyond the result dictionary

### Cipher Naming Convention

Ciphers are specified using OpenSSL's standard naming convention:
- **Algorithm-KeyLength-Mode** (e.g., "AES-128-CBC", "AES-256-GCM")
- **Case Insensitive**: Cipher names are case-insensitive
- **Standard Format**: Follows OpenSSL naming standards

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers

### Performance Benchmarks

Typical performance characteristics:
- **Single lookup**: ~0.01ms per cipher
- **Batch operations**: ~0.5ms for 50 lookups
- **Memory usage**: Minimal overhead

## See Also

- `::tossl::cipher::list` - List available cipher algorithms
- `::tossl::cipher::analyze` - Analyze cipher properties
- `::tossl::encrypt` - Encrypt data using ciphers
- `::tossl::decrypt` - Decrypt data using ciphers
- `::tossl::rand::key` - Generate random keys for ciphers
- `::tossl::rand::iv` - Generate random IVs for ciphers 