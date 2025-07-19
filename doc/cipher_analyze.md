# ::tossl::cipher::analyze

Analyze cryptographic cipher properties and characteristics.

## Overview

`::tossl::cipher::analyze` provides detailed analysis of cryptographic ciphers supported by the TOSSL library. This command returns comprehensive information about cipher properties including key length, initialization vector (IV) length, block size, and internal flags. This information is essential for understanding cipher capabilities, validating cipher parameters, and making informed decisions about cryptographic operations.

Cipher analysis is crucial for security auditing, compliance checking, and ensuring that appropriate cryptographic parameters are used in applications.

## Syntax

```
tossl::cipher::analyze cipher_name
```

### Parameters

- **cipher_name**: The name of the cryptographic cipher to analyze (e.g., `aes-256-cbc`, `aes-128-gcm`)

### Return Value

Returns a string containing cipher analysis information in the format:
`key_len=X, iv_len=Y, block_size=Z, flags=0xW`

Where:
- **key_len**: Required key length in bytes
- **iv_len**: Required initialization vector length in bytes (0 for ECB mode)
- **block_size**: Cipher block size in bytes
- **flags**: Internal OpenSSL cipher flags in hexadecimal

## Supported Ciphers

The following cipher types are supported for analysis:

### AES Ciphers

| Cipher | Key Length | IV Length | Block Size | Mode | Security Level |
|--------|------------|-----------|------------|------|----------------|
| `aes-128-ecb` | 16 bytes | 0 bytes | 16 bytes | ECB | Standard |
| `aes-192-ecb` | 24 bytes | 0 bytes | 16 bytes | ECB | Good |
| `aes-256-ecb` | 32 bytes | 0 bytes | 16 bytes | ECB | High |
| `aes-128-cbc` | 16 bytes | 16 bytes | 16 bytes | CBC | Standard |
| `aes-192-cbc` | 24 bytes | 16 bytes | 16 bytes | CBC | Good |
| `aes-256-cbc` | 32 bytes | 16 bytes | 16 bytes | CBC | High |
| `aes-128-gcm` | 16 bytes | 12 bytes | 1 byte | GCM | Standard |
| `aes-192-gcm` | 24 bytes | 12 bytes | 1 byte | GCM | Good |
| `aes-256-gcm` | 32 bytes | 12 bytes | 1 byte | GCM | High |

### Other Ciphers

| Cipher | Key Length | IV Length | Block Size | Mode | Security Level |
|--------|------------|-----------|------------|------|----------------|
| `chacha20-poly1305` | 32 bytes | 12 bytes | 1 byte | AEAD | High |
| `camellia-128-cbc` | 16 bytes | 16 bytes | 16 bytes | CBC | Standard |
| `camellia-192-cbc` | 24 bytes | 16 bytes | 16 bytes | CBC | Good |
| `camellia-256-cbc` | 32 bytes | 16 bytes | 16 bytes | CBC | High |

## Examples

### Basic Cipher Analysis

```tcl
# Analyze AES-256-CBC cipher
set analysis [tossl::cipher::analyze aes-256-cbc]
puts "AES-256-CBC analysis: $analysis"
# Output: AES-256-CBC analysis: key_len=32, iv_len=16, block_size=16, flags=0x2

# Analyze AES-128-GCM cipher
set analysis [tossl::cipher::analyze aes-128-gcm]
puts "AES-128-GCM analysis: $analysis"
# Output: AES-128-GCM analysis: key_len=16, iv_len=12, block_size=1, flags=0x300c76
```

### Cipher Comparison

```tcl
# Compare different AES modes
set ciphers {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}

foreach cipher $ciphers {
    set analysis [tossl::cipher::analyze $cipher]
    puts "$cipher: $analysis"
}
```

### Algorithm Validation

```tcl
# Validate cipher before use
proc validate_cipher {cipher_name} {
    if {[catch {
        set analysis [tossl::cipher::analyze $cipher_name]
        return [dict create success 1 analysis $analysis]
    } err]} {
        return [dict create success 0 error $err]
    }
}

# Usage
set result [validate_cipher aes-256-cbc]
if {[dict get $result success]} {
    puts "Cipher is valid: [dict get $result analysis]"
} else {
    puts "Cipher validation failed: [dict get $result error]"
}
```

### Security Assessment

```tcl
# Assess cipher security level
proc assess_cipher_security {cipher_name} {
    set analysis [tossl::cipher::analyze $cipher_name]
    
    # Parse key length
    if {[regexp {key_len=(\d+)} $analysis -> key_len]} {
        if {$key_len >= 32} {
            set security "High (256-bit key)"
        } elseif {$key_len >= 24} {
            set security "Good (192-bit key)"
        } else {
            set security "Standard (128-bit key)"
        }
    } else {
        set security "Unknown"
    }
    
    # Check mode
    if {[string match "*gcm*" $cipher_name] || [string match "*poly1305*" $cipher_name]} {
        set mode "Authenticated Encryption (AEAD)"
    } elseif {[string match "*cbc*" $cipher_name]} {
        set mode "Cipher Block Chaining (CBC)"
    } elseif {[string match "*ecb*" $cipher_name]} {
        set mode "Electronic Codebook (ECB) - Not Recommended"
    } else {
        set mode "Unknown"
    }
    
    return [dict create \
        cipher $cipher_name \
        analysis $analysis \
        security $security \
        mode $mode]
}

# Usage
set assessment [assess_cipher_security aes-256-gcm]
puts "Cipher: [dict get $assessment cipher]"
puts "Security: [dict get $assessment security]"
puts "Mode: [dict get $assessment mode]"
puts "Analysis: [dict get $assessment analysis]"
```

### Performance Analysis

```tcl
# Analyze cipher performance characteristics
proc analyze_cipher_performance {cipher_name} {
    set analysis [tossl::cipher::analyze $cipher_name]
    
    # Parse components
    if {[regexp {key_len=(\d+), iv_len=(\d+), block_size=(\d+)} $analysis -> key_len iv_len block_size]} {
        
        # Estimate performance characteristics
        if {$block_size == 1} {
            set type "Stream cipher or AEAD"
            set performance "High (stream processing)"
        } else {
            set type "Block cipher"
            set performance "Standard (block processing)"
        }
        
        # Key setup overhead
        if {$key_len >= 32} {
            set key_setup "Higher (longer key)"
        } else {
            set key_setup "Lower (shorter key)"
        }
        
        return [dict create \
            cipher $cipher_name \
            type $type \
            performance $performance \
            key_setup $key_setup \
            key_len $key_len \
            iv_len $iv_len \
            block_size $block_size]
    }
    
    return [dict create error "Could not parse analysis"]
}

# Usage
set perf [analyze_cipher_performance aes-256-gcm]
puts "Performance analysis for [dict get $perf cipher]:"
puts "  Type: [dict get $perf type]"
puts "  Performance: [dict get $perf performance]"
puts "  Key setup: [dict get $perf key_setup]"
```

### Batch Cipher Analysis

```tcl
# Analyze multiple ciphers
proc analyze_ciphers {cipher_list} {
    set results {}
    
    foreach cipher $cipher_list {
        if {[catch {
            set analysis [tossl::cipher::analyze $cipher]
            lappend results [dict create \
                cipher $cipher \
                analysis $analysis \
                success 1]
        } err]} {
            lappend results [dict create \
                cipher $cipher \
                error $err \
                success 0]
        }
    }
    
    return $results
}

# Usage
set ciphers {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm chacha20-poly1305}
set analyses [analyze_ciphers $ciphers]

foreach result $analyses {
    if {[dict get $result success]} {
        puts "[dict get $result cipher]: [dict get $result analysis]"
    } else {
        puts "[dict get $result cipher]: Error - [dict get $result error]"
    }
}
```

### Integration with Other Commands

```tcl
# Use with cipher list to analyze available ciphers
if {[catch {
    set available_ciphers [tossl::cipher::list]
    puts "Analyzing [llength $available_ciphers] available ciphers..."
    
    # Analyze first 10 ciphers
    set count 0
    foreach cipher $available_ciphers {
        if {$count >= 10} break
        if {[catch {
            set analysis [tossl::cipher::analyze $cipher]
            puts "  $cipher: $analysis"
        } err]} {
            puts "  $cipher: Error - $err"
        }
        incr count
    }
} err]} {
    puts "Could not retrieve cipher list: $err"
}
```

## Error Handling

The following errors may be returned:

- **"Unknown cipher"**: The specified cipher is not supported
- **"wrong # args"**: Incorrect number of arguments provided

### Error Handling Examples

```tcl
# Handle invalid cipher
if {[catch {tossl::cipher::analyze invalid-cipher} result]} {
    puts "Error: $result"
}

# Handle missing arguments
if {[catch {tossl::cipher::analyze} result]} {
    puts "Error: $result"
}

# Handle too many arguments
if {[catch {tossl::cipher::analyze aes-256-cbc extra-arg} result]} {
    puts "Error: $result"
}
```

## Integration with Other Commands

### With `::tossl::cipher::list`

```tcl
# Analyze all available ciphers
set ciphers [tossl::cipher::list]
foreach cipher $ciphers {
    if {[catch {tossl::cipher::analyze $cipher} analysis]} {
        puts "$cipher: Not available"
    } else {
        puts "$cipher: $analysis"
    }
}
```

### With `::tossl::cipher::info`

```tcl
# Compare analyze and info commands
set cipher "aes-256-cbc"
set analysis [tossl::cipher::analyze $cipher]
set info [tossl::cipher::info -alg $cipher]

puts "Analysis: $analysis"
puts "Info: $info"
```

### With `::tossl::encrypt` and `::tossl::decrypt`

```tcl
# Validate cipher before encryption
proc safe_encrypt {cipher key iv data} {
    # First analyze the cipher
    set analysis [tossl::cipher::analyze $cipher]
    
    # Parse key length requirement
    if {[regexp {key_len=(\d+)} $analysis -> required_key_len]} {
        set actual_key_len [string length $key]
        if {$actual_key_len != $required_key_len} {
            error "Key length mismatch: required $required_key_len, got $actual_key_len"
        }
    }
    
    # Parse IV length requirement
    if {[regexp {iv_len=(\d+)} $analysis -> required_iv_len]} {
        if {$required_iv_len > 0} {
            set actual_iv_len [string length $iv]
            if {$actual_iv_len != $required_iv_len} {
                error "IV length mismatch: required $required_iv_len, got $actual_iv_len"
            }
        }
    }
    
    # Proceed with encryption
    return [tossl::encrypt -alg $cipher -key $key -iv $iv $data]
}

# Usage
set key [tossl::rand::key -alg aes-256-cbc]
set iv [tossl::rand::iv -alg aes-256-cbc]
set data "Secret data"

set encrypted [safe_encrypt aes-256-cbc $key $iv $data]
puts "Encryption successful"
```

## Security Considerations

### Algorithm Selection

1. **Security Level**: Choose appropriate security level for your use case
   - 128-bit: Standard security (suitable for most applications)
   - 192-bit: Good security (suitable for sensitive data)
   - 256-bit: High security (suitable for highly sensitive data)

2. **Mode Selection**:
   - **ECB Mode**: Not recommended for security (deterministic)
   - **CBC Mode**: Standard mode, requires IV
   - **GCM Mode**: Authenticated encryption, recommended for new applications
   - **ChaCha20-Poly1305**: Modern authenticated encryption

3. **Key Management**: Always use appropriate key lengths and secure key generation

### Best Practices

1. **Cipher Validation**: Always validate cipher support before use
2. **Parameter Validation**: Verify key and IV lengths match requirements
3. **Mode Selection**: Prefer authenticated encryption modes (GCM, ChaCha20-Poly1305)
4. **Error Handling**: Handle cipher analysis failures gracefully

### Security Warnings

1. **ECB Mode**: Electronic Codebook mode is deterministic and may reveal patterns
2. **Key Reuse**: Never reuse keys for different purposes
3. **IV Reuse**: Never reuse initialization vectors with the same key
4. **Weak Ciphers**: Avoid deprecated or weak cipher algorithms

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions
2. **Cipher Lookup**: Direct mapping to supported OpenSSL ciphers
3. **Memory Management**: Efficient memory usage with no leaks
4. **Performance**: Fast cipher analysis with minimal overhead

### Performance Characteristics

- **Time Complexity**: O(1) for cipher analysis
- **Space Complexity**: O(1) for result storage
- **Memory Usage**: Minimal overhead beyond the result string

### Analysis Format

The analysis string format is:
```
key_len=<key_length>, iv_len=<iv_length>, block_size=<block_size>, flags=0x<flags>
```

### Flag Interpretation

The flags field contains OpenSSL internal cipher flags:
- **0x1**: ECB mode
- **0x2**: CBC mode
- **0x300c76**: GCM mode with specific features
- **0x300c70**: ChaCha20-Poly1305 mode

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Algorithm Support**: Supports all ciphers available in the OpenSSL installation

## See Also

- `::tossl::cipher::list` - List available ciphers
- `::tossl::cipher::info` - Get detailed cipher information
- `::tossl::encrypt` - Encrypt data using ciphers
- `::tossl::decrypt` - Decrypt data using ciphers
- `::tossl::algorithm::list` - List algorithms by type
- `::tossl::algorithm::info` - Get algorithm information 