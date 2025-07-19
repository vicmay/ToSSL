# ::tossl::cipher::list

List available cryptographic cipher algorithms.

## Overview

`::tossl::cipher::list` returns a list of all available cryptographic cipher algorithms supported by the TOSSL library. This command is useful for discovering available ciphers, building cipher selection interfaces, and validating cipher availability before using them in cryptographic operations.

The command supports optional filtering by cipher mode (e.g., CBC, GCM, ECB) to help narrow down the list of available ciphers for specific use cases.

## Syntax

```
tossl::cipher::list ?-type type?
```

### Parameters

- **-type type** (optional): Filter ciphers by mode type (e.g., `cbc`, `gcm`, `ecb`, `ccm`, `ofb`, `cfb`, `ctr`)

### Return Value

Returns a Tcl list containing the names of all available cipher algorithms. The list is empty if no ciphers are available or if the type filter matches no ciphers.

## Supported Cipher Types

The following cipher modes can be used with the `-type` filter:

| Mode | Description | Examples |
|------|-------------|----------|
| `cbc` | Cipher Block Chaining | AES-128-CBC, DES-CBC, CAMELLIA-256-CBC |
| `ecb` | Electronic Codebook | AES-128-ECB, DES-ECB, SM4-ECB |
| `gcm` | Galois/Counter Mode | AES-128-GCM, AES-256-GCM, ARIA-128-GCM |
| `ccm` | Counter with CBC-MAC | AES-128-CCM, AES-256-CCM |
| `ofb` | Output Feedback | AES-128-OFB, DES-OFB |
| `cfb` | Cipher Feedback | AES-128-CFB, DES-CFB |
| `ctr` | Counter Mode | AES-128-CTR, AES-256-CTR |

## Examples

### Basic Usage

```tcl
# Get list of all available ciphers
set ciphers [tossl::cipher::list]
puts "Available ciphers: [llength $ciphers]"
puts "First 10 ciphers: [lrange $ciphers 0 9]"
```

### Mode Filtering

```tcl
# Get only CBC mode ciphers
set cbc_ciphers [tossl::cipher::list -type cbc]
puts "CBC ciphers: [llength $cbc_ciphers]"
puts "CBC ciphers: $cbc_ciphers"

# Get only GCM mode ciphers
set gcm_ciphers [tossl::cipher::list -type gcm]
puts "GCM ciphers: [llength $gcm_ciphers]"
puts "GCM ciphers: $gcm_ciphers"

# Get only ECB mode ciphers
set ecb_ciphers [tossl::cipher::list -type ecb]
puts "ECB ciphers: [llength $ecb_ciphers]"
puts "ECB ciphers: $ecb_ciphers"
```

### Cipher Discovery

```tcl
# Discover available cipher families
set ciphers [tossl::cipher::list]
set families {}

foreach cipher $ciphers {
    set cipher_lower [string tolower $cipher]
    if {[string match "*aes*" $cipher_lower]} {
        lappend families "AES"
    } elseif {[string match "*des*" $cipher_lower]} {
        lappend families "DES"
    } elseif {[string match "*camellia*" $cipher_lower]} {
        lappend families "CAMELLIA"
    } elseif {[string match "*aria*" $cipher_lower]} {
        lappend families "ARIA"
    } elseif {[string match "*sm4*" $cipher_lower]} {
        lappend families "SM4"
    } elseif {[string match "*chacha*" $cipher_lower]} {
        lappend families "ChaCha20"
    }
}

set unique_families [lsort -unique $families]
puts "Available cipher families: $unique_families"
```

### Cipher Validation

```tcl
# Check if specific ciphers are available
proc check_cipher_availability {cipher_list} {
    set available_ciphers [tossl::cipher::list]
    set results {}
    
    foreach cipher $cipher_list {
        if {[lsearch $available_ciphers $cipher] != -1} {
            lappend results [dict create cipher $cipher available 1]
        } else {
            lappend results [dict create cipher $cipher available 0]
        }
    }
    
    return $results
}

# Usage
set test_ciphers {AES-128-CBC AES-256-CBC AES-128-GCM AES-256-GCM DES-CBC}
set availability [check_cipher_availability $test_ciphers]

foreach result $availability {
    set cipher [dict get $result cipher]
    set available [dict get $result available]
    if {$available} {
        puts "✓ $cipher: Available"
    } else {
        puts "✗ $cipher: Not available"
    }
}
```

### Dynamic Cipher Selection

```tcl
# Select appropriate cipher based on requirements
proc select_cipher {security_level mode} {
    set ciphers [tossl::cipher::list -type $mode]
    set selected_cipher ""
    
    foreach cipher $ciphers {
        set cipher_lower [string tolower $cipher]
        
        if {$security_level eq "high" && [string match "*256*" $cipher_lower]} {
            set selected_cipher $cipher
            break
        } elseif {$security_level eq "medium" && [string match "*192*" $cipher_lower]} {
            set selected_cipher $cipher
            break
        } elseif {$security_level eq "standard" && [string match "*128*" $cipher_lower]} {
            set selected_cipher $cipher
            break
        }
    }
    
    return $selected_cipher
}

# Usage
set high_security_cbc [select_cipher "high" "cbc"]
puts "High security CBC cipher: $high_security_cbc"

set standard_security_gcm [select_cipher "standard" "gcm"]
puts "Standard security GCM cipher: $standard_security_gcm"
```

### Integration with Other Commands

```tcl
# Analyze all available ciphers
proc analyze_all_ciphers {} {
    set ciphers [tossl::cipher::list]
    set analysis {}
    
    foreach cipher $ciphers {
        if {[catch {
            set cipher_info [tossl::cipher::analyze $cipher]
            lappend analysis [dict create \
                cipher $cipher \
                analysis $cipher_info \
                success 1]
        } err]} {
            lappend analysis [dict create \
                cipher $cipher \
                error $err \
                success 0]
        }
    }
    
    return $analysis
}

# Usage
set cipher_analysis [analyze_all_ciphers]
puts "Analyzed [llength $cipher_analysis] ciphers"

# Show first 5 successful analyses
set count 0
foreach result $cipher_analysis {
    if {$count >= 5} break
    if {[dict get $result success]} {
        puts "[dict get $result cipher]: [dict get $result analysis]"
        incr count
    }
}
```

### Performance Testing

```tcl
# Test cipher list performance
proc test_cipher_list_performance {iterations} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set ciphers [tossl::cipher::list]
        if {![llength $ciphers]} {
            error "Empty cipher list on iteration $i"
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
test_cipher_list_performance 100
```

### Security Assessment

```tcl
# Assess cipher security levels
proc assess_cipher_security {cipher_list} {
    set assessment {}
    
    foreach cipher $cipher_list {
        set security_level "unknown"
        set recommendations {}
        
        set cipher_lower [string tolower $cipher]
        
        # Check key length
        if {[string match "*256*" $cipher_lower]} {
            set security_level "high"
        } elseif {[string match "*192*" $cipher_lower]} {
            set security_level "good"
        } elseif {[string match "*128*" $cipher_lower]} {
            set security_level "standard"
        }
        
        # Check mode
        if {[string match "*ecb*" $cipher_lower]} {
            lappend recommendations "ECB mode is not recommended for security"
        }
        
        if {[string match "*gcm*" $cipher_lower] || [string match "*ccm*" $cipher_lower]} {
            lappend recommendations "Authenticated encryption mode - recommended"
        }
        
        lappend assessment [dict create \
            cipher $cipher \
            security_level $security_level \
            recommendations $recommendations]
    }
    
    return $assessment
}

# Usage
set ciphers [tossl::cipher::list -type cbc]
set security_assessment [assess_cipher_security $ciphers]

foreach assessment $security_assessment {
    puts "[dict get $assessment cipher]: [dict get $assessment security_level]"
    foreach rec [dict get $assessment recommendations] {
        puts "  - $rec"
    }
}
```

## Error Handling

The following errors may be returned:

- **"wrong # args"**: Incorrect number of arguments provided
- **Empty list**: No ciphers match the specified type filter

### Error Handling Examples

```tcl
# Handle wrong number of arguments
if {[catch {tossl::cipher::list extra-arg1 extra-arg2} result]} {
    puts "Error: $result"
}

# Handle invalid type filter
if {[catch {tossl::cipher::list -type invalid-type} result]} {
    puts "Error: $result"
} else {
    puts "No ciphers found for invalid type"
}

# Handle missing type value
if {[catch {tossl::cipher::list -type} result]} {
    puts "Error: $result"
}
```

## Integration with Other Commands

### With `::tossl::cipher::analyze`

```tcl
# Analyze all available ciphers
set ciphers [tossl::cipher::list]
foreach cipher $ciphers {
    if {[catch {tossl::cipher::analyze $cipher} analysis]} {
        puts "$cipher: Error - $analysis"
    } else {
        puts "$cipher: $analysis"
    }
}
```

### With `::tossl::cipher::info`

```tcl
# Get detailed info for all ciphers
set ciphers [tossl::cipher::list]
foreach cipher $ciphers {
    if {[catch {tossl::cipher::info -alg $cipher} info]} {
        puts "$cipher: Error - $info"
    } else {
        puts "$cipher: [dict get $info block_size] bytes block size"
    }
}
```

### With `::tossl::encrypt` and `::tossl::decrypt`

```tcl
# Test encryption with available ciphers
proc test_cipher_encryption {cipher} {
    set key [tossl::rand::key -alg $cipher]
    set iv [tossl::rand::iv -alg $cipher]
    set data "Test data"
    
    if {[catch {
        set encrypted [tossl::encrypt -alg $cipher -key $key -iv $iv $data]
        set decrypted [tossl::decrypt -alg $cipher -key $key -iv $iv $encrypted]
        return [expr {$data eq $decrypted}]
    } result]} {
        return "Error: $result"
    }
}

# Test first 5 ciphers
set ciphers [tossl::cipher::list]
set test_ciphers [lrange $ciphers 0 4]

foreach cipher $test_ciphers {
    set result [test_cipher_encryption $cipher]
    puts "$cipher: $result"
}
```

### With `::tossl::algorithm::list`

```tcl
# Compare with algorithm list
set cipher_algorithms [tossl::algorithm::list cipher]
set cipher_list [tossl::cipher::list]

puts "Algorithm list ciphers: [llength $cipher_algorithms]"
puts "Cipher list ciphers: [llength $cipher_list]"
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
   - **CCM Mode**: Authenticated encryption, suitable for constrained environments

3. **Key Management**: Always use appropriate key lengths and secure key generation

### Best Practices

1. **Cipher Validation**: Always validate cipher support before use
2. **Mode Selection**: Prefer authenticated encryption modes (GCM, CCM)
3. **Key Length**: Use appropriate key lengths for your security requirements
4. **Error Handling**: Handle cipher list failures gracefully

### Security Warnings

1. **ECB Mode**: Electronic Codebook mode is deterministic and may reveal patterns
2. **Weak Ciphers**: Avoid deprecated or weak cipher algorithms
3. **Key Reuse**: Never reuse keys for different purposes
4. **IV Reuse**: Never reuse initialization vectors with the same key

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's `EVP_CIPHER_do_all_provided()` function
2. **Provider Awareness**: Respects currently loaded OpenSSL providers
3. **Case Insensitive**: Type filtering is case-insensitive
4. **Memory Management**: Efficient memory usage with no leaks

### Performance Characteristics

- **Time Complexity**: O(n) where n is the number of available ciphers
- **Space Complexity**: O(n) for result storage
- **Memory Usage**: Minimal overhead beyond the result list

### Cipher Naming Convention

Ciphers are returned in OpenSSL's standard naming convention:
- **Algorithm-KeyLength-Mode** (e.g., "AES-128-CBC", "AES-256-GCM")
- **Case Sensitive**: Cipher names are case-sensitive
- **Standard Format**: Follows OpenSSL naming standards

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers

### Performance Benchmarks

Typical performance characteristics:
- **List retrieval**: ~1ms for 150+ ciphers
- **Type filtering**: ~1ms for filtered results
- **Memory usage**: Minimal overhead

## See Also

- `::tossl::cipher::analyze` - Analyze cipher properties
- `::tossl::cipher::info` - Get detailed cipher information
- `::tossl::encrypt` - Encrypt data using ciphers
- `::tossl::decrypt` - Decrypt data using ciphers
- `::tossl::algorithm::list` - List algorithms by type
- `::tossl::provider::list` - List available OpenSSL providers 