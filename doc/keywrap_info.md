# ::tossl::keywrap::info

Get information about key wrapping algorithms.

## Overview

`::tossl::keywrap::info` retrieves detailed information about key wrapping algorithms supported by the TOSSL library. The command provides information about algorithm properties including name, block size, key length, and initialization vector (IV) length. This is useful for understanding algorithm capabilities, validating algorithm parameters, and making informed decisions about key wrapping operations.

## Syntax

```
tossl::keywrap::info algorithm
```

### Parameters

- **algorithm**: Name of the key wrapping algorithm (e.g., "aes-128-ecb", "aes-256-cbc")

### Return Value

Returns a string containing algorithm information in the format:
`name <algorithm_name> block_size <size> key_length <length> iv_length <length>`

## Example

```tcl
# Get information about AES-128-ECB
set aes128ecb_info [tossl::keywrap::info aes-128-ecb]
puts "AES-128-ECB info: $aes128ecb_info"

# Get information about AES-256-CBC
set aes256cbc_info [tossl::keywrap::info aes-256-cbc]
puts "AES-256-CBC info: $aes256cbc_info"

# Get information about AES-192-ECB
set aes192ecb_info [tossl::keywrap::info aes-192-ecb]
puts "AES-192-ECB info: $aes192ecb_info"
```

## Supported Algorithms

### AES Algorithms

#### AES-128-ECB
- **Name**: AES-128-ECB
- **Block Size**: 16 bytes
- **Key Length**: 16 bytes
- **IV Length**: 0 bytes (ECB mode doesn't use IV)

```tcl
set info [tossl::keywrap::info aes-128-ecb]
puts $info
# Output: name AES-128-ECB block_size 16 key_length 16 iv_length 0
```

#### AES-192-ECB
- **Name**: AES-192-ECB
- **Block Size**: 16 bytes
- **Key Length**: 24 bytes
- **IV Length**: 0 bytes

```tcl
set info [tossl::keywrap::info aes-192-ecb]
puts $info
# Output: name AES-192-ECB block_size 16 key_length 24 iv_length 0
```

#### AES-256-ECB
- **Name**: AES-256-ECB
- **Block Size**: 16 bytes
- **Key Length**: 32 bytes
- **IV Length**: 0 bytes

```tcl
set info [tossl::keywrap::info aes-256-ecb]
puts $info
# Output: name AES-256-ECB block_size 16 key_length 32 iv_length 0
```

#### AES-128-CBC
- **Name**: AES-128-CBC
- **Block Size**: 16 bytes
- **Key Length**: 16 bytes
- **IV Length**: 16 bytes

```tcl
set info [tossl::keywrap::info aes-128-cbc]
puts $info
# Output: name AES-128-CBC block_size 16 key_length 16 iv_length 16
```

#### AES-192-CBC
- **Name**: AES-192-CBC
- **Block Size**: 16 bytes
- **Key Length**: 24 bytes
- **IV Length**: 16 bytes

```tcl
set info [tossl::keywrap::info aes-192-cbc]
puts $info
# Output: name AES-192-CBC block_size 16 key_length 24 iv_length 16
```

#### AES-256-CBC
- **Name**: AES-256-CBC
- **Block Size**: 16 bytes
- **Key Length**: 32 bytes
- **IV Length**: 16 bytes

```tcl
set info [tossl::keywrap::info aes-256-cbc]
puts $info
# Output: name AES-256-CBC block_size 16 key_length 32 iv_length 16
```

## Error Handling

- Returns an error if no algorithm is provided
- Returns an error if the algorithm is not supported
- Returns an error if the algorithm name is invalid or malformed

## Advanced Usage

### Algorithm Information Analysis

```tcl
# Analyze algorithm properties
proc analyze_algorithm {algorithm} {
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
        
        # Parse the information
        if {[regexp {name ([A-Z0-9-]+)} $info -> name]} {
            puts "Algorithm: $name"
        }
        
        if {[regexp {block_size (\d+)} $info -> block_size]} {
            puts "Block Size: $block_size bytes"
        }
        
        if {[regexp {key_length (\d+)} $info -> key_length]} {
            puts "Key Length: $key_length bytes"
        }
        
        if {[regexp {iv_length (\d+)} $info -> iv_length]} {
            puts "IV Length: $iv_length bytes"
        }
        
        # Determine mode
        if {$iv_length == 0} {
            puts "Mode: ECB (Electronic Codebook)"
        } else {
            puts "Mode: CBC (Cipher Block Chaining)"
        }
        
        # Security assessment
        if {$key_length >= 32} {
            puts "Security Level: High (256-bit key)"
        } elseif {$key_length >= 24} {
            puts "Security Level: Medium (192-bit key)"
        } else {
            puts "Security Level: Standard (128-bit key)"
        }
        
    } err]} {
        puts "Error analyzing algorithm '$algorithm': $err"
    }
}

# Usage
analyze_algorithm "aes-256-cbc"
```

### Batch Algorithm Analysis

```tcl
# Analyze multiple algorithms
proc analyze_algorithms {algorithms} {
    set analysis {}
    foreach algorithm $algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            lappend analysis [dict create \
                algorithm $algorithm \
                info $info \
                success true]
        } err]} {
            lappend analysis [dict create \
                algorithm $algorithm \
                error $err \
                success false]
        }
    }
    return $analysis
}

# Usage
set algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
set results [analyze_algorithms $algorithms]
foreach result $results {
    if {[dict get $result success]} {
        puts "[dict get $result algorithm]: [dict get $result info]"
    } else {
        puts "[dict get $result algorithm]: ERROR - [dict get $result error]"
    }
}
```

### Algorithm Comparison

```tcl
# Compare algorithm properties
proc compare_algorithms {algorithm1 algorithm2} {
    if {[catch {
        set info1 [tossl::keywrap::info $algorithm1]
        set info2 [tossl::keywrap::info $algorithm2]
        
        puts "Comparison: $algorithm1 vs $algorithm2"
        puts "=" * 50
        
        # Extract properties
        regexp {block_size (\d+)} $info1 -> block_size1
        regexp {key_length (\d+)} $info1 -> key_length1
        regexp {iv_length (\d+)} $info1 -> iv_length1
        
        regexp {block_size (\d+)} $info2 -> block_size2
        regexp {key_length (\d+)} $info2 -> key_length2
        regexp {iv_length (\d+)} $info2 -> iv_length2
        
        puts "Block Size: $block_size1 vs $block_size2 bytes"
        puts "Key Length: $key_length1 vs $key_length2 bytes"
        puts "IV Length: $iv_length1 vs $iv_length2 bytes"
        
        # Security comparison
        if {$key_length1 > $key_length2} {
            puts "Security: $algorithm1 has stronger key"
        } elseif {$key_length2 > $key_length1} {
            puts "Security: $algorithm2 has stronger key"
        } else {
            puts "Security: Both have same key strength"
        }
        
        # Mode comparison
        if {$iv_length1 == 0 && $iv_length2 > 0} {
            puts "Mode: $algorithm1 is ECB, $algorithm2 is CBC"
        } elseif {$iv_length1 > 0 && $iv_length2 == 0} {
            puts "Mode: $algorithm1 is CBC, $algorithm2 is ECB"
        } else {
            puts "Mode: Both use same mode"
        }
        
    } err]} {
        puts "Error comparing algorithms: $err"
    }
}

# Usage
compare_algorithms "aes-128-ecb" "aes-256-cbc"
```

### Algorithm Selection Helper

```tcl
# Helper to select appropriate algorithm based on requirements
proc select_algorithm {requirements} {
    set min_key_length [dict get $requirements min_key_length]
    set mode [dict get $requirements mode]
    set algorithms [dict get $requirements algorithms]
    
    set candidates {}
    foreach algorithm $algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            
            regexp {key_length (\d+)} $info -> key_length
            regexp {iv_length (\d+)} $info -> iv_length
            
            set algorithm_mode "unknown"
            if {$iv_length == 0} {
                set algorithm_mode "ecb"
            } else {
                set algorithm_mode "cbc"
            }
            
            if {$key_length >= $min_key_length && ($mode eq "any" || $algorithm_mode eq $mode)} {
                lappend candidates [dict create \
                    algorithm $algorithm \
                    key_length $key_length \
                    mode $algorithm_mode \
                    info $info]
            }
        } err]} {
            # Skip unsupported algorithms
        }
    }
    
    # Sort by key length (prefer stronger keys)
    set candidates [lsort -index 1 -integer -decreasing $candidates]
    
    if {[llength $candidates] > 0} {
        return [dict get [lindex $candidates 0] algorithm]
    } else {
        return ""
    }
}

# Usage
set requirements [dict create \
    min_key_length 24 \
    mode "cbc" \
    algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}]

set selected [select_algorithm $requirements]
if {$selected ne ""} {
    puts "Selected algorithm: $selected"
    puts "Info: [tossl::keywrap::info $selected]"
} else {
    puts "No suitable algorithm found"
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized cipher information functions
- **Memory Management**: Minimal memory overhead
- **Fast Lookup**: Direct algorithm name to cipher mapping
- **Consistent Results**: Same algorithm always returns same information

### Performance Monitoring

```tcl
# Monitor algorithm info performance
proc benchmark_algorithm_info {iterations algorithms} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach algorithm $algorithms {
            set result [tossl::keywrap::info $algorithm]
            if {![string match "*name*" $result]} {
                error "Invalid result for $algorithm"
            }
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set total_operations [expr {$iterations * [llength $algorithms]}]
    set avg_time [expr {double($total_time) / $total_operations}]
    
    return [dict create \
        total_time $total_time \
        total_operations $total_operations \
        average_time $avg_time \
        operations_per_second [expr {double($total_operations) * 1000 / $total_time}]]
}

# Usage
set test_algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
set benchmark [benchmark_algorithm_info 25 $test_algorithms]
puts "Average info time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Key Wrapping Workflow

```tcl
# Complete key wrapping workflow with algorithm validation
proc secure_key_wrap {algorithm plaintext_key} {
    # Step 1: Validate algorithm
    if {[catch {
        set algorithm_info [tossl::keywrap::info $algorithm]
        puts "Using algorithm: $algorithm_info"
    } err]} {
        error "Invalid algorithm '$algorithm': $err"
    }
    
    # Step 2: Generate KEK
    if {[catch {
        set kek [tossl::keywrap::kekgen $algorithm]
        puts "Generated KEK: [string length $kek] bytes"
    } err]} {
        error "Failed to generate KEK: $err"
    }
    
    # Step 3: Wrap the key
    if {[catch {
        set wrapped_key [tossl::keywrap::wrap $algorithm $kek $plaintext_key]
        puts "Wrapped key: [string length $wrapped_key] bytes"
    } err]} {
        error "Failed to wrap key: $err"
    }
    
    return [dict create \
        algorithm $algorithm \
        algorithm_info $algorithm_info \
        kek $kek \
        wrapped_key $wrapped_key]
}

# Usage
set plaintext_key "my-secret-key-data"
set result [secure_key_wrap "aes-256-cbc" $plaintext_key]
puts "Key wrapping completed successfully"
```

### Algorithm Validation

```tcl
# Validate algorithm before use
proc validate_algorithm_for_keywrap {algorithm key_length} {
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
        
        # Extract key length requirement
        regexp {key_length (\d+)} $info -> required_key_length
        
        # Check if algorithm can handle the key
        if {$key_length > $required_key_length} {
            return [dict create \
                valid false \
                reason "Key length $key_length exceeds algorithm limit $required_key_length"]
        }
        
        # Check for ECB mode (less secure)
        regexp {iv_length (\d+)} $info -> iv_length
        if {$iv_length == 0} {
            return [dict create \
                valid true \
                warning "Using ECB mode - consider CBC for better security"]
        }
        
        return [dict create valid true]
        
    } err]} {
        return [dict create \
            valid false \
            reason "Algorithm validation failed: $err"]
    }
}

# Usage
set validation [validate_algorithm_for_keywrap "aes-128-ecb" 16]
if {[dict get $validation valid]} {
    if {[dict exists $validation warning]} {
        puts "Warning: [dict get $validation warning]"
    }
    puts "Algorithm is valid for key wrapping"
} else {
    puts "Algorithm is invalid: [dict get $validation reason]"
}
```

### Security Assessment

```tcl
# Assess algorithm security
proc assess_algorithm_security {algorithm} {
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
        
        regexp {key_length (\d+)} $info -> key_length
        regexp {iv_length (\d+)} $info -> iv_length
        
        set security_score 0
        set recommendations {}
        
        # Key length assessment
        if {$key_length >= 32} {
            incr security_score 3
            lappend recommendations "Strong 256-bit key"
        } elseif {$key_length >= 24} {
            incr security_score 2
            lappend recommendations "Good 192-bit key"
        } elseif {$key_length >= 16} {
            incr security_score 1
            lappend recommendations "Standard 128-bit key"
        } else {
            lappend recommendations "Weak key length - consider stronger algorithm"
        }
        
        # Mode assessment
        if {$iv_length > 0} {
            incr security_score 2
            lappend recommendations "Uses CBC mode (more secure than ECB)"
        } else {
            lappend recommendations "Uses ECB mode - consider CBC for better security"
        }
        
        # Overall assessment
        if {$security_score >= 4} {
            set level "High"
        } elseif {$security_score >= 2} {
            set level "Medium"
        } else {
            set level "Low"
        }
        
        return [dict create \
            algorithm $algorithm \
            security_score $security_score \
            security_level $level \
            recommendations $recommendations \
            info $info]
        
    } err]} {
        return [dict create \
            algorithm $algorithm \
            error $err]
    }
}

# Usage
set assessment [assess_algorithm_security "aes-256-cbc"]
if {[dict exists $assessment error]} {
    puts "Assessment failed: [dict get $assessment error]"
} else {
    puts "Security Assessment for [dict get $assessment algorithm]:"
    puts "  Level: [dict get $assessment security_level]"
    puts "  Score: [dict get $assessment security_score]/5"
    puts "  Recommendations:"
    foreach rec [dict get $assessment recommendations] {
        puts "    - $rec"
    }
}
```

## Troubleshooting

### Common Issues

1. **"Unsupported KEK algorithm" error**
   - Check that the algorithm name is spelled correctly
   - Verify the algorithm is supported by your OpenSSL version
   - Use `tossl::keywrap::algorithms` to see available algorithms

2. **"wrong # args" error**
   - Ensure exactly one argument is provided (the algorithm name)
   - Check argument syntax

3. **Case sensitivity issues**
   - Algorithm names are case-insensitive
   - Both "aes-128-ecb" and "AES-128-ECB" work

4. **Algorithm not found**
   - Some algorithms may not be available in all OpenSSL builds
   - Check with `tossl::keywrap::algorithms` for available options

### Debug Information

```tcl
# Debug algorithm information retrieval
proc debug_algorithm_info {algorithm} {
    puts "Debug: Getting info for algorithm '$algorithm'"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::keywrap::info $algorithm]
        set end_time [clock milliseconds]
        
        puts "Debug: Info retrieval successful"
        puts "Debug: Retrieval time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Result: $result"
        
        # Validate result format
        if {[string match "*name*" $result] && 
            [string match "*block_size*" $result] && 
            [string match "*key_length*" $result] && 
            [string match "*iv_length*" $result]} {
            puts "Debug: Result has valid format"
        } else {
            puts "Debug: Result may not have valid format"
        }
        
        # Extract and validate values
        if {[regexp {name ([A-Z0-9-]+)} $result -> name]} {
            puts "Debug: Algorithm name: $name"
        }
        
        if {[regexp {block_size (\d+)} $result -> block_size]} {
            puts "Debug: Block size: $block_size bytes"
        }
        
        if {[regexp {key_length (\d+)} $result -> key_length]} {
            puts "Debug: Key length: $key_length bytes"
        }
        
        if {[regexp {iv_length (\d+)} $result -> iv_length]} {
            puts "Debug: IV length: $iv_length bytes"
        }
        
        return $result
    } err]} {
        puts "Debug: Info retrieval failed: $err"
        return ""
    }
}

# Usage
set result [debug_algorithm_info "aes-128-ecb"]
puts "Final result: $result"
```

## Algorithm Properties Reference

### Supported Algorithms Summary

| Algorithm | Block Size | Key Length | IV Length | Mode | Security Level |
|-----------|------------|------------|-----------|------|----------------|
| AES-128-ECB | 16 bytes | 16 bytes | 0 bytes | ECB | Standard |
| AES-192-ECB | 16 bytes | 24 bytes | 0 bytes | ECB | Good |
| AES-256-ECB | 16 bytes | 32 bytes | 0 bytes | ECB | High |
| AES-128-CBC | 16 bytes | 16 bytes | 16 bytes | CBC | Standard |
| AES-192-CBC | 16 bytes | 24 bytes | 16 bytes | CBC | Good |
| AES-256-CBC | 16 bytes | 32 bytes | 16 bytes | CBC | High |

### Return Value Format

The command returns information in the following format:
`name <algorithm_name> block_size <size> key_length <length> iv_length <length>`

### Field Descriptions

- **name**: The canonical name of the algorithm
- **block_size**: Size of the cipher block in bytes
- **key_length**: Required key length in bytes
- **iv_length**: Required initialization vector length in bytes (0 for ECB mode)

### Security Considerations

1. **Key Length**: Longer keys provide better security
   - 128-bit (16 bytes): Standard security
   - 192-bit (24 bytes): Good security
   - 256-bit (32 bytes): High security

2. **Mode Selection**: 
   - **ECB Mode**: Simpler but less secure, no IV required
   - **CBC Mode**: More secure, requires IV

3. **Algorithm Strength**: AES is a well-vetted standard algorithm

## See Also

- `::tossl::keywrap::algorithms` - List available key wrapping algorithms
- `::tossl::keywrap::kekgen` - Generate key encryption keys
- `::tossl::keywrap::wrap` - Wrap keys using KEK
- `::tossl::keywrap::unwrap` - Unwrap keys using KEK
- `::tossl::encrypt` - General encryption operations
- `::tossl::decrypt` - General decryption operations

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions
2. **Algorithm Lookup**: Direct mapping from algorithm name to cipher
3. **Information Extraction**: Retrieves cipher properties via OpenSSL APIs
4. **Memory Management**: Efficient memory usage with no leaks

### Performance Characteristics

- **Time Complexity**: O(1) for algorithm lookup
- **Space Complexity**: O(1) for result storage
- **Memory Usage**: Minimal overhead beyond result string

### OpenSSL Compatibility

- **Standard Algorithms**: Supports all standard AES variants
- **OpenSSL Version**: Compatible with OpenSSL 1.1.1 and later
- **Provider Support**: Works with default and legacy providers

### Algorithm Naming

- **Case Insensitive**: Algorithm names are case-insensitive
- **Standard Names**: Uses OpenSSL standard algorithm names
- **Consistent Format**: Returns canonical uppercase names 