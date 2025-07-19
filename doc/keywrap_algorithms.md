# ::tossl::keywrap::algorithms

List available key wrapping algorithms.

## Overview

`::tossl::keywrap::algorithms` returns a list of all available key wrapping algorithms supported by the TOSSL library. This command is useful for discovering available algorithms, building algorithm selection interfaces, and validating algorithm availability before using them in key wrapping operations.

Key wrapping algorithms are symmetric encryption algorithms used to protect other cryptographic keys. The algorithms returned by this command can be used with other key wrapping commands such as `::tossl::keywrap::kekgen`, `::tossl::keywrap::wrap`, and `::tossl::keywrap::unwrap`.

## Syntax

```
tossl::keywrap::algorithms
```

### Parameters

This command takes no parameters.

### Return Value

Returns a Tcl list containing the names of all available key wrapping algorithms. The list is empty if no algorithms are available.

## Supported Algorithms

The following algorithms are currently supported:

### AES Algorithms

| Algorithm | Key Length | Block Size | Mode | Security Level | IV Required |
|-----------|------------|------------|------|----------------|-------------|
| `aes-128-ecb` | 16 bytes | 16 bytes | ECB | Standard | No |
| `aes-192-ecb` | 24 bytes | 16 bytes | ECB | Good | No |
| `aes-256-ecb` | 32 bytes | 16 bytes | ECB | High | No |
| `aes-128-cbc` | 16 bytes | 16 bytes | CBC | Standard | Yes |
| `aes-192-cbc` | 24 bytes | 16 bytes | CBC | Good | Yes |
| `aes-256-cbc` | 32 bytes | 16 bytes | CBC | High | Yes |

## Examples

### Basic Usage

```tcl
# Get list of available algorithms
set algorithms [tossl::keywrap::algorithms]
puts "Available key wrapping algorithms: $algorithms"

# Output: Available key wrapping algorithms: aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc
```

### Algorithm Discovery

```tcl
# Discover and display algorithm information
set algorithms [tossl::keywrap::algorithms]
puts "Found [llength $algorithms] key wrapping algorithms:"

foreach algorithm $algorithms {
    set info [tossl::keywrap::info $algorithm]
    puts "  $algorithm: $info"
}
```

### Algorithm Selection

```tcl
# Select algorithm based on requirements
proc select_algorithm {security_level mode} {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        if {[string match "*$security_level*" $algorithm] && 
            [string match "*$mode*" $algorithm]} {
            return $algorithm
        }
    }
    
    error "No algorithm found matching security level '$security_level' and mode '$mode'"
}

# Usage examples
set high_security_cbc [select_algorithm "256" "cbc"]
puts "Selected high security CBC algorithm: $high_security_cbc"

set standard_ecb [select_algorithm "128" "ecb"]
puts "Selected standard ECB algorithm: $standard_ecb"
```

### Algorithm Validation

```tcl
# Validate algorithm availability
proc is_algorithm_available {algorithm_name} {
    set algorithms [tossl::keywrap::algorithms]
    return [expr {[lsearch $algorithms $algorithm_name] != -1}]
}

# Usage
if {[is_algorithm_available "aes-256-cbc"]} {
    puts "AES-256-CBC is available"
} else {
    puts "AES-256-CBC is not available"
}
```

### Complete Key Wrapping Workflow

```tcl
# Complete workflow using algorithm discovery
proc secure_key_wrapping {data security_level} {
    # Step 1: Get available algorithms
    set algorithms [tossl::keywrap::algorithms]
    
    # Step 2: Select appropriate algorithm
    set selected_algorithm ""
    foreach algorithm $algorithms {
        if {[string match "*$security_level*" $algorithm]} {
            set selected_algorithm $algorithm
            break
        }
    }
    
    if {$selected_algorithm eq ""} {
        error "No algorithm found for security level '$security_level'"
    }
    
    puts "Selected algorithm: $selected_algorithm"
    
    # Step 3: Generate KEK
    set kek [tossl::keywrap::kekgen $selected_algorithm]
    puts "Generated KEK: [string length $kek] bytes"
    
    # Step 4: Wrap data
    set wrapped_data [tossl::keywrap::wrap $selected_algorithm $kek $data]
    puts "Wrapped data: [string length $wrapped_data] bytes"
    
    return [dict create \
        algorithm $selected_algorithm \
        kek $kek \
        wrapped_data $wrapped_data]
}

# Usage
set sensitive_data "This is sensitive data that needs protection"
set result [secure_key_wrapping $sensitive_data "256"]
puts "Key wrapping completed successfully"
```

### Algorithm Comparison

```tcl
# Compare algorithm properties
proc compare_algorithms {} {
    set algorithms [tossl::keywrap::algorithms]
    
    puts "Algorithm Comparison:"
    puts [format "%-15s %-10s %-10s %-8s %-15s" "Algorithm" "Key Size" "Block Size" "Mode" "Security Level"]
    puts [string repeat "-" 70]
    
    foreach algorithm $algorithms {
        set info [tossl::keywrap::info $algorithm]
        
        # Parse info string
        if {[regexp {key_length (\d+)} $info -> key_length] &&
            [regexp {block_size (\d+)} $info -> block_size]} {
            
            # Determine security level
            if {[string match "*256*" $algorithm]} {
                set security "High"
            } elseif {[string match "*192*" $algorithm]} {
                set security "Good"
            } else {
                set security "Standard"
            }
            
            # Determine mode
            if {[string match "*cbc*" $algorithm]} {
                set mode "CBC"
            } else {
                set mode "ECB"
            }
            
            puts [format "%-15s %-10s %-10s %-8s %-15s" \
                $algorithm "${key_length}B" "${block_size}B" $mode $security]
        }
    }
}

# Usage
compare_algorithms
```

### Error Handling

```tcl
# Handle algorithm discovery errors
if {[catch {
    set algorithms [tossl::keywrap::algorithms]
    puts "Available algorithms: $algorithms"
} err]} {
    puts "Error discovering algorithms: $err"
    exit 1
}

# Validate algorithm list
if {![llength $algorithms]} {
    puts "Warning: No key wrapping algorithms available"
} else {
    puts "Found [llength $algorithms] key wrapping algorithms"
}
```

### Performance Testing

```tcl
# Test algorithm discovery performance
proc test_algorithm_discovery_performance {iterations} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set algorithms [tossl::keywrap::algorithms]
        if {![llength $algorithms]} {
            error "Empty algorithms list on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "Completed $iterations algorithm discoveries in ${duration}ms"
    puts "Average time per discovery: [expr {double($duration) / $iterations}]ms"
}

# Usage
test_algorithm_discovery_performance 1000
```

## Error Handling

- **No errors**: This command does not return errors under normal circumstances
- **Empty list**: Returns an empty list if no algorithms are available
- **Argument errors**: Returns an error if arguments are provided (command takes no arguments)

## Integration with Other Commands

### With `::tossl::keywrap::info`

```tcl
# Get detailed information for all algorithms
set algorithms [tossl::keywrap::algorithms]
foreach algorithm $algorithms {
    set info [tossl::keywrap::info $algorithm]
    puts "$algorithm: $info"
}
```

### With `::tossl::keywrap::kekgen`

```tcl
# Generate KEKs for all available algorithms
set algorithms [tossl::keywrap::algorithms]
foreach algorithm $algorithms {
    set kek [tossl::keywrap::kekgen $algorithm]
    puts "$algorithm: [string length $kek] byte KEK"
}
```

### With `::tossl::keywrap::wrap` and `::tossl::keywrap::unwrap`

```tcl
# Test wrap/unwrap cycle for all algorithms
set algorithms [tossl::keywrap::algorithms]
set test_data "Test data for algorithm validation"

foreach algorithm $algorithms {
    if {[catch {
        set kek [tossl::keywrap::kekgen $algorithm]
        set wrapped [tossl::keywrap::wrap $algorithm $kek $test_data]
        set unwrapped [tossl::keywrap::unwrap $algorithm $kek $wrapped]
        
        if {$test_data eq $unwrapped} {
            puts "✓ $algorithm: Wrap/unwrap cycle successful"
        } else {
            puts "✗ $algorithm: Wrap/unwrap cycle failed"
        }
    } err]} {
        puts "✗ $algorithm: Error during wrap/unwrap cycle: $err"
    }
}
```

## Security Considerations

### Algorithm Selection

1. **Security Level**: Choose appropriate security level for your use case
   - 128-bit: Standard security (suitable for most applications)
   - 192-bit: Good security (suitable for sensitive data)
   - 256-bit: High security (suitable for highly sensitive data)

2. **Mode Selection**:
   - **ECB Mode**: Simpler but less secure, no IV required
   - **CBC Mode**: More secure, requires IV

3. **Key Management**: Always store KEKs securely and separately from wrapped data

### Best Practices

1. **Algorithm Validation**: Always validate algorithm availability before use
2. **Error Handling**: Handle cases where no algorithms are available
3. **Performance**: Consider performance implications when selecting algorithms
4. **Compatibility**: Ensure algorithm compatibility across different systems

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions
2. **Algorithm Discovery**: Direct mapping to supported OpenSSL ciphers
3. **Memory Management**: Efficient memory usage with no leaks
4. **Performance**: Fast algorithm lookup with minimal overhead

### Performance Characteristics

- **Time Complexity**: O(1) for algorithm list retrieval
- **Space Complexity**: O(n) where n is the number of algorithms
- **Memory Usage**: Minimal overhead beyond the result list

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Algorithm Support**: Supports all AES variants available in the OpenSSL installation

### Algorithm Availability

The availability of algorithms depends on:

1. **OpenSSL Version**: Different versions support different algorithms
2. **Build Configuration**: Some algorithms may be disabled during build
3. **System Requirements**: Hardware acceleration may affect availability
4. **Security Policies**: Some systems may restrict certain algorithms

## See Also

- `::tossl::keywrap::info` - Get information about key wrapping algorithms
- `::tossl::keywrap::kekgen` - Generate key encryption keys
- `::tossl::keywrap::wrap` - Wrap data using a KEK
- `::tossl::keywrap::unwrap` - Unwrap data using a KEK
- `::tossl::algorithm::list` - List algorithms by type
- `::tossl::algorithm::info` - Get information about algorithms 