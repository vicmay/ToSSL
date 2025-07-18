# ::tossl::pbe::algorithms

## Overview

The `::tossl::pbe::algorithms` command returns a list of supported hash algorithms that can be used with Password-Based Encryption (PBE) operations. This command is essential for discovering available algorithms, validating algorithm names, and building dynamic PBE applications that can adapt to the available cryptographic capabilities of the system.

## Syntax

```tcl
::tossl::pbe::algorithms
```

## Parameters

This command takes no parameters.

## Return Value

Returns a Tcl list containing the names of supported hash algorithms that can be used with PBE operations.

## Examples

### Basic Usage

```tcl
# Get list of supported PBE algorithms
set algorithms [tossl::pbe::algorithms]
puts "Supported algorithms: $algorithms"
puts "Number of algorithms: [llength $algorithms]"
```

### Algorithm Discovery

```tcl
# Discover available algorithms
set available_algorithms [tossl::pbe::algorithms]

puts "Available PBE algorithms:"
foreach algorithm $available_algorithms {
    puts "  - $algorithm"
}
```

### Algorithm Validation

```tcl
# Validate if a specific algorithm is supported
proc is_algorithm_supported {algorithm_name} {
    set supported [tossl::pbe::algorithms]
    return [expr {[lsearch $supported $algorithm_name] != -1}]
}

# Usage examples
set test_algorithms {sha256 sha512 sha1 md5 invalid-algorithm}

foreach algorithm $test_algorithms {
    if {[is_algorithm_supported $algorithm]} {
        puts "$algorithm: Supported"
    } else {
        puts "$algorithm: Not supported"
    }
}
```

### Dynamic Algorithm Selection

```tcl
# Select the best available algorithm
proc select_best_algorithm {} {
    set algorithms [tossl::pbe::algorithms]
    
    # Prefer SHA-512, then SHA-256, then SHA-1, then MD5
    set preferred_order {sha512 sha256 sha1 md5}
    
    foreach preferred $preferred_order {
        if {[lsearch $algorithms $preferred] != -1} {
            return $preferred
        }
    }
    
    # Fallback to first available algorithm
    return [lindex $algorithms 0]
}

set best_alg [select_best_algorithm]
puts "Selected algorithm: $best_alg"
```

### Algorithm Security Classification

```tcl
# Classify algorithms by security level
proc classify_algorithms {} {
    set algorithms [tossl::pbe::algorithms]
    set secure {}
    set legacy {}
    
    foreach algorithm $algorithms {
        switch $algorithm {
            "sha256" - "sha512" {
                lappend secure $algorithm
            }
            "sha1" - "md5" {
                lappend legacy $algorithm
            }
            default {
                puts "Unknown algorithm: $algorithm"
            }
        }
    }
    
    return [list $secure $legacy]
}

set classification [classify_algorithms]
set secure_algorithms [lindex $classification 0]
set legacy_algorithms [lindex $classification 1]

puts "Secure algorithms: $secure_algorithms"
puts "Legacy algorithms: $legacy_algorithms"
```

### Integration with PBE Operations

```tcl
# Use returned algorithms with PBE operations
set algorithms [tossl::pbe::algorithms]
set password "test_password"
set salt [tossl::pbe::saltgen 16]
set data "Test data"

puts "Testing each algorithm with PBE operations:"
foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    
    # Test with pbe::keyderive
    set rc1 [catch {tossl::pbe::keyderive $algorithm $password $salt 1000 32} key]
    if {$rc1 == 0} {
        puts "  pbe::keyderive: OK"
    } else {
        puts "  pbe::keyderive: FAILED - $key"
    }
    
    # Test with pbe::encrypt
    set rc2 [catch {tossl::pbe::encrypt $algorithm $password $salt $data} encrypted]
    if {$rc2 == 0} {
        puts "  pbe::encrypt: OK"
    } else {
        puts "  pbe::encrypt: FAILED - $encrypted"
    }
}
```

### Algorithm Performance Testing

```tcl
# Test performance of different algorithms
proc benchmark_algorithms {} {
    set algorithms [tossl::pbe::algorithms]
    set password "test_password"
    set salt [tossl::pbe::saltgen 16]
    set iterations 1000
    
    puts "Algorithm Performance Benchmark:"
    puts "================================"
    
    foreach algorithm $algorithms {
        set start_time [clock milliseconds]
        
        # Run multiple iterations for accurate timing
        for {set i 0} {$i < 100} {incr i} {
            set rc [catch {tossl::pbe::keyderive $algorithm $password $salt $iterations 32} result]
            if {$rc != 0} {
                puts "  $algorithm: FAILED - $result"
                continue
            }
        }
        
        set end_time [clock milliseconds]
        set duration [expr {$end_time - $start_time}]
        
        puts "  $algorithm: ${duration}ms for 100 operations"
    }
}

benchmark_algorithms
```

### Algorithm Availability Check

```tcl
# Check if specific algorithms are available
proc check_algorithm_availability {required_algorithms} {
    set available [tossl::pbe::algorithms]
    set missing {}
    set found {}
    
    foreach required $required_algorithms {
        if {[lsearch $available $required] != -1} {
            lappend found $required
        } else {
            lappend missing $required
        }
    }
    
    return [list $found $missing]
}

# Example usage
set required {sha256 sha512 sha1 md5}
set result [check_algorithm_availability $required]
set found [lindex $result 0]
set missing [lindex $result 1]

puts "Found algorithms: $found"
puts "Missing algorithms: $missing"

if {[llength $missing] > 0} {
    puts "WARNING: Some required algorithms are not available"
}
```

### Deterministic Results

```tcl
# Verify that results are deterministic
set result1 [tossl::pbe::algorithms]
set result2 [tossl::pbe::algorithms]

if {$result1 eq $result2} {
    puts "Results are deterministic: OK"
} else {
    puts "WARNING: Results are not deterministic"
    puts "First call: $result1"
    puts "Second call: $result2"
}
```

### Algorithm Sorting and Ordering

```tcl
# Check if algorithms are returned in sorted order
set algorithms [tossl::pbe::algorithms]
set sorted [lsort $algorithms]

if {$algorithms eq $sorted} {
    puts "Algorithms are returned in sorted order"
} else {
    puts "Algorithms are not returned in sorted order"
    puts "Original order: $algorithms"
    puts "Sorted order: $sorted"
}
```

## Error Handling

- **Extra arguments**: Returns an error if any arguments are provided
- **No arguments**: Works correctly (this is the expected usage)

### Error Examples

```tcl
# Extra arguments (will fail)
tossl::pbe::algorithms extra_arg
# Error: wrong # args: should be "tossl::pbe::algorithms"

# Multiple arguments (will fail)
tossl::pbe::algorithms arg1 arg2
# Error: wrong # args: should be "tossl::pbe::algorithms"

# No arguments (works correctly)
tossl::pbe::algorithms
# Returns: sha1 sha256 sha512 md5
```

## Security Considerations

### Algorithm Security Levels

- **SHA-256/SHA-512**: Modern, secure algorithms recommended for new applications
- **SHA-1**: Legacy algorithm, avoid for new applications
- **MD5**: Legacy algorithm, avoid for new applications

### Algorithm Selection Guidelines

```tcl
proc select_secure_algorithm {} {
    set algorithms [tossl::pbe::algorithms]
    
    # Prefer SHA-512 for maximum security
    if {[lsearch $algorithms "sha512"] != -1} {
        return "sha512"
    }
    
    # Fallback to SHA-256
    if {[lsearch $algorithms "sha256"] != -1} {
        return "sha256"
    }
    
    # Only use legacy algorithms if nothing else is available
    if {[lsearch $algorithms "sha1"] != -1} {
        puts "WARNING: Using legacy SHA-1 algorithm"
        return "sha1"
    }
    
    if {[lsearch $algorithms "md5"] != -1} {
        puts "WARNING: Using legacy MD5 algorithm"
        return "md5"
    }
    
    error "No suitable algorithms available"
}
```

## Performance Considerations

### Algorithm Performance Characteristics

- **SHA-256**: Fast, good balance of security and performance
- **SHA-512**: Slightly slower but higher security
- **SHA-1**: Fastest but less secure
- **MD5**: Fastest but least secure

### Performance Testing

```tcl
proc performance_test {iterations} {
    set algorithms [tossl::pbe::algorithms]
    set password "test_password"
    set salt [tossl::pbe::saltgen 16]
    
    puts "Performance test with $iterations iterations per algorithm:"
    
    foreach algorithm $algorithms {
        set start_time [clock milliseconds]
        
        for {set i 0} {$i < $iterations} {incr i} {
            tossl::pbe::keyderive $algorithm $password $salt 1000 32
        }
        
        set end_time [clock milliseconds]
        set duration [expr {$end_time - $start_time}]
        set ops_per_sec [expr {($iterations * 1000.0) / $duration}]
        
        puts "  $algorithm: ${duration}ms (${ops_per_sec:.1f} ops/sec)"
    }
}

# Run performance test
performance_test 100
```

## Best Practices

### 1. Always Check Available Algorithms

```tcl
# Good: Check what's available before using
set algorithms [tossl::pbe::algorithms]
if {[lsearch $algorithms "sha256"] == -1} {
    error "SHA-256 not available on this system"
}
set key [tossl::pbe::keyderive sha256 $password $salt 1000 32]

# Avoid: Assume specific algorithms are available
set key [tossl::pbe::keyderive sha256 $password $salt 1000 32] ;# May fail
```

### 2. Use Secure Algorithm Selection

```tcl
# Good: Select the most secure available algorithm
proc get_secure_algorithm {} {
    set algorithms [tossl::pbe::algorithms]
    foreach preferred {sha512 sha256 sha1 md5} {
        if {[lsearch $algorithms $preferred] != -1} {
            return $preferred
        }
    }
    error "No suitable algorithms available"
}

# Avoid: Always use a specific algorithm
set algorithm "sha256" ;# May not be available
```

### 3. Validate Algorithm Names

```tcl
# Good: Validate algorithm names before use
proc validate_algorithm {algorithm_name} {
    set supported [tossl::pbe::algorithms]
    if {[lsearch $supported $algorithm_name] == -1} {
        error "Algorithm '$algorithm_name' not supported. Available: $supported"
    }
    return $algorithm_name
}

# Usage
set algorithm [validate_algorithm "sha256"]
```

### 4. Handle Algorithm Availability Gracefully

```tcl
# Good: Graceful fallback when preferred algorithms aren't available
proc select_algorithm_with_fallback {preferred_algorithms} {
    set available [tossl::pbe::algorithms]
    
    foreach preferred $preferred_algorithms {
        if {[lsearch $available $preferred] != -1} {
            return $preferred
        }
    }
    
    # Fallback to first available
    set fallback [lindex $available 0]
    puts "WARNING: Using fallback algorithm: $fallback"
    return $fallback
}
```

## Troubleshooting

### Common Issues

1. **"wrong # args" error**
   - **Cause**: Providing arguments to the command
   - **Solution**: Call without any arguments: `tossl::pbe::algorithms`

2. **Empty result list**
   - **Cause**: No algorithms are available in the OpenSSL build
   - **Solution**: Check OpenSSL installation and provider configuration

3. **Algorithm not found in result**
   - **Cause**: Algorithm not supported by the current OpenSSL build
   - **Solution**: Use one of the returned algorithms or check OpenSSL configuration

### Debugging Example

```tcl
proc debug_algorithms {} {
    puts "Debugging PBE algorithms:"
    
    set rc [catch {tossl::pbe::algorithms} result]
    if {$rc != 0} {
        puts "  Error: $result"
        return
    }
    
    puts "  Available algorithms: $result"
    puts "  Number of algorithms: [llength $result]"
    
    foreach algorithm $result {
        puts "  Testing $algorithm..."
        
        # Test basic functionality
        set rc [catch {tossl::pbe::keyderive $algorithm "test" "salt" 1000 32} err]
        if {$rc == 0} {
            puts "    $algorithm: OK"
        } else {
            puts "    $algorithm: FAILED - $err"
        }
    }
}
```

## Related Commands

- `::tossl::pbe::keyderive` - Derive keys using PBKDF2 with specified algorithm
- `::tossl::pbe::encrypt` - Encrypt data using password-based encryption
- `::tossl::pbe::decrypt` - Decrypt data using password-based encryption
- `::tossl::pbe::saltgen` - Generate random salts for PBE operations
- `::tossl::digest::list` - List available digest algorithms
- `::tossl::algorithm::list` - List available algorithms in general

## Implementation Notes

- **OpenSSL API**: Uses `EVP_get_digestbyname()` to verify algorithm availability
- **Algorithm List**: Hardcoded list of PBE algorithms: sha1, sha256, sha512, md5
- **Availability Check**: Only returns algorithms that are actually available in the OpenSSL build
- **Return Format**: Returns a Tcl list of algorithm names as strings
- **Deterministic**: Returns the same result on multiple calls
- **No Parameters**: Command takes no arguments

## Version Compatibility

- **OpenSSL 3.0+**: Full support for all algorithms
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers
- **Legacy support**: Includes older algorithms for compatibility

## Algorithm Details

### Supported Algorithms

| Algorithm | Security Level | Performance | Recommendation |
|-----------|----------------|-------------|----------------|
| SHA-512   | High          | Medium      | Best for high security |
| SHA-256   | High          | Fast        | Recommended for most uses |
| SHA-1     | Low           | Very Fast   | Legacy only |
| MD5       | Very Low      | Fastest     | Legacy only |

### Algorithm Characteristics

- **SHA-512**: 512-bit output, highest security, slightly slower
- **SHA-256**: 256-bit output, high security, good performance
- **SHA-1**: 160-bit output, legacy, fast but cryptographically broken
- **MD5**: 128-bit output, legacy, fast but cryptographically broken

### Usage Recommendations

```tcl
# For new applications
set algorithm "sha256"  ;# Good balance of security and performance

# For high-security applications
set algorithm "sha512"  ;# Maximum security

# For legacy compatibility only
set algorithm "sha1"    ;# Avoid for new code
set algorithm "md5"     ;# Avoid for new code
``` 