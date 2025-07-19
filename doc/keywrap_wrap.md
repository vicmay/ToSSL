# ::tossl::keywrap::wrap

Wrap data using a key encryption key (KEK).

## Overview

`::tossl::keywrap::wrap` encrypts data using a key encryption key (KEK) to protect sensitive information. This command is the counterpart to `::tossl::keywrap::unwrap` and is used to secure data for storage or transmission. The wrapped data includes an initialization vector (IV) for CBC mode algorithms, making it suitable for secure key management operations.

Key wrapping is a fundamental cryptographic operation used in key management systems to protect other cryptographic keys or sensitive data. The wrapped data can only be recovered using the same KEK and algorithm.

## Syntax

```
tossl::keywrap::wrap algorithm kek_key data
```

### Parameters

- **algorithm**: The key wrapping algorithm name (e.g., `aes-128-ecb`, `aes-256-cbc`)
- **kek_key**: The key encryption key used for wrapping
- **data**: The data to wrap (can be any binary data)

### Return Value

Returns the wrapped data as a byte array. The wrapped data includes the initialization vector (for CBC mode) and the encrypted data.

## Supported Algorithms

The following algorithms are supported for key wrapping:

### AES Algorithms

| Algorithm | Key Length | Block Size | Mode | Security Level | IV Included |
|-----------|------------|------------|------|----------------|-------------|
| `aes-128-ecb` | 16 bytes | 16 bytes | ECB | Standard | No |
| `aes-192-ecb` | 24 bytes | 16 bytes | ECB | Good | No |
| `aes-256-ecb` | 32 bytes | 16 bytes | ECB | High | No |
| `aes-128-cbc` | 16 bytes | 16 bytes | CBC | Standard | Yes |
| `aes-192-cbc` | 24 bytes | 16 bytes | CBC | Good | Yes |
| `aes-256-cbc` | 32 bytes | 16 bytes | CBC | High | Yes |

## Examples

### Basic Wrapping

```tcl
# Generate KEK and wrap data
set kek [tossl::keywrap::kekgen aes-256-cbc]
set original_data "Secret data to protect"
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $original_data]

puts "Original data: $original_data"
puts "Wrapped data: [string length $wrapped_data] bytes"
```

### Complete Workflow

```tcl
# Complete wrap/unwrap cycle
set kek [tossl::keywrap::kekgen aes-256-cbc]
set sensitive_data "This is sensitive data that needs protection"

# Wrap the data
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $sensitive_data]
puts "Wrapped data: [string length $wrapped_data] bytes"

# Unwrap the data
set unwrapped_data [tossl::keywrap::unwrap aes-256-cbc $kek $wrapped_data]
puts "Successfully unwrapped: $unwrapped_data"
```

### Error Handling

```tcl
# Handle wrap failures gracefully
proc safe_wrap {algorithm kek data} {
    if {[catch {
        set result [tossl::keywrap::wrap $algorithm $kek $data]
        return [dict create success 1 data $result]
    } err]} {
        return [dict create success 0 error $err]
    }
}

# Usage
set result [safe_wrap aes-256-cbc $kek $sensitive_data]
if {[dict get $result success]} {
    puts "Wrapped data: [string length [dict get $result data]] bytes"
} else {
    puts "Wrap failed: [dict get $result error]"
}
```

### Algorithm Validation

```tcl
# Validate algorithm before wrapping
proc validate_and_wrap {algorithm kek data} {
    # Check if algorithm is supported
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
    } err]} {
        error "Algorithm '$algorithm' not supported: $err"
    }
    
    # Attempt wrapping
    if {[catch {
        set wrapped_data [tossl::keywrap::wrap $algorithm $kek $data]
        return $wrapped_data
    } err]} {
        error "Wrap failed: $err"
    }
}

# Usage
if {[catch {
    set wrapped [validate_and_wrap aes-256-cbc $kek $sensitive_data]
    puts "Successfully wrapped: [string length $wrapped] bytes"
} err]} {
    puts "Error: $err"
}
```

### Binary Data Handling

```tcl
# Wrap binary data
set kek [tossl::keywrap::kekgen aes-256-cbc]
set binary_data [binary format "cccc" 0x01 0x02 0x03 0x04]

set wrapped_binary [tossl::keywrap::wrap aes-256-cbc $kek $binary_data]
puts "Original binary: [binary encode hex $binary_data]"
puts "Wrapped binary: [string length $wrapped_binary] bytes"
```

### Large Data Handling

```tcl
# Wrap large amounts of data
set kek [tossl::keywrap::kekgen aes-256-cbc]
set large_data [string repeat "Large data block " 1000]

set wrapped_large [tossl::keywrap::wrap aes-256-cbc $kek $large_data]
puts "Original size: [string length $large_data] bytes"
puts "Wrapped size: [string length $wrapped_large] bytes"
```

### Algorithm Comparison

```tcl
# Compare different algorithms
proc compare_wrapping_algorithms {data} {
    set algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
    
    puts "Algorithm Comparison:"
    puts [format "%-15s %-10s %-15s %-10s" "Algorithm" "Key Size" "Wrapped Size" "Mode"]
    puts [string repeat "-" 60]
    
    foreach algorithm $algorithms {
        set kek [tossl::keywrap::kekgen $algorithm]
        set wrapped [tossl::keywrap::wrap $algorithm $kek $data]
        
        set key_size [string length $kek]
        set wrapped_size [string length $wrapped]
        
        if {[string match "*cbc*" $algorithm]} {
            set mode "CBC"
        } else {
            set mode "ECB"
        }
        
        puts [format "%-15s %-10s %-15s %-10s" $algorithm "${key_size}B" "${wrapped_size}B" $mode]
    }
}

# Usage
set test_data "Test data for algorithm comparison"
compare_wrapping_algorithms $test_data
```

### Security Best Practices

```tcl
# Secure key wrapping with proper validation
proc secure_key_wrapping {algorithm sensitive_data} {
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
    
    # Step 3: Wrap the data
    if {[catch {
        set wrapped_data [tossl::keywrap::wrap $algorithm $kek $sensitive_data]
        puts "Wrapped data: [string length $wrapped_data] bytes"
    } err]} {
        error "Failed to wrap data: $err"
    }
    
    return [dict create \
        algorithm $algorithm \
        algorithm_info $algorithm_info \
        kek $kek \
        wrapped_data $wrapped_data]
}

# Usage
set plaintext_key "my-secret-key-data"
set result [secure_key_wrapping "aes-256-cbc" $plaintext_key]
puts "Key wrapping completed successfully"
```

### Performance Testing

```tcl
# Test wrapping performance
proc test_wrapping_performance {algorithm data_size iterations} {
    set kek [tossl::keywrap::kekgen $algorithm]
    set test_data [string repeat "A" $data_size]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set wrapped [tossl::keywrap::wrap $algorithm $kek $test_data]
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "Performance test for $algorithm:"
    puts "  Data size: $data_size bytes"
    puts "  Iterations: $iterations"
    puts "  Total time: ${duration}ms"
    puts "  Average time per wrap: [expr {double($duration) / $iterations}]ms"
    puts "  Throughput: [expr {double($iterations * $data_size) / $duration}] bytes/ms"
}

# Usage
test_wrapping_performance aes-256-cbc 1024 100
```

## Error Handling

The following errors may be returned:

- **"Unsupported KEK algorithm"**: The specified algorithm is not supported
- **"Failed to generate random IV"**: Failed to generate initialization vector
- **"Failed to create cipher context"**: Failed to create OpenSSL cipher context
- **"Failed to initialize key wrapping"**: Failed to initialize encryption
- **"Failed to wrap key"**: Failed during encryption process
- **"Failed to finalize key wrapping"**: Failed to finalize encryption
- **"Memory allocation failed"**: System memory allocation failed
- **"wrong # args"**: Incorrect number of arguments provided

## Integration with Other Commands

### With `::tossl::keywrap::kekgen`

```tcl
# Generate KEK and wrap data
set kek [tossl::keywrap::kekgen aes-256-cbc]
set sensitive_data "Data to protect"
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $sensitive_data]
```

### With `::tossl::keywrap::unwrap`

```tcl
# Complete wrap/unwrap cycle
set kek [tossl::keywrap::kekgen aes-256-cbc]
set original_data "Secret data"

# Wrap
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $original_data]

# Unwrap
set unwrapped_data [tossl::keywrap::unwrap aes-256-cbc $kek $wrapped_data]

# Verify
if {$original_data eq $unwrapped_data} {
    puts "Wrap/unwrap cycle successful"
} else {
    puts "Wrap/unwrap cycle failed"
}
```

### With `::tossl::keywrap::info`

```tcl
# Get algorithm information before wrapping
set algorithm "aes-256-cbc"
set info [tossl::keywrap::info $algorithm]
puts "Algorithm info: $info"

set kek [tossl::keywrap::kekgen $algorithm]
set wrapped_data [tossl::keywrap::wrap $algorithm $kek "test data"]
```

### With `::tossl::keywrap::algorithms`

```tcl
# Wrap data with all available algorithms
set algorithms [tossl::keywrap::algorithms]
set test_data "Test data"

foreach algorithm $algorithms {
    set kek [tossl::keywrap::kekgen $algorithm]
    set wrapped [tossl::keywrap::wrap $algorithm $kek $test_data]
    puts "$algorithm: [string length $wrapped] bytes"
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
   - **CBC Mode**: More secure, requires IV (automatically generated)

3. **Key Management**: Always store KEKs securely and separately from wrapped data

### Best Practices

1. **Algorithm Validation**: Always validate algorithm support before use
2. **Error Handling**: Handle wrap failures gracefully
3. **Key Generation**: Use `::tossl::keywrap::kekgen` for secure KEK generation
4. **Data Validation**: Validate data before and after wrapping
5. **Memory Management**: Be aware that wrapped data may be larger than original

### Security Warnings

1. **ECB Mode**: Electronic Codebook mode is deterministic and may reveal patterns
2. **Key Reuse**: Never reuse KEKs for different purposes
3. **Key Storage**: Store KEKs securely, separate from wrapped data
4. **Data Size**: Be aware that wrapped data includes IV and padding

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions for encryption
2. **IV Generation**: Automatically generates cryptographically secure IVs for CBC mode
3. **Memory Management**: Efficient memory allocation with proper cleanup
4. **Algorithm Validation**: Validates algorithm support before wrapping

### Performance Characteristics

- **Time Complexity**: O(n) where n is the size of data to wrap
- **Space Complexity**: O(n) for result storage
- **Memory Usage**: Minimal overhead beyond the wrapped data

### Data Format

The wrapped data format depends on the algorithm:

- **ECB Mode**: Encrypted data only
- **CBC Mode**: IV (16 bytes) + encrypted data

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Algorithm Support**: Supports all AES variants available in the OpenSSL installation

### Performance Benchmarks

Typical performance characteristics:

- **AES-256-CBC**: ~1-2ms per 1KB of data
- **AES-128-ECB**: ~0.5-1ms per 1KB of data
- **Memory Overhead**: ~16 bytes for CBC mode (IV), minimal for ECB mode

## See Also

- `::tossl::keywrap::unwrap` - Unwrap data using a KEK
- `::tossl::keywrap::kekgen` - Generate key encryption keys
- `::tossl::keywrap::info` - Get information about key wrapping algorithms
- `::tossl::keywrap::algorithms` - List available key wrapping algorithms
- `::tossl::encrypt` - General encryption operations
- `::tossl::decrypt` - General decryption operations 