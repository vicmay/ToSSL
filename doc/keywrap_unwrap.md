# ::tossl::keywrap::unwrap

Unwrap data using a key encryption key (KEK).

## Overview

`::tossl::keywrap::unwrap` decrypts previously wrapped data using a key encryption key (KEK). This command is the counterpart to `::tossl::keywrap::wrap` and is used to recover the original data from wrapped/crypted data.



## Syntax

```
tossl::keywrap::unwrap algorithm kek_key wrapped_data
```

### Parameters

- **algorithm**: The key wrapping algorithm name (e.g., `aes-128-ecb`, `aes-256-cbc`)
- **kek_key**: The key encryption key used for unwrapping
- **wrapped_data**: The data to unwrap (previously wrapped using the same algorithm and KEK)

### Return Value

Returns the unwrapped data as a byte array. If unwrapping fails, an error is returned.

## Supported Algorithms

The following algorithms are supported for key unwrapping:

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

### Basic Unwrapping

```tcl
# Generate KEK and wrap data
set kek [tossl::keywrap::kekgen aes-256-cbc]
set original_data "Secret data to protect"
set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $original_data]

# Unwrap the data
set unwrapped_data [tossl::keywrap::unwrap aes-256-cbc $kek $wrapped_data]
puts "Successfully unwrapped: $unwrapped_data"
```

### Error Handling

```tcl
# Handle unwrap failures gracefully
proc safe_unwrap {algorithm kek wrapped_data} {
    if {[catch {
        set result [tossl::keywrap::unwrap $algorithm $kek $wrapped_data]
        return [dict create success 1 data $result]
    } err]} {
        return [dict create success 0 error $err]
    }
}

# Usage
set result [safe_unwrap aes-256-cbc $kek $wrapped_data]
if {[dict get $result success]} {
    puts "Unwrapped data: [dict get $result data]"
} else {
    puts "Unwrap failed: [dict get $result error]"
}
```

### Algorithm Validation

```tcl
# Validate algorithm before unwrapping
proc validate_and_unwrap {algorithm kek wrapped_data} {
    # Check if algorithm is supported
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
    } err]} {
        error "Algorithm '$algorithm' not supported: $err"
    }
    
    # Attempt unwrapping
    if {[catch {
        set unwrapped_data [tossl::keywrap::unwrap $algorithm $kek $wrapped_data]
        return $unwrapped_data
    } err]} {
        error "Unwrap failed: $err"
    }
}

# Usage
if {[catch {
    set unwrapped [validate_and_unwrap aes-256-cbc $kek $wrapped_data]
    puts "Successfully unwrapped: $unwrapped"
} err]} {
    puts "Error: $err"
}
```

### Complete Workflow Example

```tcl
# Complete key wrapping and unwrapping workflow
proc complete_key_wrapping_workflow {algorithm data} {
    # Step 1: Generate KEK
    set kek [tossl::keywrap::kekgen $algorithm]
    puts "Generated KEK: [string length $kek] bytes"
    
    # Step 2: Wrap the data
    set wrapped_data [tossl::keywrap::wrap $algorithm $kek $data]
    puts "Wrapped data: [string length $wrapped_data] bytes"
    
    # Step 3: Unwrap the data
    set unwrapped_data [tossl::keywrap::unwrap $algorithm $kek $wrapped_data]
    puts "Successfully unwrapped: $unwrapped_data"
    return [dict create success 1 kek $kek wrapped $wrapped_data unwrapped $unwrapped_data]
}

# Usage
set result [complete_key_wrapping_workflow aes-256-cbc "Test data"]
if {[dict get $result success]} {
    puts "Workflow completed successfully"
} else {
    puts "Workflow completed with unwrap failure"
}
```

## Error Handling

The command may return the following errors:

- **"Unsupported KEK algorithm"**: The specified algorithm is not supported
- **"Invalid wrapped data length"**: The wrapped data is too short or malformed
- **"Failed to create cipher context"**: OpenSSL cipher context creation failed
- **"Failed to initialize key unwrapping"**: Cipher initialization failed
- **"Failed to unwrap key"**: Decryption update failed
- **"Failed to finalize key unwrapping"**: Decryption finalization failed
- **"Memory allocation failed"**: System memory allocation failed

### Common Error Scenarios

```tcl
# Invalid algorithm
if {[catch {tossl::keywrap::unwrap invalid-algorithm $kek $wrapped_data} err]} {
    puts "Invalid algorithm error: $err"
}

# Wrong number of arguments
if {[catch {tossl::keywrap::unwrap} err]} {
    puts "No arguments error: $err"
}

# Too many arguments
if {[catch {tossl::keywrap::unwrap aes-256-cbc $kek $wrapped_data extra} err]} {
    puts "Too many arguments error: $err"
}

# Invalid wrapped data
if {[catch {tossl::keywrap::unwrap aes-256-cbc $kek "short"} err]} {
    puts "Invalid data error: $err"
}

# Wrong KEK
if {[catch {tossl::keywrap::unwrap aes-256-cbc $wrong_kek $wrapped_data} err]} {
    puts "Wrong KEK error: $err"
}
```

## Security Considerations

### Security Best Practices

1. **Key Management**: Store KEKs securely and separately from wrapped data
2. **Algorithm Selection**: Use strong algorithms (AES-256) for sensitive data
3. **Error Handling**: Always handle unwrap failures gracefully
4. **Data Validation**: Validate unwrapped data before use

## Integration with Other Commands

### Key Wrapping Workflow

```tcl
# Complete workflow with error handling
proc secure_key_workflow {algorithm sensitive_data} {
    # Step 1: Generate KEK
    set kek [tossl::keywrap::kekgen $algorithm]
    
    # Step 2: Wrap data
    set wrapped_data [tossl::keywrap::wrap $algorithm $kek $sensitive_data]
    
    # Step 3: Unwrap the data
    set unwrapped_data [tossl::keywrap::unwrap $algorithm $kek $wrapped_data]
    
    return [dict create \
        algorithm $algorithm \
        kek $kek \
        wrapped_data $wrapped_data \
        unwrapped_data $unwrapped_data]
}
```

### Algorithm Information Integration

```tcl
# Get algorithm information for unwrapping
proc get_unwrap_info {algorithm} {
    if {[catch {
        set info [tossl::keywrap::info $algorithm]
        return $info
    } err]} {
        error "Cannot get info for algorithm '$algorithm': $err"
    }
}

# Usage
set info [get_unwrap_info aes-256-cbc]
puts "Algorithm info: $info"
```

## See Also

- `::tossl::keywrap::info` - Get information about key wrapping algorithms
- `::tossl::keywrap::algorithms` - List available key wrapping algorithms
- `::tossl::keywrap::kekgen` - Generate key encryption keys
- `::tossl::keywrap::wrap` - Wrap data using a KEK
- `::tossl::encrypt` - General encryption operations
- `::tossl::decrypt` - General decryption operations

## Technical Notes

### Implementation Details

1. **OpenSSL Integration**: Uses OpenSSL's EVP cipher functions for decryption
2. **IV Extraction**: Attempts to extract initialization vector from wrapped data
3. **Memory Management**: Efficient memory allocation with proper cleanup
4. **Algorithm Validation**: Validates algorithm support before unwrapping

### Performance Characteristics

- **Time Complexity**: O(n) where n is the size of wrapped data
- **Space Complexity**: O(n) for result storage
- **Memory Usage**: Minimal overhead beyond the unwrapped data

### OpenSSL Compatibility

- **OpenSSL 1.1.1+**: Full compatibility
- **OpenSSL 3.0+**: Full compatibility
- **Algorithm Support**: Supports all AES variants available in the OpenSSL installation

 