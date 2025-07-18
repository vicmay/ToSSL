# ::tossl::algorithm::info

## Overview

The `::tossl::algorithm::info` command provides detailed information about cryptographic algorithms supported by the ToSSL extension. This command is useful for discovering algorithm capabilities, validating algorithm availability, and understanding algorithm properties before using them in cryptographic operations.

## Syntax

```tcl
::tossl::algorithm::info algorithm type
```

## Parameters

- **algorithm** (required): The name of the cryptographic algorithm
- **type** (required): The type/category of the algorithm. Supported types include:
  - `digest` - Hash functions (e.g., SHA-256, MD5)
  - `cipher` - Symmetric encryption algorithms (e.g., AES, DES)
  - `mac` - Message Authentication Code algorithms (e.g., HMAC, CMAC)
  - `kdf` - Key Derivation Function algorithms (e.g., PBKDF2, Scrypt)
  - `keyexch` - Key Exchange algorithms (e.g., ECDH, DH)
  - `signature` - Digital signature algorithms (e.g., RSA, ECDSA)
  - `asym_cipher` - Asymmetric encryption algorithms (e.g., RSA, SM2)

## Returns

Returns a formatted string containing algorithm information in the format:
```
algorithm=<name>, type=<type>, status=<status>
```

Where:
- `<name>` is the algorithm name as provided
- `<type>` is the algorithm type as provided
- `<status>` indicates availability (typically "available")

## Examples

### Basic Usage

```tcl
# Get information about SHA-256 digest algorithm
set info [tossl::algorithm::info "sha256" "digest"]
puts "SHA-256 info: $info"
# Output: SHA-256 info: algorithm=sha256, type=digest, status=available

# Get information about AES-128-CBC cipher
set info [tossl::algorithm::info "aes-128-cbc" "cipher"]
puts "AES-128-CBC info: $info"
# Output: AES-128-CBC info: algorithm=aes-128-cbc, type=cipher, status=available
```

### Algorithm Discovery

```tcl
# Discover available digest algorithms
set digest_algorithms {
    "md5" "sha1" "sha224" "sha256" "sha384" "sha512"
    "sha3-224" "sha3-256" "sha3-384" "sha3-512"
    "blake2b256" "blake2b512" "blake2s256"
}

foreach algorithm $digest_algorithms {
    set rc [catch {set info [tossl::algorithm::info $algorithm "digest"]} err]
    if {$rc == 0} {
        puts "✓ $algorithm: $info"
    } else {
        puts "✗ $algorithm: Not available"
    }
}
```

### Cipher Algorithm Information

```tcl
# Check various cipher algorithms
set cipher_algorithms {
    "aes-128-cbc" "aes-256-cbc" "aes-128-gcm" "aes-256-gcm"
    "chacha20-poly1305" "des-cbc" "bf-cbc"
}

foreach algorithm $cipher_algorithms {
    set rc [catch {set info [tossl::algorithm::info $algorithm "cipher"]} err]
    if {$rc == 0} {
        puts "✓ $algorithm: $info"
    } else {
        puts "✗ $algorithm: Not available"
    }
}
```

### Algorithm Validation Function

```tcl
proc validate_algorithm {algorithm type} {
    set rc [catch {set info [tossl::algorithm::info $algorithm $type]} err]
    if {$rc != 0} {
        puts "Algorithm '$algorithm' of type '$type' is not available"
        puts "Error: $err"
        return 0
    }
    
    puts "Algorithm '$algorithm' of type '$type' is available"
    puts "Info: $info"
    return 1
}

# Test various algorithm combinations
set test_cases {
    {"sha256" "digest"}
    {"aes-128-cbc" "cipher"}
    {"hmac" "mac"}
    {"pbkdf2" "kdf"}
    {"ecdh" "keyexch"}
    {"rsa" "signature"}
    {"rsa" "asym_cipher"}
}

foreach {algorithm type} $test_cases {
    validate_algorithm $algorithm $type
}
```

### Integration with Algorithm List

```tcl
# Get all available algorithms of a specific type
proc get_available_algorithms {type} {
    set rc [catch {set algorithm_list [tossl::algorithm::list $type]} err]
    if {$rc != 0} {
        puts "Failed to get algorithm list for type '$type': $err"
        return {}
    }
    
    set algorithms [split $algorithm_list ", "]
    set available {}
    
    foreach algorithm $algorithms {
        set algorithm [string trim $algorithm]
        if {[string length $algorithm] > 0} {
            set rc [catch {tossl::algorithm::info $algorithm $type} err]
            if {$rc == 0} {
                lappend available $algorithm
            }
        }
    }
    
    return $available
}

# Get all available digest algorithms
set available_digests [get_available_algorithms "digest"]
puts "Available digest algorithms: $available_digests"

# Get all available cipher algorithms
set available_ciphers [get_available_algorithms "cipher"]
puts "Available cipher algorithms: $available_ciphers"
```

### Algorithm Type Validation

```tcl
# Validate algorithm type before use
proc is_valid_algorithm_type {type} {
    set valid_types {
        "digest" "cipher" "mac" "kdf" "keyexch" "signature" "asym_cipher"
    }
    
    return [expr {[lsearch $valid_types $type] >= 0}]
}

proc safe_algorithm_info {algorithm type} {
    if {![is_valid_algorithm_type $type]} {
        puts "Error: Invalid algorithm type '$type'"
        puts "Valid types: digest, cipher, mac, kdf, keyexch, signature, asym_cipher"
        return ""
    }
    
    set rc [catch {set info [tossl::algorithm::info $algorithm $type]} err]
    if {$rc != 0} {
        puts "Error getting info for '$algorithm' of type '$type': $err"
        return ""
    }
    
    return $info
}

# Test with valid and invalid types
puts [safe_algorithm_info "sha256" "digest"]
puts [safe_algorithm_info "sha256" "invalid_type"]
```

### Error Handling

```tcl
# Handle missing arguments
set rc [catch {tossl::algorithm::info} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}

set rc [catch {tossl::algorithm::info "sha256"} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}

# Handle invalid algorithm names
set rc [catch {tossl::algorithm::info "invalid-algorithm" "digest"} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}

# Handle invalid algorithm types
set rc [catch {tossl::algorithm::info "sha256" "invalid-type"} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}

# Handle empty arguments
set rc [catch {tossl::algorithm::info "" "digest"} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}

set rc [catch {tossl::algorithm::info "sha256" ""} err]
if {$rc != 0} {
    puts "Error (expected): $err"
}
```

## Error Handling

- **Missing arguments**: Returns an error if either `algorithm` or `type` is not provided
- **Invalid algorithm**: Returns an error if the algorithm is not recognized
- **Invalid type**: Returns an error if the algorithm type is not supported
- **Empty arguments**: Returns an error if either argument is an empty string

### Common Error Messages

```tcl
# Wrong number of arguments
tossl::algorithm::info
# Error: wrong # args: should be "tossl::algorithm::info algorithm type"

# Missing second argument
tossl::algorithm::info "sha256"
# Error: wrong # args: should be "tossl::algorithm::info algorithm type"

# Invalid algorithm or type
tossl::algorithm::info "invalid-algorithm" "digest"
# Error: Algorithm not found or not available
```

## Security Considerations

1. **Algorithm Validation**: Always validate algorithm availability before using it in cryptographic operations
2. **Algorithm Strength**: This command only provides availability information, not security strength assessment
3. **Deprecated Algorithms**: Some algorithms (like MD5, SHA-1) may be available but are cryptographically weak
4. **Provider Dependencies**: Algorithm availability depends on loaded OpenSSL providers

## Best Practices

1. **Check Availability First**: Always verify algorithm availability before attempting to use it
2. **Handle Errors Gracefully**: Implement proper error handling for cases where algorithms are not available
3. **Use Type Validation**: Validate algorithm types before passing them to the command
4. **Cache Results**: For performance-critical applications, consider caching algorithm availability information
5. **Fallback Strategies**: Implement fallback strategies when preferred algorithms are not available

## Troubleshooting

### Algorithm Not Found

```tcl
# If an algorithm is not found, check if it's available in the current OpenSSL build
set rc [catch {tossl::algorithm::info "sha3-256" "digest"} err]
if {$rc != 0} {
    puts "SHA3-256 not available in this OpenSSL build"
    puts "Consider using SHA-256 as an alternative"
}
```

### Provider Issues

```tcl
# Check if required providers are loaded
set rc [catch {tossl::provider::list} providers]
if {$rc == 0} {
    puts "Loaded providers: $providers"
} else {
    puts "Failed to get provider list"
}
```

### Case Sensitivity

```tcl
# Algorithm names are typically case-sensitive
set rc1 [catch {tossl::algorithm::info "SHA256" "digest"} err1]
set rc2 [catch {tossl::algorithm::info "sha256" "digest"} err2]

if {$rc1 != 0 && $rc2 == 0} {
    puts "Note: Algorithm names are case-sensitive"
    puts "Use lowercase: sha256, not SHA256"
}
```

## Related Commands

- `::tossl::algorithm::list` - List available algorithms of a specific type
- `::tossl::provider::list` - List loaded OpenSSL providers
- `::tossl::provider::load` - Load additional OpenSSL providers
- `::tossl::digest` - Compute hash digests
- `::tossl::encrypt` - Encrypt data using symmetric ciphers
- `::tossl::decrypt` - Decrypt data using symmetric ciphers

## Performance Notes

- The command is lightweight and fast for single algorithm queries
- For bulk algorithm checking, consider using `::tossl::algorithm::list` first
- Performance may vary depending on the number of loaded OpenSSL providers

## Version Compatibility

- This command is available in ToSSL version 0.1 and later
- Algorithm availability depends on the underlying OpenSSL version
- Some algorithms may require specific OpenSSL builds or providers 