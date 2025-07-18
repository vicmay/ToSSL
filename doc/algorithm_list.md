# ::tossl::algorithm::list

## Overview

The `::tossl::algorithm::list` command enumerates all available cryptographic algorithms of a specific type supported by the ToSSL extension. This command is useful for discovering algorithm capabilities, building algorithm selection interfaces, and validating algorithm availability before using them in cryptographic operations.

## Syntax

```tcl
::tossl::algorithm::list type
```

## Parameters

- **type** (required): The type/category of algorithms to list. Supported types include:
  - `digest` - Hash functions (e.g., SHA-256, MD5, SHA3-512)
  - `cipher` - Symmetric encryption algorithms (e.g., AES, DES, ChaCha20)
  - `mac` - Message Authentication Code algorithms (e.g., HMAC, CMAC)
  - `kdf` - Key Derivation Function algorithms (e.g., PBKDF2, Scrypt, Argon2)
  - `keyexch` - Key Exchange algorithms (e.g., ECDH, DH)
  - `signature` - Digital signature algorithms (e.g., RSA, DSA, ECDSA, Ed25519)
  - `asym_cipher` - Asymmetric encryption algorithms (e.g., RSA, SM2)

## Return Value

Returns a Tcl list containing the names of all available algorithms of the specified type. The list is empty if no algorithms of that type are available.

## Examples

### Basic Usage

```tcl
# List all available digest algorithms
set digests [tossl::algorithm::list digest]
puts "Available digest algorithms: $digests"

# List all available cipher algorithms
set ciphers [tossl::algorithm::list cipher]
puts "Available cipher algorithms: $ciphers"

# List all available MAC algorithms
set macs [tossl::algorithm::list mac]
puts "Available MAC algorithms: $macs"
```

### Algorithm Discovery

```tcl
# Discover available algorithms for each type
set types {digest cipher mac kdf keyexch signature asym_cipher}

foreach type $types {
    set algorithms [tossl::algorithm::list $type]
    puts "$type algorithms ([llength $algorithms]): $algorithms"
}
```

### Algorithm Validation

```tcl
# Check if specific algorithms are available
set required_digests {sha256 sha512}
set available_digests [tossl::algorithm::list digest]

foreach digest $required_digests {
    if {[lsearch $available_digests $digest] >= 0} {
        puts "$digest is available"
    } else {
        puts "$digest is NOT available"
    }
}
```

### Integration with algorithm::info

```tcl
# Get detailed information about each available algorithm
set algorithms [tossl::algorithm::list digest]

foreach algorithm $algorithms {
    set info [tossl::algorithm::info $algorithm digest]
    puts "$algorithm: $info"
}
```

## Error Handling

- **Missing arguments**: Returns an error if the `type` parameter is not provided
- **Invalid type**: Returns an error if the algorithm type is not supported
- **Empty arguments**: Returns an error if the type argument is an empty string

### Error Examples

```tcl
# Missing argument
tossl::algorithm::list
# Error: wrong # args: should be "tossl::algorithm::list type"

# Invalid type
tossl::algorithm::list invalid-type
# Error: Unknown algorithm type

# Empty argument
tossl::algorithm::list ""
# Error: Unknown algorithm type
```

## Security Considerations

### Algorithm Availability

- **Provider-dependent**: The list of available algorithms depends on which OpenSSL providers are loaded
- **Build-dependent**: Some algorithms may not be available in all OpenSSL builds
- **FIPS mode**: In FIPS mode, only FIPS-approved algorithms will be listed

### Best Practices

1. **Always validate**: Use `::tossl::algorithm::info` to verify algorithm availability before use
2. **Check provider status**: Ensure required providers are loaded before listing algorithms
3. **Handle empty results**: Be prepared for empty lists if no algorithms of the requested type are available
4. **Case sensitivity**: Algorithm names are case-sensitive in subsequent operations

### Example: Robust Algorithm Selection

```tcl
proc select_algorithm {type preferred_algorithms} {
    set available [tossl::algorithm::list $type]
    
    if {[llength $available] == 0} {
        error "No $type algorithms available"
    }
    
    # Try preferred algorithms first
    foreach alg $preferred_algorithms {
        if {[lsearch $available $alg] >= 0} {
            # Verify it's actually available
            set info [tossl::algorithm::info $alg $type]
            if {[string match "*status=available*" $info]} {
                return $alg
            }
        }
    }
    
    # Fall back to first available algorithm
    return [lindex $available 0]
}

# Usage
set cipher [select_algorithm cipher {aes-256-gcm aes-128-gcm aes-256-cbc}]
puts "Selected cipher: $cipher"
```

## Performance Considerations

- **Fast enumeration**: The command uses OpenSSL's efficient enumeration APIs
- **Cached results**: Consider caching results if called frequently with the same type
- **Large lists**: Cipher algorithms may return large lists (100+ algorithms)

### Performance Example

```tcl
# Cache algorithm lists for better performance
array set algorithm_cache {}

proc get_algorithms {type} {
    global algorithm_cache
    
    if {![info exists algorithm_cache($type)]} {
        set algorithm_cache($type) [tossl::algorithm::list $type]
    }
    
    return $algorithm_cache($type)
}
```

## Troubleshooting

### Common Issues

1. **Empty algorithm lists**
   - **Cause**: No providers loaded or no algorithms of that type available
   - **Solution**: Check provider status with `::tossl::provider::list`

2. **Missing expected algorithms**
   - **Cause**: OpenSSL build doesn't include certain algorithms
   - **Solution**: Verify OpenSSL build configuration

3. **Case sensitivity issues**
   - **Cause**: Algorithm names may have different case in different contexts
   - **Solution**: Use exact case as returned by this command

### Debugging Example

```tcl
# Debug algorithm availability
puts "Provider status:"
puts [tossl::provider::list]

puts "Algorithm availability:"
foreach type {digest cipher mac kdf keyexch signature asym_cipher} {
    set count [llength [tossl::algorithm::list $type]]
    puts "  $type: $count algorithms"
}
```

## Related Commands

- `::tossl::algorithm::info` - Get detailed information about a specific algorithm
- `::tossl::digest::list` - List available digest algorithms (alternative)
- `::tossl::cipher::list` - List available cipher algorithms (alternative)
- `::tossl::provider::list` - List loaded OpenSSL providers
- `::tossl::provider::load` - Load additional OpenSSL providers

## Implementation Notes

- **OpenSSL APIs**: Uses `EVP_MD_do_all_provided()` for digest algorithms and `EVP_CIPHER_do_all_provided()` for cipher algorithms
- **Hardcoded lists**: For algorithm types without direct OpenSSL enumeration APIs (mac, kdf, keyexch, signature, asym_cipher), returns predefined lists
- **Duplicate prevention**: Automatically removes duplicate algorithm names
- **Provider awareness**: Respects currently loaded OpenSSL providers

## Version Compatibility

- **OpenSSL 3.0+**: Full support for all algorithm types
- **Provider-based**: Algorithm availability depends on loaded providers
- **FIPS compatibility**: Works correctly in FIPS mode with appropriate providers 