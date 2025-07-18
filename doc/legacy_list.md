# ::tossl::legacy::list

List all available legacy cipher algorithms.

## Syntax

    tossl::legacy::list

- No arguments.

## Description

Returns a Tcl list of all legacy cipher algorithms that are available in the current OpenSSL build. This command is specifically designed to list legacy/obsolete cipher algorithms that are not recommended for new applications but may be needed for compatibility with older systems.

The command checks for the availability of each legacy algorithm and only includes those that are actually supported by the OpenSSL legacy provider.

## Output

Returns a Tcl list containing the names of available legacy cipher algorithms, e.g.:

```
des-ecb des-cbc des-cfb des-ofb bf-cbc cast5-cbc rc4
```

## Examples

### Basic Usage

```tcl
# Get list of all available legacy algorithms
set algorithms [tossl::legacy::list]
puts "Available legacy algorithms: $algorithms"
```

### Iterating Through Legacy Algorithms

```tcl
# Get and iterate through available legacy algorithms
set algorithms [tossl::legacy::list]
foreach alg $algorithms {
    puts "Found legacy algorithm: $alg"
}
```

### Checking for Specific Legacy Algorithms

```tcl
# Check if specific legacy algorithms are available
set algorithms [tossl::legacy::list]

if {[lsearch -exact $algorithms "des-cbc"] >= 0} {
    puts "DES-CBC is available"
} else {
    puts "DES-CBC is not available"
}

if {[lsearch -exact $algorithms "bf-cbc"] >= 0} {
    puts "Blowfish-CBC is available"
} else {
    puts "Blowfish-CBC is not available"
}
```

### Algorithm Validation

```tcl
# Validate that returned algorithms are actually supported
set algorithms [tossl::legacy::list]
set valid_algorithms {}

foreach alg $algorithms {
    set rc [catch {tossl::legacy::info $alg} info]
    if {$rc == 0} {
        lappend valid_algorithms $alg
        puts "✓ $alg is valid"
    } else {
        puts "✗ $alg is not valid: $info"
    }
}

puts "Valid algorithms: $valid_algorithms"
```

### Legacy Algorithm Discovery

```tcl
# Discover what types of legacy algorithms are available
set algorithms [tossl::legacy::list]

set des_algorithms {}
set blowfish_algorithms {}
set cast5_algorithms {}
set rc4_algorithms {}
set rc5_algorithms {}

foreach alg $algorithms {
    if {[string match "des-*" $alg]} {
        lappend des_algorithms $alg
    } elseif {[string match "bf-*" $alg]} {
        lappend blowfish_algorithms $alg
    } elseif {[string match "cast5-*" $alg]} {
        lappend cast5_algorithms $alg
    } elseif {[string match "rc4*" $alg]} {
        lappend rc4_algorithms $alg
    } elseif {[string match "rc5-*" $alg]} {
        lappend rc5_algorithms $alg
    }
}

puts "DES algorithms: $des_algorithms"
puts "Blowfish algorithms: $blowfish_algorithms"
puts "CAST5 algorithms: $cast5_algorithms"
puts "RC4 algorithms: $rc4_algorithms"
puts "RC5 algorithms: $rc5_algorithms"
```

### Compatibility Checking

```tcl
# Check compatibility with legacy systems
proc check_legacy_compatibility {required_algorithms} {
    set available [tossl::legacy::list]
    set missing {}
    set available_count 0
    
    foreach required $required_algorithms {
        if {[lsearch -exact $available $required] >= 0} {
            incr available_count
            puts "✓ $required is available"
        } else {
            lappend missing $required
            puts "✗ $required is missing"
        }
    }
    
    set compatibility_rate [expr {double($available_count) / [llength $required_algorithms] * 100}]
    puts "Compatibility rate: $compatibility_rate%"
    
    if {[llength $missing] > 0} {
        puts "Missing algorithms: $missing"
        return 0
    }
    
    return 1
}

# Example usage
set required_legacy {
    "des-cbc"
    "bf-cbc"
    "rc4"
}

if {[check_legacy_compatibility $required_legacy]} {
    puts "System is compatible with legacy requirements"
} else {
    puts "System is NOT compatible with legacy requirements"
}
```

## Error Handling

- If extra arguments are provided, an error is returned:

```tcl
tossl::legacy::list extra
# Error: wrong # args: should be "tossl::legacy::list "
```

- The command will return an empty list if no legacy algorithms are available:

```tcl
set algorithms [tossl::legacy::list]
if {[llength $algorithms] == 0} {
    puts "No legacy algorithms available"
}
```

## Expected Legacy Algorithms

The following legacy algorithms are typically available (availability may vary by OpenSSL build):

### DES (Data Encryption Standard)
- `des-ecb` - DES in ECB mode
- `des-cbc` - DES in CBC mode
- `des-cfb` - DES in CFB mode
- `des-ofb` - DES in OFB mode
- `des-ede` - DES-EDE (2-key triple DES)
- `des-ede-cbc` - DES-EDE in CBC mode
- `des-ede3` - DES-EDE3 (3-key triple DES)
- `des-ede3-cbc` - DES-EDE3 in CBC mode

### Blowfish
- `bf-ecb` - Blowfish in ECB mode
- `bf-cbc` - Blowfish in CBC mode
- `bf-cfb` - Blowfish in CFB mode
- `bf-ofb` - Blowfish in OFB mode

### CAST5
- `cast5-ecb` - CAST5 in ECB mode
- `cast5-cbc` - CAST5 in CBC mode
- `cast5-cfb` - CAST5 in CFB mode
- `cast5-ofb` - CAST5 in OFB mode

### RC4/RC5
- `rc4` - RC4 stream cipher
- `rc4-40` - RC4 with 40-bit key
- `rc5-ecb` - RC5 in ECB mode
- `rc5-cbc` - RC5 in CBC mode
- `rc5-cfb` - RC5 in CFB mode
- `rc5-ofb` - RC5 in OFB mode

## Security Notes

⚠️ **WARNING: Legacy algorithms are considered cryptographically weak and should not be used for new applications.**

- **DES**: Considered cryptographically broken due to its small key size (56 bits)
- **Blowfish**: While not broken, it has a small block size (64 bits) making it vulnerable to birthday attacks
- **CAST5**: Similar issues to Blowfish with small block size
- **RC4**: Known vulnerabilities and should not be used
- **RC5**: Not recommended for new applications

### When to Use Legacy Algorithms

Legacy algorithms should only be used for:
- Interoperability with legacy systems
- Decrypting old data that was encrypted with these algorithms
- Testing and educational purposes
- Compliance with specific legacy requirements

### Recommendations

- Use modern algorithms like AES-256-GCM, ChaCha20-Poly1305, or AES-256-CBC for new applications
- Migrate away from legacy algorithms as soon as possible
- Consider using the `tossl::cipher::list` command for modern algorithm information
- Always use strong, randomly generated keys and IVs
- Implement proper key management and rotation

## Notes

- The command requires the OpenSSL legacy provider to be loaded
- Algorithm availability depends on the OpenSSL build configuration
- Some legacy algorithms may be disabled in hardened OpenSSL builds
- The command only returns algorithms that are actually available and functional
- The list may be empty if no legacy algorithms are supported in the current build
- Use `tossl::legacy::info <algorithm>` to get detailed information about specific algorithms 