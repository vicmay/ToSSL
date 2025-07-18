# ::tossl::legacy::info

Get information about a legacy cipher algorithm.

## Syntax

    tossl::legacy::info <algorithm>

- `<algorithm>`: The legacy cipher algorithm name (e.g., `des-cbc`, `bf-cbc`, `rc4`)

## Description

Returns detailed information about a legacy cipher algorithm, including its block size, key length, and IV length. This command is specifically designed for legacy/obsolete cipher algorithms that are not recommended for new applications but may be needed for compatibility with older systems.

## Output

Returns a Tcl list with key-value pairs containing:
- `name`: The algorithm name
- `block_size`: Block size in bytes
- `key_length`: Key length in bytes
- `iv_length`: IV length in bytes (0 for stream ciphers)

## Examples

### Basic Legacy Cipher Information

```tcl
# Get information about DES-CBC
set info [tossl::legacy::info "des-cbc"]

# Parse the result
for {set i 0} {$i < [llength $info]} {incr i 2} {
    set key [lindex $info $i]
    set value [lindex $info [expr {$i + 1}]]
    puts "$key: $value"
}
# Output:
# name: des-cbc
# block_size: 8
# key_length: 8
# iv_length: 8
```

### Information for Different Legacy Algorithms

```tcl
# DES in different modes
set des_ecb [tossl::legacy::info "des-ecb"]
set des_cbc [tossl::legacy::info "des-cbc"]
set des_cfb [tossl::legacy::info "des-cfb"]

# Blowfish
set blowfish [tossl::legacy::info "bf-cbc"]

# CAST5
set cast5 [tossl::legacy::info "cast5-cbc"]

# RC4 (stream cipher)
set rc4 [tossl::legacy::info "rc4"]
```

### Algorithm Validation

```tcl
proc validate_legacy_algorithm {algorithm} {
    set rc [catch {tossl::legacy::info $algorithm} info]
    if {$rc != 0} {
        puts "Algorithm '$algorithm' is not supported"
        return 0
    }
    
    # Extract key information
    set name ""
    set block_size 0
    set key_length 0
    set iv_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        
        switch $key {
            "name" { set name $value }
            "block_size" { set block_size $value }
            "key_length" { set key_length $value }
            "iv_length" { set iv_length $value }
        }
    }
    
    puts "Algorithm: $name"
    puts "Block size: $block_size bytes"
    puts "Key length: $key_length bytes"
    puts "IV length: $iv_length bytes"
    
    return 1
}

# Test various algorithms
set algorithms {"des-cbc" "bf-cbc" "rc4" "invalid-algorithm"}
foreach alg $algorithms {
    puts "\nValidating: $alg"
    validate_legacy_algorithm $alg
}
```

### Error Handling

```tcl
# Handle unsupported algorithms
set rc [catch {tossl::legacy::info "aes-256-gcm"} result]
if {$rc != 0} {
    puts "Error: $result"
    puts "Note: AES-256-GCM is not a legacy algorithm"
}

# Handle invalid algorithm names
set rc [catch {tossl::legacy::info "invalid-algorithm"} result]
if {$rc != 0} {
    puts "Error: $result"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::legacy::info
# Error: wrong # args: should be "tossl::legacy::info algorithm"
```

- If the algorithm is not supported or not available, an error is returned:

```tcl
tossl::legacy::info "invalid-algorithm"
# Error: Unsupported legacy cipher algorithm
```

- If the algorithm is not a legacy algorithm, an error is returned:

```tcl
tossl::legacy::info "aes-128-cbc"
# Error: Unsupported legacy cipher algorithm
```

## Supported Legacy Algorithms

The following legacy algorithms are typically supported (availability may vary by OpenSSL build):

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
- Consider using the `tossl::cipher::info` command for modern algorithm information
- Always use strong, randomly generated keys and IVs
- Implement proper key management and rotation

## Notes

- The command requires the OpenSSL legacy provider to be loaded
- Algorithm availability depends on the OpenSSL build configuration
- Some legacy algorithms may be disabled in hardened OpenSSL builds
- The command returns a list with key-value pairs rather than a dict for compatibility
- Block ciphers have positive IV lengths, while stream ciphers typically have IV length of 0 