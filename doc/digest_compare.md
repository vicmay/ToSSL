# ::tossl::digest::compare

## Overview

The `::tossl::digest::compare` command performs secure comparison of two hash digest values. This command is essential for verifying data integrity, checking file authenticity, and validating cryptographic signatures. The comparison is done in a constant-time manner to prevent timing attacks.

## Syntax

```tcl
::tossl::digest::compare hash1 hash2
```

## Parameters

- **hash1** (required): The first hash value to compare. Can be any string representing a hash digest.
- **hash2** (required): The second hash value to compare. Can be any string representing a hash digest.

## Returns

Returns a boolean value:
- **1** if the hashes are identical
- **0** if the hashes are different

## Examples

### Basic Usage

```tcl
# Compare two identical hashes
set hash1 [tossl::digest -alg sha256 "Hello, World!"]
set hash2 [tossl::digest -alg sha256 "Hello, World!"]
set result [tossl::digest::compare $hash1 $hash2]
puts "Hashes match: $result"
# Output: Hashes match: 1

# Compare different hashes
set hash3 [tossl::digest -alg sha256 "Different data"]
set result [tossl::digest::compare $hash1 $hash3]
puts "Hashes match: $result"
# Output: Hashes match: 0
```

### File Integrity Verification

```tcl
# Verify file integrity
set original_hash [tossl::digest::stream -alg sha256 -file "document.pdf"]
puts "Original hash: $original_hash"

# Later, verify the file hasn't changed
set current_hash [tossl::digest::stream -alg sha256 -file "document.pdf"]
if {[tossl::digest::compare $original_hash $current_hash]} {
    puts "File integrity verified - no changes detected"
} else {
    puts "WARNING: File has been modified!"
}
```

### Password Verification

```tcl
# Store hashed password
set password "user_password"
set salt [tossl::rand::bytes 16]
set stored_hash [tossl::digest -alg sha256 "$password$salt"]

# Later, verify password
set input_password "user_password"
set input_hash [tossl::digest -alg sha256 "$input_password$salt"]

if {[tossl::digest::compare $stored_hash $input_hash]} {
    puts "Password is correct"
} else {
    puts "Password is incorrect"
}
```

### Digital Signature Verification

```tcl
# Verify digital signature
set data "Important document content"
set signature [tossl::rsa::sign -privkey $private_key -alg sha256 $data]

# Later, verify the signature
set computed_hash [tossl::digest -alg sha256 $data]
set verified_hash [tossl::rsa::verify -pubkey $public_key -alg sha256 $data $signature]

if {[tossl::digest::compare $computed_hash $verified_hash]} {
    puts "Signature is valid"
} else {
    puts "Signature verification failed"
}
```

### Multiple Hash Comparison

```tcl
# Compare hashes from different algorithms
set data "Test data"
set md5_hash [tossl::digest -alg md5 $data]
set sha1_hash [tossl::digest -alg sha1 $data]
set sha256_hash [tossl::digest -alg sha256 $data]

# These should all be different
puts "MD5 vs SHA1: [tossl::digest::compare $md5_hash $sha1_hash]"
puts "MD5 vs SHA256: [tossl::digest::compare $md5_hash $sha256_hash]"
puts "SHA1 vs SHA256: [tossl::digest::compare $sha1_hash $sha256_hash]"
# Output: All should be 0 (different)
```

### HMAC Verification

```tcl
# Verify HMAC signatures
set key [binary format H* "00112233445566778899aabbccddeeff"]
set message "Authenticated message"
set hmac1 [tossl::hmac -alg sha256 -key $key $message]
set hmac2 [tossl::hmac -alg sha256 -key $key $message]

if {[tossl::digest::compare $hmac1 $hmac2]} {
    puts "HMAC verification successful"
} else {
    puts "HMAC verification failed"
}
```

### Batch Hash Verification

```tcl
# Verify multiple files at once
set files {"file1.txt" "file2.txt" "file3.txt"}
set expected_hashes {
    "a1b2c3d4e5f6..."
    "f6e5d4c3b2a1..."
    "1234567890ab..."
}

for {set i 0} {$i < [llength $files]} {incr i} {
    set file [lindex $files $i]
    set expected [lindex $expected_hashes $i]
    set actual [tossl::digest::stream -alg sha256 -file $file]
    
    if {[tossl::digest::compare $expected $actual]} {
        puts "$file: OK"
    } else {
        puts "$file: FAILED"
    }
}
```

## Error Handling

The command will return an error in the following cases:

- **Wrong number of arguments**: Must provide exactly two hash values
- **Missing arguments**: Both hash1 and hash2 are required

### Error Examples

```tcl
# Wrong number of arguments
tossl::digest::compare "hash1"
# Error: wrong # args: should be "tossl::digest::compare hash1 hash2"

# Too many arguments
tossl::digest::compare "hash1" "hash2" "hash3"
# Error: wrong # args: should be "tossl::digest::compare hash1 hash2"

# No arguments
tossl::digest::compare
# Error: wrong # args: should be "tossl::digest::compare hash1 hash2"
```

## Security Considerations

### Timing Attack Resistance

The `::tossl::digest::compare` command is designed to be resistant to timing attacks. The comparison is performed in constant time, meaning the execution time is not dependent on how many characters match between the two hashes.

```tcl
# This comparison is safe from timing attacks
set result [tossl::digest::compare $hash1 $hash2]
```

### Hash Length Validation

The command automatically handles hashes of different lengths by returning 0 (false) immediately if the lengths don't match, which is both efficient and secure.

```tcl
# Different length hashes are safely handled
set short_hash "abc123"
set long_hash "a1b2c3d4e5f6..."
set result [tossl::digest::compare $short_hash $long_hash]
# Returns 0 immediately without detailed comparison
```

### Case Sensitivity

The comparison is case-sensitive, which is important for cryptographic applications where exact matching is required.

```tcl
set hash1 "a1b2c3d4e5f6"
set hash2 "A1B2C3D4E5F6"
set result [tossl::digest::compare $hash1 $hash2]
# Returns 0 (different) due to case sensitivity
```

### Input Validation

The command accepts any string input, making it flexible for various hash formats and encodings.

```tcl
# Works with hex strings
set hex1 "a1b2c3d4e5f6"
set hex2 "a1b2c3d4e5f6"

# Works with base64 strings
set b64_hash1 [tossl::digest -alg sha256 "data" -format base64]
set b64_hash2 [tossl::digest -alg sha256 "data" -format base64]

# Works with binary data (as strings)
set bin_hash1 [tossl::digest -alg sha256 "data" -format binary]
set bin_hash2 [tossl::digest -alg sha256 "data" -format binary]
```

## Performance Notes

- **Constant time**: Comparison time is independent of hash content
- **Efficient**: Early termination for different-length hashes
- **Memory efficient**: No additional memory allocation required
- **Scalable**: Performance remains consistent regardless of hash size

### Performance Example

```tcl
# Performance test
set hash1 [tossl::digest -alg sha512 "test data"]
set hash2 [tossl::digest -alg sha512 "test data"]

set start_time [clock clicks -microseconds]
for {set i 0} {$i < 1000} {incr i} {
    tossl::digest::compare $hash1 $hash2
}
set end_time [clock clicks -microseconds]
puts "1000 comparisons took: [expr $end_time - $start_time] microseconds"
```

## Best Practices

### Use for Cryptographic Purposes

```tcl
# Good: Use for cryptographic verification
set expected_hash [tossl::digest -alg sha256 $data]
set actual_hash [tossl::digest -alg sha256 $data]
if {[tossl::digest::compare $expected_hash $actual_hash]} {
    # Proceed with confidence
}
```

### Avoid for General String Comparison

```tcl
# Avoid: Don't use for general string comparison
# Use string comparison instead
if {$string1 eq $string2} {
    # Use Tcl's string comparison for non-cryptographic purposes
}
```

### Verify Hash Formats

```tcl
# Ensure consistent hash formats
set hash1 [tossl::digest -alg sha256 "data" -format hex]
set hash2 [tossl::digest -alg sha256 "data" -format hex]
# Both hashes are in hex format for comparison
```

### Handle Edge Cases

```tcl
# Handle empty hashes appropriately
if {[string length $hash1] == 0 || [string length $hash2] == 0} {
    puts "Warning: Empty hash detected"
}

# Handle very short hashes
if {[string length $hash1] < 32} {
    puts "Warning: Hash seems unusually short"
}
```

### Integration with Other Commands

```tcl
# Common integration pattern
proc verify_file_integrity {filename expected_hash} {
    if {![file exists $filename]} {
        return 0
    }
    
    set actual_hash [tossl::digest::stream -alg sha256 -file $filename]
    return [tossl::digest::compare $expected_hash $actual_hash]
}

# Usage
if {[verify_file_integrity "document.pdf" $stored_hash]} {
    puts "File integrity verified"
} else {
    puts "File integrity check failed"
}
```

## Related Commands

- **`::tossl::digest`**: Compute hash digests
- **`::tossl::digest::stream`**: Compute hash digests of files
- **`::tossl::digest::list`**: List available digest algorithms
- **`::tossl::hmac`**: Compute HMAC signatures
- **`::tossl::rsa::sign`**: Create digital signatures
- **`::tossl::rsa::verify`**: Verify digital signatures

## Troubleshooting

### Common Issues

1. **Hashes not matching when expected**
   - Check if hashes are in the same format (hex, base64, binary)
   - Verify the same algorithm was used for both hashes
   - Ensure no whitespace or encoding issues

2. **Performance concerns**
   - The command is optimized for constant-time comparison
   - For bulk comparisons, consider batching operations

3. **Security considerations**
   - Always use this command for cryptographic comparisons
   - Don't use string comparison for hash verification
   - Be aware of timing attack resistance

### Debugging

```tcl
# Debug hash comparison issues
proc debug_hash_comparison {hash1 hash2} {
    puts "Hash1 length: [string length $hash1]"
    puts "Hash2 length: [string length $hash2]"
    puts "Hash1: $hash1"
    puts "Hash2: $hash2"
    puts "Comparison result: [tossl::digest::compare $hash1 $hash2]"
}

debug_hash_comparison $hash1 $hash2
``` 