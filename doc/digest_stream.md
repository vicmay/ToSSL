# ::tossl::digest::stream

## Overview

The `::tossl::digest::stream` command computes cryptographic hash digests of files using streaming operations. This command is specifically designed for processing large files efficiently by reading them in chunks rather than loading the entire file into memory. It's ideal for file integrity verification, checksum generation, and processing files that are too large to fit in memory.

## Syntax

```tcl
::tossl::digest::stream -alg algorithm -file filename [-format format]
```

## Parameters

- **-alg algorithm** (required): The hash algorithm to use. Supported algorithms include:
  - `md5` - MD5 (128-bit, deprecated for security)
  - `sha1` - SHA-1 (160-bit, deprecated for security)
  - `sha224` - SHA-224 (224-bit)
  - `sha256` - SHA-256 (256-bit)
  - `sha384` - SHA-384 (384-bit)
  - `sha512` - SHA-512 (512-bit)
  - `sha3-224` - SHA3-224 (224-bit)
  - `sha3-256` - SHA3-256 (256-bit)
  - `sha3-384` - SHA3-384 (384-bit)
  - `sha3-512` - SHA3-512 (512-bit)
  - `blake2b256` - BLAKE2b-256 (256-bit)
  - `blake2b512` - BLAKE2b-512 (512-bit)
  - `blake2s256` - BLAKE2s-256 (256-bit)
  - `sm3` - SM3 (256-bit)
  - `ripemd160` - RIPEMD-160 (160-bit)
  - `whirlpool` - Whirlpool (512-bit)

- **-file filename** (required): The path to the file to hash. The file must be readable.

- **-format format** (optional): Output format for the digest. Default is `hex`.
  - `hex` - Hexadecimal string (default)
  - `binary` - Raw binary data
  - `base64` - Base64 encoded string

## Returns

Returns the computed hash digest of the file in the specified format.

## Examples

### Basic Usage

```tcl
# Compute SHA-256 hash of a file
set hash [tossl::digest::stream -alg sha256 -file "document.pdf"]
puts "SHA-256: $hash"

# Compute SHA-512 hash
set hash [tossl::digest::stream -alg sha512 -file "large_file.dat"]
puts "SHA-512: $hash"
```

### Different Output Formats

```tcl
set filename "test_file.txt"

# Hexadecimal output (default)
set hex_hash [tossl::digest::stream -alg sha256 -file $filename]
puts "Hex: $hex_hash"

# Binary output
set bin_hash [tossl::digest::stream -alg sha256 -file $filename -format binary]
puts "Binary length: [string length $bin_hash]"

# Base64 output
set b64_hash [tossl::digest::stream -alg sha256 -file $filename -format base64]
puts "Base64: $b64_hash"
```

### File Integrity Verification

```tcl
# Generate hash for file distribution
set original_hash [tossl::digest::stream -alg sha256 -file "software.zip"]
puts "Original hash: $original_hash"

# Later, verify downloaded file
set downloaded_hash [tossl::digest::stream -alg sha256 -file "downloaded_software.zip"]
if {$original_hash eq $downloaded_hash} {
    puts "File integrity verified!"
} else {
    puts "File corruption detected!"
}
```

### Multiple Algorithm Comparison

```tcl
set filename "important_document.pdf"

# Generate multiple hashes for different purposes
set md5_hash [tossl::digest::stream -alg md5 -file $filename]
set sha256_hash [tossl::digest::stream -alg sha256 -file $filename]
set sha512_hash [tossl::digest::stream -alg sha512 -file $filename]

puts "MD5: $md5_hash"
puts "SHA-256: $sha256_hash"
puts "SHA-512: $sha512_hash"
```

### Large File Processing

```tcl
# Process large files efficiently
set large_file "database_backup.sql"

# Time the operation
set start_time [clock milliseconds]
set hash [tossl::digest::stream -alg sha256 -file $large_file]
set end_time [clock milliseconds]
set duration [expr {($end_time - $start_time) / 1000.0}]

puts "Hash: $hash"
puts "Processing time: ${duration}s"
```

### Batch File Processing

```tcl
# Process multiple files
set files [glob "*.txt"]
foreach file $files {
    set hash [tossl::digest::stream -alg sha256 -file $file]
    puts "$file: $hash"
}
```

### Binary File Handling

```tcl
# Hash binary files (images, executables, etc.)
set image_hash [tossl::digest::stream -alg sha256 -file "image.jpg"]
set exe_hash [tossl::digest::stream -alg sha512 -file "program.exe"]

puts "Image SHA-256: $image_hash"
puts "Executable SHA-512: $exe_hash"
```

## Performance Characteristics

### Memory Efficiency

The streaming approach uses a fixed buffer size (8KB) regardless of file size:

```tcl
# Memory usage is constant regardless of file size
set small_hash [tossl::digest::stream -alg sha256 -file "small.txt"]  ;# ~8KB memory
set large_hash [tossl::digest::stream -alg sha256 -file "large.dat"]  ;# ~8KB memory
```

### Processing Speed

Performance varies by algorithm and file size:

```tcl
# Benchmark different algorithms on same file
set filename "test_file.dat"

foreach alg {md5 sha1 sha256 sha512} {
    set start [clock milliseconds]
    set hash [tossl::digest::stream -alg $alg -file $filename]
    set end [clock milliseconds]
    set time [expr {($end - $start) / 1000.0}]
    puts "$alg: ${time}s"
}
```

## Error Handling

### File Access Errors

```tcl
# Handle non-existent files
if {[catch {
    set hash [tossl::digest::stream -alg sha256 -file "nonexistent.txt"]
} err]} {
    puts "Error: $err"
    # Error: Cannot open file for reading
}

# Handle permission errors
if {[catch {
    set hash [tossl::digest::stream -alg sha256 -file "/root/protected.txt"]
} err]} {
    puts "Error: $err"
    # Error: Cannot open file for reading
}
```

### Invalid Parameters

```tcl
# Handle invalid algorithm
if {[catch {
    set hash [tossl::digest::stream -alg invalid_alg -file "test.txt"]
} err]} {
    puts "Error: $err"
    # Error: Unknown digest algorithm
}

# Handle missing parameters
if {[catch {
    set hash [tossl::digest::stream -alg sha256]
} err]} {
    puts "Error: $err"
    # Error: Missing required options
}
```

## Security Considerations

### Algorithm Selection

Choose algorithms based on security requirements:

```tcl
# For legacy compatibility (insecure)
set legacy_hash [tossl::digest::stream -alg md5 -file $filename]

# For general purpose (secure)
set secure_hash [tossl::digest::stream -alg sha256 -file $filename]

# For maximum security
set max_security_hash [tossl::digest::stream -alg sha3-512 -file $filename]
```

### File Path Security

```tcl
# Validate file paths to prevent directory traversal
proc safe_hash_file {filename} {
    # Normalize path and check for suspicious patterns
    set normalized [file normalize $filename]
    if {[string match "*..*" $normalized] || [string match "*~*" $normalized]} {
        error "Suspicious file path"
    }
    
    return [tossl::digest::stream -alg sha256 -file $normalized]
}
```

## Best Practices

### Choose Appropriate Algorithms

```tcl
# For file integrity (fast, secure)
set integrity_hash [tossl::digest::stream -alg sha256 -file $filename]

# For cryptographic purposes (maximum security)
set crypto_hash [tossl::digest::stream -alg sha3-512 -file $filename]

# For legacy systems (compatibility only)
set legacy_hash [tossl::digest::stream -alg md5 -file $filename]
```

### Handle Large Files Efficiently

```tcl
# For very large files, consider progress reporting
proc hash_with_progress {filename} {
    set file_size [file size $filename]
    set hash [tossl::digest::stream -alg sha256 -file $filename]
    puts "Processed [file size $filename] bytes"
    return $hash
}
```

### Verify File Existence

```tcl
# Always check if file exists before hashing
proc safe_file_hash {filename} {
    if {![file exists $filename]} {
        error "File does not exist: $filename"
    }
    if {![file readable $filename]} {
        error "File is not readable: $filename"
    }
    return [tossl::digest::stream -alg sha256 -file $filename]
}
```

### Use Consistent Formats

```tcl
# For database storage, use consistent format
set hash [tossl::digest::stream -alg sha256 -file $filename -format hex]
# Store in database as lowercase hex string
set db_hash [string tolower $hash]
```

## Comparison with Regular Digest

The streaming version produces identical results to the regular digest command:

```tcl
# These produce the same result
set file_content [read [open "test.txt" r]]
set regular_hash [tossl::digest -alg sha256 $file_content]
set stream_hash [tossl::digest::stream -alg sha256 -file "test.txt"]

puts "Regular: $regular_hash"
puts "Stream:  $stream_hash"
puts "Match: [expr {$regular_hash eq $stream_hash}]"
```

## Related Commands

- **`::tossl::digest`**: Compute digest of data in memory
- **`::tossl::digest::list`**: List available digest algorithms
- **`::tossl::digest::compare`**: Compare two digest values
- **`::tossl::hmac`**: Compute HMAC using digests
- **`::tossl::encrypt`**: Encrypt files or data
- **`::tossl::decrypt`**: Decrypt files or data

## Performance Notes

- **Memory usage**: Constant ~8KB regardless of file size
- **Processing speed**: Varies by algorithm (MD5 > SHA-1 > SHA-256 > SHA-512)
- **File size limits**: Only limited by available disk space and processing time
- **Concurrent processing**: Safe for multiple simultaneous operations on different files

## Troubleshooting

### Common Issues

1. **File not found errors**
   - Verify file path is correct
   - Check file permissions
   - Ensure file exists before processing

2. **Permission denied errors**
   - Check read permissions on file
   - Verify directory access permissions
   - Run with appropriate user privileges

3. **Memory issues with large files**
   - Streaming approach should handle files of any size
   - Check available disk space for temporary operations
   - Monitor system memory usage during processing

### Debugging

```tcl
# Debug file access issues
proc debug_file_hash {filename} {
    puts "File: $filename"
    puts "Exists: [file exists $filename]"
    puts "Readable: [file readable $filename]"
    puts "Size: [file size $filename]"
    
    if {[file exists $filename] && [file readable $filename]} {
        set hash [tossl::digest::stream -alg sha256 -file $filename]
        puts "Hash: $hash"
        return $hash
    } else {
        error "Cannot access file"
    }
}
``` 