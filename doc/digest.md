# ::tossl::digest

## Overview

The `::tossl::digest` command computes cryptographic hash digests using various algorithms supported by OpenSSL. This command is essential for data integrity verification, digital signatures, password hashing, and other cryptographic operations that require one-way hash functions.

## Syntax

```tcl
::tossl::digest -alg algorithm [-format format] data
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

- **-format format** (optional): Output format for the digest. Default is `hex`.
  - `hex` - Hexadecimal string (default)
  - `binary` - Raw binary data
  - `base64` - Base64 encoded string

- **data** (required): The data to hash. Can be a string or binary data.

## Returns

Returns the computed hash digest in the specified format.

## Examples

### Basic Usage

```tcl
# Compute SHA-256 hash of a string
set hash [tossl::digest -alg sha256 "Hello, World!"]
puts "SHA-256: $hash"
# Output: SHA-256: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

# Compute SHA-512 hash
set hash [tossl::digest -alg sha512 "Hello, World!"]
puts "SHA-512: $hash"
```

### Different Output Formats

```tcl
set data "Test data"

# Hexadecimal output (default)
set hex_hash [tossl::digest -alg sha256 $data]
puts "Hex: $hex_hash"

# Binary output
set bin_hash [tossl::digest -alg sha256 -format binary $data]
puts "Binary length: [string length $bin_hash]"

# Base64 output
set b64_hash [tossl::digest -alg sha256 -format base64 $data]
puts "Base64: $b64_hash"
```

### File Hashing

```tcl
# Hash a file
set file_data [read [open "document.txt" r]]
set file_hash [tossl::digest -alg sha256 $file_data]
puts "File SHA-256: $file_hash"
```

### Password Hashing

```tcl
# Hash a password (use with salt for better security)
set password "my_password"
set salt [tossl::rand::bytes 16]
set hashed_password [tossl::digest -alg sha256 "$password$salt"]
puts "Hashed password: $hashed_password"
```

### Data Integrity Verification

```tcl
# Verify data integrity
set original_data "Important data"
set original_hash [tossl::digest -alg sha256 $original_data]

# Later, verify the data hasn't changed
set current_hash [tossl::digest -alg sha256 $original_data]
if {$original_hash eq $current_hash} {
    puts "Data integrity verified"
} else {
    puts "Data has been modified!"
}
```

### Multiple Algorithms Comparison

```tcl
set data "Test message"

# Compare different algorithms
foreach alg {md5 sha1 sha256 sha512} {
    set hash [tossl::digest -alg $alg $data]
    puts "$alg: $hash"
}
```

## Error Handling

The command will return an error in the following cases:

- **Invalid algorithm**: Unsupported hash algorithm
- **Missing data**: No data provided to hash
- **Invalid format**: Unsupported output format
- **OpenSSL error**: Internal OpenSSL errors

### Error Examples

```tcl
# Invalid algorithm
tossl::digest -alg invalid_alg "data"
# Error: unsupported digest algorithm: invalid_alg

# Missing data
tossl::digest -alg sha256
# Error: wrong # args: should be "tossl::digest -alg algorithm [-format format] data"

# Invalid format
tossl::digest -alg sha256 -format invalid_format "data"
# Error: unsupported format: invalid_format
```

## Security Considerations

### Algorithm Security

- **MD5 and SHA-1**: These algorithms are cryptographically broken and should not be used for security purposes
- **SHA-256/SHA-512**: Currently secure and recommended for most applications
- **SHA-3**: Newer standard, provides additional security margin
- **BLAKE2**: High-performance alternative to SHA-3

### Password Hashing

For password hashing, consider using dedicated functions:

```tcl
# Better password hashing with salt and iterations
set password "user_password"
set salt [tossl::rand::bytes 16]
set iterations 10000
set hashed [tossl::kdf::pbkdf2 -password $password -salt $salt -iterations $iterations -keylen 32]
```

### Collision Resistance

- **SHA-256**: Provides 128-bit collision resistance
- **SHA-512**: Provides 256-bit collision resistance
- **SHA-3**: Provides similar security levels with different construction

## Performance Notes

- **SHA-256**: Good balance of security and performance
- **SHA-512**: Faster on 64-bit systems
- **SHA-3**: Slower than SHA-2 but provides different security properties
- **BLAKE2**: Very fast, especially BLAKE2b

## Best Practices

### Choose Appropriate Algorithms

```tcl
# For general purpose hashing
set hash [tossl::digest -alg sha256 $data]

# For high-performance applications
set hash [tossl::digest -alg blake2b256 $data]

# For maximum security
set hash [tossl::digest -alg sha3-512 $data]
```

### Handle Large Data Efficiently

```tcl
# For large files, consider streaming
set file [open "large_file.dat" r]
set hash [tossl::digest::stream -alg sha256 $file]
close $file
```

### Verify Hash Lengths

```tcl
# Verify expected hash lengths
set hash [tossl::digest -alg sha256 "test"]
if {[string length $hash] != 64} {
    error "Invalid SHA-256 hash length"
}
```

## Related Commands

- **`::tossl::digest::list`**: List available digest algorithms
- **`::tossl::digest::stream`**: Stream-based digest computation
- **`::tossl::digest::compare`**: Compare two digests
- **`::tossl::hmac`**: Compute HMAC (Hash-based Message Authentication Code)
- **`::tossl::sign`**: Create digital signatures using digests

## Implementation Details

The command is implemented using OpenSSL's EVP digest functions:

```c
int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Parse arguments
    const char *algorithm = NULL;
    const char *format = "hex";
    const char *data = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < objc; i++) {
        if (strcmp(Tcl_GetString(objv[i]), "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing algorithm", TCL_STATIC);
                return TCL_ERROR;
            }
            algorithm = Tcl_GetString(objv[i]);
        } else if (strcmp(Tcl_GetString(objv[i]), "-format") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing format", TCL_STATIC);
                return TCL_ERROR;
            }
            format = Tcl_GetString(objv[i]);
        } else {
            data = Tcl_GetString(objv[i]);
        }
    }
    
    // Validate required parameters
    if (!algorithm || !data) {
        Tcl_SetResult(interp, "missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Compute digest using OpenSSL EVP
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    
    if (!md) {
        EVP_MD_CTX_free(ctx);
        Tcl_SetResult(interp, "unsupported digest algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, strlen(data));
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    
    // Format output
    Tcl_Obj *result = FormatDigest(digest, digest_len, format);
    Tcl_SetObjResult(interp, result);
    
    return TCL_OK;
}
```

## Testing

The command is thoroughly tested with the following test cases:

- All supported algorithms
- Different output formats
- Error handling
- Performance tests
- Security validation

Run the tests with:

```bash
tclsh tests/test_digest.tcl
```

## Version History

- **Initial implementation**: Basic digest computation
- **Current version**: Full algorithm support and format options
- **Future enhancements**: Additional algorithms and streaming support 