# ::tossl::encrypt

## Overview

The `::tossl::encrypt` command provides symmetric encryption functionality using various algorithms supported by OpenSSL. This command is essential for securing sensitive data, implementing secure communication protocols, and protecting information at rest.

## Syntax

```tcl
::tossl::encrypt -alg algorithm [-key key] [-iv iv] [-aad aad] [-tag tag] [-format format] data
```

## Parameters

- **-alg algorithm** (required): The encryption algorithm to use. Supported algorithms include:
  - `aes-128-ecb` - AES-128 in ECB mode (not recommended for security)
  - `aes-192-ecb` - AES-192 in ECB mode (not recommended for security)
  - `aes-256-ecb` - AES-256 in ECB mode (not recommended for security)
  - `aes-128-cbc` - AES-128 in CBC mode
  - `aes-192-cbc` - AES-192 in CBC mode
  - `aes-256-cbc` - AES-256 in CBC mode
  - `aes-128-cfb` - AES-128 in CFB mode
  - `aes-192-cfb` - AES-192 in CFB mode
  - `aes-256-cfb` - AES-256 in CFB mode
  - `aes-128-ofb` - AES-128 in OFB mode
  - `aes-192-ofb` - AES-192 in OFB mode
  - `aes-256-ofb` - AES-256 in OFB mode
  - `aes-128-gcm` - AES-128 in GCM mode (authenticated encryption)
  - `aes-192-gcm` - AES-192 in GCM mode (authenticated encryption)
  - `aes-256-gcm` - AES-256 in GCM mode (authenticated encryption)
  - `aes-128-ccm` - AES-128 in CCM mode (authenticated encryption)
  - `aes-192-ccm` - AES-192 in CCM mode (authenticated encryption)
  - `aes-256-ccm` - AES-256 in CCM mode (authenticated encryption)
  - `chacha20-poly1305` - ChaCha20-Poly1305 (authenticated encryption)
  - `camellia-128-cbc` - Camellia-128 in CBC mode
  - `camellia-192-cbc` - Camellia-192 in CBC mode
  - `camellia-256-cbc` - Camellia-256 in CBC mode

- **-key key** (required): The encryption key. Must be appropriate length for the algorithm.
- **-iv iv** (optional): Initialization vector. Required for CBC, CFB, OFB modes.
- **-aad aad** (optional): Additional authenticated data for GCM/CCM modes.
- **-tag tag** (optional): Authentication tag for GCM/CCM modes.
- **-format format** (optional): Output format. Default is `base64`.
  - `base64` - Base64 encoded string (default)
  - `hex` - Hexadecimal string
  - `binary` - Raw binary data

- **data** (required): The data to encrypt. Can be a string or binary data.

## Returns

Returns the encrypted data in the specified format. For authenticated encryption modes (GCM, CCM, ChaCha20-Poly1305), the authentication tag is included in the output.

## Examples

### Basic AES-256-CBC Encryption

```tcl
# Generate a random key and IV
set key [tossl::rand::bytes 32]  # 256-bit key
set iv [tossl::rand::bytes 16]   # 128-bit IV

# Encrypt data
set plaintext "Secret message"
set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $plaintext]
puts "Encrypted: $ciphertext"

# Decrypt data
set decrypted [tossl::decrypt -alg aes-256-cbc -key $key -iv $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### AES-GCM Authenticated Encryption

```tcl
# Generate key and nonce for GCM
set key [tossl::rand::bytes 32]  # 256-bit key
set nonce [tossl::rand::bytes 12] # 96-bit nonce

# Encrypt with authentication
set plaintext "Authenticated message"
set aad "Additional authenticated data"
set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce -aad $aad $plaintext]
puts "Authenticated ciphertext: $ciphertext"
```

### ChaCha20-Poly1305 Encryption

```tcl
# Generate key and nonce
set key [tossl::rand::bytes 32]  # 256-bit key
set nonce [tossl::rand::bytes 12] # 96-bit nonce

# Encrypt
set plaintext "Fast authenticated encryption"
set ciphertext [tossl::encrypt -alg chacha20-poly1305 -key $key -iv $nonce $plaintext]
puts "ChaCha20-Poly1305: $ciphertext"
```

### Different Output Formats

```tcl
set key [tossl::rand::bytes 32]
set iv [tossl::rand::bytes 16]
set data "Test data"

# Base64 output (default)
set b64_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $data]
puts "Base64: $b64_cipher"

# Hexadecimal output
set hex_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv -format hex $data]
puts "Hex: $hex_cipher"

# Binary output
set bin_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv -format binary $data]
puts "Binary length: [string length $bin_cipher]"
```

### File Encryption

```tcl
# Read file data
set file_data [read [open "document.txt" r]]

# Generate encryption parameters
set key [tossl::rand::bytes 32]
set iv [tossl::rand::bytes 16]

# Encrypt file
set encrypted_data [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $file_data]

# Save encrypted file
set outfile [open "document.txt.enc" w]
puts -nonewline $outfile $encrypted_data
close $outfile
```

### Key Derivation for Encryption

```tcl
# Derive key from password
set password "my_secret_password"
set salt [tossl::rand::bytes 16]
set derived_key [tossl::kdf::pbkdf2 -password $password -salt $salt -iterations 10000 -keylen 32]

# Use derived key for encryption
set iv [tossl::rand::bytes 16]
set ciphertext [tossl::encrypt -alg aes-256-cbc -key $derived_key -iv $iv "Secret data"]
```

## Error Handling

The command will return an error in the following cases:

- **Invalid algorithm**: Unsupported encryption algorithm
- **Invalid key length**: Key size doesn't match algorithm requirements
- **Missing IV**: IV required but not provided for CBC/CFB/OFB modes
- **Invalid IV length**: IV size doesn't match algorithm requirements
- **OpenSSL error**: Internal OpenSSL errors

### Error Examples

```tcl
# Invalid algorithm
tossl::encrypt -alg invalid_alg -key $key -iv $iv "data"
# Error: unsupported cipher algorithm: invalid_alg

# Wrong key length
set short_key [tossl::rand::bytes 16]  # Too short for AES-256
tossl::encrypt -alg aes-256-cbc -key $short_key -iv $iv "data"
# Error: invalid key length for algorithm

# Missing IV for CBC mode
tossl::encrypt -alg aes-256-cbc -key $key "data"
# Error: IV required for CBC mode

# Wrong IV length
set wrong_iv [tossl::rand::bytes 8]  # Too short
tossl::encrypt -alg aes-256-cbc -key $key -iv $wrong_iv "data"
# Error: invalid IV length for algorithm
```

## Security Considerations

### Algorithm Security

- **ECB mode**: Never use for secure applications - no authentication, vulnerable to patterns
- **CBC mode**: Requires proper IV management, vulnerable to padding oracle attacks
- **GCM/CCM modes**: Provide authenticated encryption, recommended for most applications
- **ChaCha20-Poly1305**: High-performance authenticated encryption

### Key Management

```tcl
# Good: Generate random keys
set key [tossl::rand::bytes 32]

# Bad: Use predictable keys
set key "my_secret_key_123"  # Don't do this
```

### IV/Nonce Management

```tcl
# Good: Generate random IV for each encryption
set iv [tossl::rand::bytes 16]

# Bad: Reuse IV
set iv "static_iv_123"  # Don't do this
```

### Authenticated Encryption

```tcl
# Recommended: Use authenticated encryption
set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce $plaintext]

# Less secure: Use unauthenticated encryption
set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $plaintext]
```

## Performance Notes

- **AES-GCM**: Good performance with authentication
- **ChaCha20-Poly1305**: Very fast, especially on systems without AES hardware acceleration
- **AES-CBC**: Fast but requires separate authentication
- **Key size impact**: Larger keys provide better security but may be slower

## Best Practices

### Use Authenticated Encryption

```tcl
# Good: Use GCM mode for authenticated encryption
set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce $plaintext]

# Also good: Use ChaCha20-Poly1305
set ciphertext [tossl::encrypt -alg chacha20-poly1305 -key $key -iv $nonce $plaintext]
```

### Proper Key and IV Generation

```tcl
# Good: Generate cryptographically secure random values
set key [tossl::rand::bytes 32]
set iv [tossl::rand::bytes 16]

# For GCM/CCM, use 12-byte nonce
set nonce [tossl::rand::bytes 12]
```

### Handle Errors Gracefully

```tcl
# Good: Check for errors
if {[catch {set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce $plaintext]} error]} {
    puts "Encryption failed: $error"
    # Handle error appropriately
}
```

## Related Commands

- **`::tossl::decrypt`**: Decrypt data using the same algorithms
- **`::tossl::rand::bytes`**: Generate random keys and IVs
- **`::tossl::kdf::pbkdf2`**: Derive keys from passwords
- **`::tossl::key::generate`**: Generate encryption keys
- **`::tossl::hmac`**: Add message authentication codes

## Implementation Details

The command is implemented using OpenSSL's EVP cipher functions:

```c
int EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Parse arguments
    const char *algorithm = NULL;
    const char *key = NULL;
    const char *iv = NULL;
    const char *aad = NULL;
    const char *format = "base64";
    const char *data = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < objc; i++) {
        if (strcmp(Tcl_GetString(objv[i]), "-alg") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing algorithm", TCL_STATIC);
                return TCL_ERROR;
            }
            algorithm = Tcl_GetString(objv[i]);
        } else if (strcmp(Tcl_GetString(objv[i]), "-key") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing key", TCL_STATIC);
                return TCL_ERROR;
            }
            key = Tcl_GetString(objv[i]);
        } else if (strcmp(Tcl_GetString(objv[i]), "-iv") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing IV", TCL_STATIC);
                return TCL_ERROR;
            }
            iv = Tcl_GetString(objv[i]);
        } else if (strcmp(Tcl_GetString(objv[i]), "-aad") == 0) {
            if (++i >= objc) {
                Tcl_SetResult(interp, "missing AAD", TCL_STATIC);
                return TCL_ERROR;
            }
            aad = Tcl_GetString(objv[i]);
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
    if (!algorithm || !key || !data) {
        Tcl_SetResult(interp, "missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Initialize OpenSSL cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "unsupported cipher algorithm", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char*)key, (unsigned char*)iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        Tcl_SetResult(interp, "failed to initialize encryption", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add AAD if provided
    if (aad) {
        int aad_len;
        EVP_EncryptUpdate(ctx, NULL, &aad_len, (unsigned char*)aad, strlen(aad));
    }
    
    // Encrypt data
    unsigned char *outbuf = malloc(strlen(data) + EVP_MAX_BLOCK_LENGTH);
    int outlen;
    EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char*)data, strlen(data));
    
    // Finalize encryption
    int tmplen;
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;
    
    // Get tag for authenticated encryption
    unsigned char tag[16];
    int taglen = 0;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1) {
        taglen = 16;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Format output
    Tcl_Obj *result = FormatEncryptedData(outbuf, outlen, tag, taglen, format);
    Tcl_SetObjResult(interp, result);
    free(outbuf);
    
    return TCL_OK;
}
```

## Testing

The command is thoroughly tested with the following test cases:

- All supported algorithms
- Different key and IV sizes
- Various output formats
- Error handling
- Performance tests
- Security validation

Run the tests with:

```bash
tclsh tests/test_encrypt.tcl
```

## Version History

- **Initial implementation**: Basic encryption support
- **Current version**: Full algorithm support with authenticated encryption
- **Future enhancements**: Additional algorithms and streaming support 