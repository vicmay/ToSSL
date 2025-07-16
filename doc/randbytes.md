# ::tossl::rand::bytes

## Overview

The `::tossl::rand::bytes` command generates cryptographically secure random bytes using OpenSSL's `RAND_bytes()` function. This command is essential for cryptographic operations that require unpredictable random data, such as generating encryption keys, initialization vectors (IVs), salts, and nonces.

## Syntax

```tcl
::tossl::rand::bytes count
```

## Parameters

- **count** (integer): The number of random bytes to generate. Must be a positive integer between 1 and 4096.

## Returns

Returns a Tcl byte array containing the specified number of cryptographically secure random bytes.

## Examples

### Basic Usage

```tcl
# Generate 16 random bytes
set random_bytes [tossl::rand::bytes 16]
puts "Random bytes (hex): [binary encode hex $random_bytes]"
```

### Generate Different Amounts

```tcl
# Generate 1 byte
set one_byte [tossl::rand::bytes 1]

# Generate 32 bytes (256 bits)
set key_material [tossl::rand::bytes 32]

# Generate 64 bytes (512 bits)
set large_random [tossl::rand::bytes 64]
```

### Generate Encryption Key and IV

```tcl
# Generate AES-256 key (32 bytes)
set aes_key [tossl::rand::bytes 32]

# Generate AES IV (16 bytes)
set aes_iv [tossl::rand::bytes 16]

# Use for encryption
set ciphertext [tossl::encrypt -alg aes-256-cbc -key $aes_key -iv $aes_iv "Secret message"]
```

### Generate Salt for Password Hashing

```tcl
# Generate 16-byte salt for PBKDF2
set salt [tossl::rand::bytes 16]
set derived_key [tossl::kdf::pbkdf2 -password "my_password" -salt $salt -iterations 10000 -keylen 32]
```

### Generate Nonce for Authenticated Encryption

```tcl
# Generate 12-byte nonce for AES-GCM
set nonce [tossl::rand::bytes 12]
```

## Error Handling

The command will return an error in the following cases:

- **Invalid argument count**: Wrong number of arguments
- **Invalid argument type**: Non-integer argument
- **Invalid range**: Argument less than 1 or greater than 4096
- **OpenSSL error**: If `RAND_bytes()` fails internally

### Error Examples

```tcl
# Too few arguments
tossl::rand::bytes
# Error: wrong # args: should be "tossl::rand::bytes count"

# Too many arguments
tossl::rand::bytes 16 32
# Error: wrong # args: should be "tossl::rand::bytes count"

# Invalid argument type
tossl::rand::bytes "not_a_number"
# Error: expected integer but got "not_a_number"

# Invalid range - zero
tossl::rand::bytes 0
# Error: count must be an integer between 1 and 4096

# Invalid range - negative
tossl::rand::bytes -1
# Error: count must be an integer between 1 and 4096

# Invalid range - too large
tossl::rand::bytes 5000
# Error: count must be an integer between 1 and 4096
```

## Security Considerations

### Cryptographically Secure

The `::tossl::rand::bytes` command uses OpenSSL's `RAND_bytes()` function, which provides cryptographically secure random numbers suitable for:

- Encryption keys
- Initialization vectors (IVs)
- Salts for password hashing
- Nonces for authenticated encryption
- Session tokens
- Cryptographic challenges

### Entropy Sources

OpenSSL automatically uses multiple entropy sources including:

- Hardware random number generators (if available)
- Operating system entropy pools
- Environmental noise
- User input timing

### Limitations

- **Maximum size**: Limited to 4096 bytes per call to prevent memory exhaustion
- **Performance**: May be slower than pseudo-random number generators
- **Blocking**: May block if insufficient entropy is available

## Performance Notes

- **Small amounts**: Fast for small byte counts (1-64 bytes)
- **Large amounts**: May be slower for large byte counts due to entropy requirements
- **Repeated calls**: Each call generates fresh entropy, so multiple small calls may be slower than one large call

## Best Practices

### Use Appropriate Sizes

```tcl
# Good: Use appropriate sizes for the cryptographic operation
set aes_key [tossl::rand::bytes 32]  # 256-bit key
set aes_iv [tossl::rand::bytes 16]   # 128-bit IV
set salt [tossl::rand::bytes 16]     # 128-bit salt
```

### Avoid Reusing Random Data

```tcl
# Good: Generate fresh random data for each operation
set key1 [tossl::rand::bytes 32]
set key2 [tossl::rand::bytes 32]  # Different from key1

# Bad: Reusing the same random data
set key [tossl::rand::bytes 32]
set iv $key  # Don't reuse key as IV
```

### Handle Errors Gracefully

```tcl
# Good: Check for errors
if {[catch {set random_bytes [tossl::rand::bytes 32]} error]} {
    puts "Failed to generate random bytes: $error"
    # Handle error appropriately
}
```

## Related Commands

- **`::tossl::rand::key`**: Generate random keys for specific cipher algorithms
- **`::tossl::rand::iv`**: Generate random initialization vectors for specific cipher algorithms
- **`::tossl::rand::test`**: Test random number generation quality
- **`::tossl::kdf::pbkdf2`**: Use random bytes as salt for key derivation
- **`::tossl::encrypt`**: Use random bytes for encryption keys and IVs

## Implementation Details

The command is implemented in C using OpenSSL's `RAND_bytes()` function:

```c
int RandBytesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Validate arguments
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "count");
        return TCL_ERROR;
    }
    
    // Parse and validate count
    int count;
    if (Tcl_GetIntFromObj(interp, objv[2], &count) != TCL_OK || 
        count <= 0 || count > 4096) {
        Tcl_SetResult(interp, "count must be an integer between 1 and 4096", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Generate random bytes
    unsigned char *bytes = malloc(count);
    if (RAND_bytes(bytes, count) != 1) {
        free(bytes);
        Tcl_SetResult(interp, "OpenSSL: random generation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Return as Tcl byte array
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(bytes, count));
    free(bytes);
    return TCL_OK;
}
```

## Testing

The command is thoroughly tested with the following test cases:

- Basic functionality with various byte counts
- Error handling for invalid arguments
- Randomness quality tests
- Performance and memory tests
- Edge cases and boundary conditions

Run the tests with:

```bash
tclsh tests/test_randbytes.tcl
```

## Version History

- **Initial implementation**: Basic random byte generation
- **Current version**: Full error handling and validation
- **Future enhancements**: May include additional entropy sources and performance optimizations 