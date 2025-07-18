# ::tossl::kdf::argon2

## Overview

The `::tossl::kdf::argon2` command provides password-based key derivation using the Argon2 algorithm. **Note: The current implementation has a known issue where it incorrectly uses scrypt instead of proper Argon2, which may cause inconsistent behavior.**

## Syntax

```tcl
::tossl::kdf::argon2 -pass <password> -salt <salt> -t <time> -m <memory> -p <parallel> -len <length>
```

## Parameters

- `-pass <password>`: The password string to derive the key from
- `-salt <salt>`: The salt value (recommended 16+ bytes for security)
- `-t <time>`: Time cost parameter (number of iterations, must be positive)
- `-m <memory>`: Memory cost parameter (in KB, must be positive)
- `-p <parallel>`: Parallelism parameter (number of parallel threads, must be positive)
- `-len <length>`: Output key length in bytes (must be between 1 and 4096)

## Returns

Returns a byte array containing the derived key of the specified length.

## Examples

### Basic Key Derivation

```tcl
# Generate a random salt
set salt [tossl::rand::bytes 16]

# Derive a 32-byte key using Argon2
set key [tossl::kdf::argon2 -pass "my_password" -salt $salt -t 2 -m 16 -p 1 -len 32]
puts "Derived key length: [string length $key] bytes"
```

### Different Key Lengths

```tcl
set password "test_password"
set salt [tossl::rand::bytes 16]

# Derive different key lengths
set key16 [tossl::kdf::argon2 -pass $password -salt $salt -t 2 -m 16 -p 1 -len 16]
set key64 [tossl::kdf::argon2 -pass $password -salt $salt -t 2 -m 16 -p 1 -len 64]

puts "16-byte key: [string length $key16] bytes"
puts "64-byte key: [string length $key64] bytes"
```

### Different Parameter Combinations

```tcl
set password "test_password"
set salt [tossl::rand::bytes 16]

# Higher time cost (more iterations)
set key1 [tossl::kdf::argon2 -pass $password -salt $salt -t 10 -m 16 -p 1 -len 32]

# Higher memory cost
set key2 [tossl::kdf::argon2 -pass $password -salt $salt -t 2 -m 1024 -p 1 -len 32]

# Higher parallelism
set key3 [tossl::kdf::argon2 -pass $password -salt $salt -t 2 -m 16 -p 4 -len 32]
```

### Complete Password Hashing Workflow

```tcl
# Generate a secure random salt
set salt [tossl::rand::bytes 16]

# Derive key with appropriate parameters
set derived_key [tossl::kdf::argon2 -pass "user_password" -salt $salt -t 3 -m 65536 -p 1 -len 32]

# Store salt and derived key (never store the original password)
puts "Salt (hex): [binary encode hex $salt]"
puts "Derived key (hex): [binary encode hex $derived_key]"
```

## Error Handling

The command will return an error in the following cases:

- **Wrong number of arguments**: Missing or extra parameters
- **Missing required parameters**: Any of the required parameters is missing
- **Invalid parameter values**: Zero or negative values for numeric parameters
- **Invalid key length**: Key length less than 1 or greater than 4096
- **Invalid argument types**: Non-integer values for numeric parameters
- **Implementation limitation**: Current implementation may fail with "Argon2 not supported in this build"

### Error Examples

```tcl
# Too few arguments
tossl::kdf::argon2
# Error: wrong # args: should be "tossl::kdf::argon2 -pass password -salt salt -t time -m memory -p parallel -len length"

# Missing password
set salt [tossl::rand::bytes 16]
tossl::kdf::argon2 -salt $salt -t 2 -m 16 -p 1 -len 32
# Error: wrong # args: should be "tossl::kdf::argon2 -pass password -salt salt -t time -m memory -p parallel -len length"

# Invalid time parameter (zero)
set password "test"
set salt [tossl::rand::bytes 16]
tossl::kdf::argon2 -pass $password -salt $salt -t 0 -m 16 -p 1 -len 32
# Error: All parameters are required and must be positive

# Invalid key length (too large)
tossl::kdf::argon2 -pass $password -salt $salt -t 2 -m 16 -p 1 -len 5000
# May succeed or fail depending on implementation

# Invalid argument type
tossl::kdf::argon2 -pass $password -salt $salt -t "not_a_number" -m 16 -p 1 -len 32
# Error: expected integer but got "not_a_number"
```

## Security Considerations

### Known Implementation Issue

**Important**: The current implementation has a known issue where it incorrectly uses the scrypt algorithm instead of proper Argon2. This may cause:

- Inconsistent behavior across different parameter combinations
- Different security properties than expected from Argon2
- Potential compatibility issues with other Argon2 implementations

### Best Practices

- **Use unique salts**: Always generate a unique, random salt for each password
- **Appropriate parameters**: Choose time and memory costs based on your security requirements
- **Key length**: Use appropriate key lengths (32 bytes for AES-256, 16 bytes for AES-128)
- **Error handling**: Always check for errors and handle them appropriately

### Parameter Guidelines

- **Time cost (-t)**: 2-10 for interactive applications, 10+ for server applications
- **Memory cost (-m)**: 16-65536 KB (16KB-64MB) depending on available memory
- **Parallelism (-p)**: 1-4 threads, depending on CPU cores
- **Salt length**: At least 16 bytes, preferably 32 bytes
- **Key length**: 16-64 bytes for most applications

## Performance Notes

- **Parameter impact**: Higher time and memory costs increase computation time
- **Memory usage**: Memory cost directly affects RAM usage during key derivation
- **Parallelism**: Higher parallelism may improve performance on multi-core systems
- **Implementation limitation**: Current implementation may not scale as expected due to the scrypt fallback

## Implementation Details

The command is implemented in C using OpenSSL's key derivation functions. However, the current implementation has a known issue where it uses `EVP_PBE_scrypt` instead of proper Argon2, which may cause inconsistent behavior.

### Current Implementation

```c
int Argon2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Parse Argon2 parameters
    // ...
    
    // INCORRECT: Uses scrypt instead of Argon2
    if (EVP_PBE_scrypt(password, pass_len, (const unsigned char *)salt, salt_len, 
                       time_cost, memory_cost, parallelism, 0, key, length) != 1) {
        free(key);
        Tcl_SetResult(interp, "OpenSSL: Argon2 not supported in this build", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Return derived key
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, length));
    free(key);
    return TCL_OK;
}
```

## Related Commands

- **`::tossl::kdf::pbkdf2`**: Password-based key derivation using PBKDF2
- **`::tossl::kdf::scrypt`**: Password-based key derivation using scrypt
- **`::tossl::rand::bytes`**: Generate random bytes for salt generation
- **`::tossl::encrypt`**: Use derived keys for encryption

## Testing

The command includes comprehensive tests that verify:

- Basic functionality with various parameters
- Error handling for invalid inputs
- Consistency of results with same parameters
- Different outputs for different inputs
- Edge cases and boundary conditions
- Performance characteristics

**Note**: Tests may fail intermittently due to the known implementation issue where the command uses scrypt instead of Argon2.

## Future Improvements

- Implement proper Argon2 using OpenSSL's Argon2 support (when available)
- Add support for different Argon2 variants (Argon2d, Argon2i, Argon2id)
- Improve error messages to reflect actual implementation behavior
- Add parameter validation for Argon2-specific constraints 