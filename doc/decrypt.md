# ::tossl::decrypt

**Decrypt data using the specified cipher, key, and IV.**

## Syntax

```tcl
::tossl::decrypt -alg <name> -key <key> -iv <iv> <data>
```

- `-alg <name>`: Cipher algorithm (e.g., aes-128-cbc)
- `-key <key>`: Key bytes (binary)
- `-iv <iv>`: IV bytes (binary)
- `<data>`: Ciphertext to decrypt (byte array)

## Returns
Decrypted plaintext as a Tcl byte array.

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if decryption fails or is not supported in this build.

## Security Considerations

- Use secure key and IV management practices.
- Only decrypt data from trusted sources.

## See Also
- [encrypt](encrypt.md) 