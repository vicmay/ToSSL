# ::tossl::hmac

**Compute HMAC using the specified hash algorithm.**

## Syntax

```tcl
::tossl::hmac -alg <algorithm> -key <key> <data>
```

- `-alg <algorithm>`: Hash algorithm (e.g., sha256)
- `-key <key>`: Key bytes (binary)
- `<data>`: Data to authenticate (string or binary)

## Returns
HMAC as a hex string.

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if HMAC is not supported in this build.

## Security Considerations

- Use a strong, random key for HMAC.
- Choose a secure hash algorithm (e.g., sha256 or better).

## See Also
- [PBKDF2](pbkdf2.md)
- [Scrypt](scrypt.md)
- [Argon2](argon2.md) 