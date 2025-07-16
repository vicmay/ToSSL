# ::tossl::pbkdf2

**Key derivation using the PBKDF2 algorithm.**

## Syntax

```tcl
::tossl::pbkdf2 -pass <password> -salt <salt> -iter <iterations> -len <length> -digest <algorithm>
```

- `-pass <password>`: Password string
- `-salt <salt>`: Salt bytes
- `-iter <iterations>`: Number of iterations
- `-len <length>`: Output key length (bytes)
- `-digest <algorithm>`: Hash algorithm (e.g., sha256)

## Returns
Derived key bytes (binary).

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if PBKDF2 is not supported in this build.

## Security Considerations

- Use a strong, random salt for each password.
- Use a high iteration count for better security.

## See Also
- [Scrypt](scrypt.md)
- [Argon2](argon2.md) 