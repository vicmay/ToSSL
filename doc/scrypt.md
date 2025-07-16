# ::tossl::scrypt

**Key derivation using the Scrypt algorithm.**

## Syntax

```tcl
::tossl::scrypt -pass <password> -salt <salt> -n <n> -r <r> -p <p> -len <length>
```

- `-pass <password>`: Password string
- `-salt <salt>`: Salt bytes
- `-n <n>`: CPU/memory cost parameter
- `-r <r>`: Block size parameter
- `-p <p>`: Parallelization parameter
- `-len <length>`: Output key length (bytes)

## Returns
Derived key bytes (binary).

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if Scrypt is not supported in this build.

## Security Considerations

- Use a strong, random salt for each password.
- Choose parameters according to current best practices for Scrypt.

## See Also
- [PBKDF2](pbkdf2.md)
- [Argon2](argon2.md) 