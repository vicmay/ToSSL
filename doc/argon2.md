# ::tossl::argon2

## Overview
The `::tossl::argon2` command provides password hashing using the Argon2 key derivation function, suitable for secure password storage and key derivation.

## Syntax
```
::tossl::argon2 <password> <salt> <t_cost> <m_cost> <parallelism> <output_length>
```
- `<password>`: The password to hash (string)
- `<salt>`: The salt value (string, recommended 16+ bytes)
- `<t_cost>`: Time cost (number of iterations, e.g., 2)
- `<m_cost>`: Memory cost (in KB, e.g., 65536 for 64MB)
- `<parallelism>`: Number of parallel threads (e.g., 1)
- `<output_length>`: Desired output length in bytes (e.g., 32)

## Example
```
set hash [::tossl::argon2 "mypassword" "mysalt" 2 65536 1 32]
puts "Argon2 hash: $hash"
```

## Error Handling
- If required parameters are missing or invalid, an error is thrown.
- Output length must be a positive integer.
- Salt should be unique per password.

## Security Considerations
- Always use a unique, random salt for each password.
- Choose t_cost and m_cost according to your security requirements and available resources.
- Never store plain passwords; only store the Argon2 hash and salt.
- Avoid using low values for t_cost and m_cost in production.

## Best Practices
- Use at least 16 bytes of salt.
- Use high enough t_cost and m_cost to slow down brute-force attacks.
- Regularly review and update parameters as hardware improves. 