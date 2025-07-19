# ::tossl::rsa::components

Extract the mathematical components of an RSA private key.

## Overview

`::tossl::rsa::components` extracts the mathematical components of an RSA private key and returns them as a dictionary. This is useful for cryptographic analysis, key validation, and educational purposes.

## Syntax

```
tossl::rsa::components -key <pem>
```

- `-key <pem>`: The RSA private key in PEM format.

## Example

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set components [tossl::rsa::components -key $priv]

# Access individual components
set modulus [dict get $components n]
set public_exponent [dict get $components e]
set private_exponent [dict get $components d]
set prime1 [dict get $components p]
set prime2 [dict get $components q]

puts "Modulus (n): $modulus"
puts "Public exponent (e): $public_exponent"
puts "Private exponent (d): $private_exponent"
```

## Return Value

Returns a dictionary containing the RSA key components:

- `n` - Modulus (product of p and q)
- `e` - Public exponent
- `d` - Private exponent
- `p` - First prime factor
- `q` - Second prime factor
- `dmp1` - d mod (p-1)
- `dmq1` - d mod (q-1)
- `iqmp` - q^(-1) mod p

All values are returned as hexadecimal strings.

## Error Handling

- Returns an error if the key is not a valid RSA private key.
- Returns an error if the key format is invalid.
- Returns an error if the key is a public key (only private keys are supported).

## Security Considerations

- **Sensitive Information**: This command extracts the complete private key components. Handle the output securely.
- **Key Material**: Never log or expose the returned components in production environments.
- **Educational Use**: This command is primarily useful for educational purposes and cryptographic analysis.

## Best Practices

- Only use this command with test keys or for educational purposes.
- Do not expose the returned components in logs or outputs.
- Validate that the key is from a trusted source before extracting components.
- Consider using `tossl::rsa::validate` to verify key integrity before extracting components.

## Mathematical Background

The RSA algorithm is based on the mathematical properties of large prime numbers:

- **n = p × q**: The modulus is the product of two large prime numbers
- **e**: Public exponent (typically 65537)
- **d**: Private exponent, where (e × d) mod φ(n) = 1
- **φ(n) = (p-1) × (q-1)**: Euler's totient function

The Chinese Remainder Theorem (CRT) parameters (dmp1, dmq1, iqmp) are used for efficient decryption and signing.

## See Also
- `tossl::rsa::validate`
- `tossl::key::generate`
- `tossl::ec::components` 