# ::tossl::ed25519::generate

Generate an Ed25519 key pair.

## Overview

The `::tossl::ed25519::generate` command creates a new Ed25519 key pair using cryptographically secure random number generation. It returns the private key in PEM format.

## Syntax

```
::tossl::ed25519::generate
```

No arguments are required.

## Example

```tcl
# Generate Ed25519 key pair
set priv [tossl::ed25519::generate]
puts "Private key: $priv"

# Extract public key
set pub [tossl::key::getpub -key $priv]
puts "Public key: $pub"
```

## Return Value

- Returns the Ed25519 private key in PEM format.
- Returns an error if key generation fails.

## Error Handling

- Returns an error if the key generation fails.
- Returns an error if memory allocation fails.
- Returns an error if the wrong number of arguments is provided.

## Security Considerations

- **Random Number Generation**: The command uses OpenSSL's cryptographically secure random number generator.
- **Key Storage**: Store private keys securely and never expose them in logs or outputs.
- **Key Validation**: Always validate generated keys before use in production.
- **Key Size**: Ed25519 keys provide 128-bit security level.

## Best Practices

- Store private keys securely with appropriate access controls.
- Use the generated keys with other Ed25519 commands for signing and verification.
- Do not expose private key material in logs or error messages.
- Validate generated keys before use in production.

## Key Properties

### Ed25519 Key Characteristics
- **Key Size**: 256 bits (32 bytes)
- **Security Level**: 128 bits
- **Signature Size**: 64 bytes
- **Deterministic Signatures**: Yes
- **Resistance to Timing Attacks**: Yes

### Key Format
- **Private Key**: PEM format with "-----BEGIN PRIVATE KEY-----" header
- **Public Key**: Can be extracted using `tossl::key::getpub`
- **Key Type**: Ed25519 (Edwards-curve Digital Signature Algorithm)

## Common Use Cases

### Basic Key Generation
```tcl
set priv [tossl::ed25519::generate]
set pub [tossl::key::getpub -key $priv]
puts "Generated Ed25519 key pair"
```

### Key Generation with Validation
```tcl
set priv [tossl::ed25519::generate]
set pub [tossl::key::getpub -key $priv]

# Validate the keys
set parsed_priv [tossl::key::parse -key $priv]
set parsed_pub [tossl::key::parse -key $pub]

if {[dict get $parsed_priv type] eq "ed25519" && [dict get $parsed_pub type] eq "ed25519"} {
    puts "Keys are valid Ed25519 keys"
} else {
    puts "Keys are invalid"
}
```

### Key Generation with Functionality Testing
```tcl
set priv [tossl::ed25519::generate]
set pub [tossl::key::getpub -key $priv]

# Test signing and verification
set data "Test message"
set sig [tossl::ed25519::sign $priv $data]
set verified [tossl::ed25519::verify $pub $data $sig]

if {$verified} {
    puts "Key pair is functional"
} else {
    puts "Key pair is not functional"
}
```

### Multiple Key Generation
```tcl
set keys {}
for {set i 0} {$i < 5} {incr i} {
    lappend keys [tossl::ed25519::generate]
}

puts "Generated [llength $keys] Ed25519 keys"
```

## Performance Considerations

- Ed25519 key generation is very fast.
- Key generation time is consistent and predictable.
- Memory usage is minimal and constant.
- The algorithm is optimized for both key generation and cryptographic operations.

## Algorithm Details

Ed25519 is an elliptic curve digital signature algorithm based on the Edwards-curve Digital Signature Algorithm (EdDSA) using the Curve25519 elliptic curve. It provides:

- **High Security**: 128-bit security level
- **Fast Operations**: Optimized for both signing and verification
- **Compact Keys**: 256-bit private keys, 256-bit public keys
- **Compact Signatures**: 64-byte signatures
- **Deterministic Signatures**: Same message and key always produce the same signature
- **Resistance to Timing Attacks**: Constant-time implementation
- **No Random Number Generation Required**: For signing (deterministic by design)

## Comparison with Other Algorithms

| Algorithm | Private Key Size | Public Key Size | Signature Size | Security Level | Performance |
|-----------|------------------|-----------------|----------------|----------------|-------------|
| Ed25519   | 256 bits         | 256 bits        | 64 bytes       | 128 bits       | Very fast   |
| RSA-2048  | 2048 bits        | 2048 bits       | 256 bytes      | 112 bits       | Slower      |
| ECDSA     | 256 bits         | 256 bits        | 64-128 bytes   | 128 bits       | Fast        |

## Key Management

### Key Storage
```tcl
set priv [tossl::ed25519::generate]

# Store private key securely
set key_file [open "private_key.pem" w]
puts $key_file $priv
close $key_file

# Set appropriate permissions (Unix/Linux)
exec chmod 600 private_key.pem
```

### Key Loading
```tcl
# Load private key from file
set key_file [open "private_key.pem" r]
set priv [read $key_file]
close $key_file

# Extract public key
set pub [tossl::key::getpub -key $priv]
```

## See Also
- `::tossl::ed25519::sign`
- `::tossl::ed25519::verify`
- `::tossl::key::getpub`
- `::tossl::key::parse`
- `::tossl::key::fingerprint`
- `::tossl::ed448::generate`
- `::tossl::x25519::generate` 