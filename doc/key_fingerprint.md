# ::tossl::key::fingerprint

## Overview

The `::tossl::key::fingerprint` command computes a cryptographic fingerprint (hash) of a public key using a specified digest algorithm. This is useful for key identification, trust anchors, and certificate pinning.

## Syntax

```tcl
::tossl::key::fingerprint -key <public_key_pem> ?-alg <digest>?
```

- `-key <public_key_pem>`: PEM-encoded public key (required)
- `-alg <digest>`: Digest algorithm (optional, default: `sha256`). Supported: `sha256`, `sha1`, `sha512`, etc.

## Returns

A hex-encoded string representing the fingerprint of the public key.

## Examples

### Basic Usage

```tcl
set keys [tossl::key::generate -type rsa -bits 2048]
set pub [dict get $keys public]
set fp [tossl::key::fingerprint -key $pub]
puts "Fingerprint (sha256): $fp"
```

### Specify Digest Algorithm

```tcl
set fp_sha1 [tossl::key::fingerprint -key $pub -alg sha1]
puts "Fingerprint (sha1): $fp_sha1"

set fp_sha512 [tossl::key::fingerprint -key $pub -alg sha512]
puts "Fingerprint (sha512): $fp_sha512"
```

### Error Handling

```tcl
# Invalid key
if {[catch {tossl::key::fingerprint -key "not a key"} err]} {
    puts "Error: $err"
}

# Unknown digest
if {[catch {tossl::key::fingerprint -key $pub -alg notadigest} err]} {
    puts "Error: $err"
}
```

## Error Handling

- Returns an error if the key cannot be parsed or is not a public key.
- Returns an error if the digest algorithm is unknown.
- Returns an error if required arguments are missing or too many arguments are provided.

## Security Considerations

- Use strong digest algorithms (e.g., `sha256` or `sha512`) for fingerprinting.
- Do not use fingerprints for authentication unless combined with a secure trust model.

## Best Practices

- Always verify the fingerprint length matches the expected digest output.
- Use fingerprints for key pinning, trust anchors, and audit logs.
- Use in conjunction with `::tossl::key::generate`, `::tossl::key::analyze`, and certificate validation commands.

## Related Commands

- `::tossl::key::generate` — Generate a new key pair
- `::tossl::key::analyze` — Inspect key properties
- `::tossl::key::write` — Serialize a key
- `::tossl::x509::fingerprint` — Compute a certificate fingerprint

## Troubleshooting

- **Error: Failed to parse public key**: Ensure the input is a valid PEM-encoded public key.
- **Error: Unknown digest algorithm**: Use a supported digest (e.g., `sha256`, `sha1`, `sha512`). 