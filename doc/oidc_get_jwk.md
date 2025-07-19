# ::tossl::oidc::get_jwk

Retrieve a specific JSON Web Key (JWK) from a JWKS by its key ID (kid).

## Syntax

    tossl::oidc::get_jwk -jwks <jwks_data> -kid <key_id>

## Parameters

- `-jwks <jwks_data>`: The JWKS data containing the keys (required)
- `-kid <key_id>`: The key ID to search for (required)

## Description

Extracts a specific JSON Web Key (JWK) from a JSON Web Key Set (JWKS) by matching the key ID (kid) parameter. This is useful when you need to verify a JWT signature and know which specific key was used to sign it.

The command searches through all keys in the JWKS and returns the first key that matches the specified key ID.

## Return Value

Returns the JWK as a JSON string if found, or throws an error if the key is not found.

Example JWK return value:
```json
{
  "kty": "RSA",
  "kid": "key-id-1",
  "n": "modulus-value",
  "e": "AQAB",
  "alg": "RS256",
  "use": "sig"
}
```

## Examples

### Basic JWK Retrieval

```tcl
# JWKS data with multiple keys
set jwks_data {
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "n": "modulus-1",
      "e": "AQAB",
      "alg": "RS256"
    },
    {
      "kty": "EC",
      "kid": "key-2",
      "crv": "P-256",
      "x": "x-coord",
      "y": "y-coord",
      "alg": "ES256"
    }
  ]
}
}

# Get the RSA key
set rsa_key [tossl::oidc::get_jwk -jwks $jwks_data -kid "key-1"]
puts "RSA Key: $rsa_key"

# Get the EC key
set ec_key [tossl::oidc::get_jwk -jwks $jwks_data -kid "key-2"]
puts "EC Key: $ec_key"
```

### JWK Retrieval from Fetched JWKS

```tcl
# Fetch JWKS from provider
set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://example.com/.well-known/jwks.json"]

# Get a specific key by ID
set signing_key [tossl::oidc::get_jwk -jwks $jwks -kid "signing-key-2023"]

# Use the key for JWT verification (future implementation)
# set verified [tossl::jwt::verify -token $jwt -jwk $signing_key]
```

### Error Handling for Missing Keys

```tcl
set jwks_data {
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "n": "modulus",
      "e": "AQAB"
    }
  ]
}
}

if {[catch {
    set key [tossl::oidc::get_jwk -jwks $jwks_data -kid "non-existent-key"]
} result]} {
    puts "Key not found: $result"
    # Handle missing key scenario
}
```

### Complete OIDC Flow with JWK Retrieval

```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Fetch JWKS
set jwks [tossl::oidc::fetch_jwks -jwks_uri [dict get $config jwks_uri]]

# 3. Extract JWT header to get key ID (future implementation)
# set header [tossl::jwt::get_header -token $id_token]
# set kid [dict get $header kid]

# 4. Get the specific signing key
set signing_key [tossl::oidc::get_jwk -jwks $jwks -kid $kid]

# 5. Verify the JWT signature (future implementation)
# set verified [tossl::oidc::validate_id_token \
#     -token $id_token \
#     -jwk $signing_key \
#     -issuer [dict get $config issuer] \
#     -audience $client_id]
```

## Error Handling

### Key Not Found

```tcl
if {[catch {
    set key [tossl::oidc::get_jwk -jwks $jwks_data -kid "missing-key"]
} result]} {
    puts "Error: $result"
    # Expected: "Key with specified 'kid' not found"
}
```

### Invalid JWKS Format

```tcl
if {[catch {
    set key [tossl::oidc::get_jwk -jwks "invalid json" -kid "key-1"]
} result]} {
    puts "Error: $result"
    # Expected: "Invalid JWKS data"
}
```

### Missing Required Parameters

```tcl
if {[catch {
    tossl::oidc::get_jwk -jwks $jwks_data
} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}
```

## Performance

- **Key Lookup**: O(n) where n is the number of keys in the JWKS
- **Memory Usage**: Minimal - only returns the matching key
- **Typical Performance**: < 1 millisecond for JWKS with < 100 keys

## Security Considerations

1. **Key ID Validation**: The key ID must match exactly (case-sensitive)
2. **JWKS Integrity**: The JWKS should be fetched from a trusted source
3. **Key Rotation**: Be prepared to handle cases where keys are rotated
4. **Multiple Keys**: JWKS may contain multiple keys with the same algorithm

## Integration with JWT Verification

This command is designed to work with JWT verification (future implementation):

```tcl
# Future JWT verification flow
set id_token "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0..."

# Extract key ID from JWT header
set header [tossl::jwt::get_header -token $id_token]
set kid [dict get $header kid]

# Get the signing key
set signing_key [tossl::oidc::get_jwk -jwks $jwks -kid $kid]

# Verify the JWT
set verified [tossl::jwt::verify -token $id_token -jwk $signing_key]
```

## Common Use Cases

1. **JWT Signature Verification**: Get the key used to sign a JWT
2. **Key Rotation**: Handle provider key rotation scenarios
3. **Multiple Algorithms**: Support different signing algorithms
4. **Security Auditing**: Inspect specific keys for security analysis

## See Also

- `::tossl::oidc::fetch_jwks` - Fetch JWKS from provider
- `::tossl::oidc::validate_jwks` - Validate JWKS structure
- `::tossl::jwt::verify` - Verify JWT signatures (future)
- `::tossl::jwt::get_header` - Extract JWT header (future) 