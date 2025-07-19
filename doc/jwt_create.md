# ::tossl::jwt::create

Create a JWT (JSON Web Token) with cryptographic signature using various algorithms.

## Syntax

    tossl::jwt::create -header <header_json> -payload <payload_json> -key <key> -alg <algorithm>

## Description

The `::tossl::jwt::create` command creates a cryptographically signed JWT token according to RFC 7519 (JSON Web Token) specifications. This command supports multiple signing algorithms and key types for different security requirements.

**Security Note**: Always use appropriate key sizes and algorithms for your security requirements. The "none" algorithm should only be used for testing purposes.

## Parameters

- `-header <header_json>`: JWT header as a JSON string (required)
- `-payload <payload_json>`: JWT payload as a JSON string (required)
- `-key <key>`: Signing key (required)
  - For HMAC algorithms: Secret key string
  - For RSA/EC algorithms: PEM-encoded private key
  - For "none" algorithm: Empty string
- `-alg <algorithm>`: Signing algorithm (required)
  - HMAC: `HS256`, `HS384`, `HS512`
  - RSA: `RS256`, `RS384`, `RS512`
  - EC: `ES256`, `ES384`, `ES512`
  - None: `none` (for testing only)

## Return Value

Returns the complete JWT token as a string in the format `header.payload.signature`.

## Supported Algorithms

### HMAC Algorithms (Symmetric)
- **HS256**: HMAC with SHA-256
- **HS384**: HMAC with SHA-384
- **HS512**: HMAC with SHA-512

### RSA Algorithms (Asymmetric)
- **RS256**: RSA with SHA-256
- **RS384**: RSA with SHA-384
- **RS512**: RSA with SHA-512

### Elliptic Curve Algorithms (Asymmetric)
- **ES256**: ECDSA with SHA-256 (P-256 curve)
- **ES384**: ECDSA with SHA-384 (P-384 curve)
- **ES512**: ECDSA with SHA-512 (P-521 curve)

### None Algorithm (Testing Only)
- **none**: No signature (for testing purposes only)

## Examples

### Basic JWT Creation with HMAC

```tcl
# Create header and payload
set header [dict create alg HS256 typ JWT]
set payload [dict create \
    sub "user123" \
    iss "example.com" \
    exp [expr [clock seconds] + 3600] \
    iat [clock seconds]]

# Convert to JSON
set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

# Create JWT
set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "my_secret_key" -alg HS256]

puts "JWT: $jwt"
```

### JWT Creation with RSA

```tcl
# Generate RSA key pair
set key_data [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $key_data private]
set public_key [dict get $key_data public]

# Create header and payload
set header [dict create alg RS256 typ JWT]
set payload [dict create \
    sub "user456" \
    iss "secure-app.com" \
    aud "api.example.com" \
    exp [expr [clock seconds] + 7200]]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

# Create JWT with RSA private key
set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg RS256]

# Verify with public key
set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg RS256]
puts "Verification result: [dict get $verify_result valid]"
```

### JWT Creation with Elliptic Curve

```tcl
# Generate EC key pair
set key_data [tossl::key::generate -type ec -curve prime256v1]
set private_key [dict get $key_data private]
set public_key [dict get $key_data public]

# Create header and payload
set header [dict create alg ES256 typ JWT]
set payload [dict create \
    sub "user789" \
    iss "ec-app.com" \
    exp [expr [clock seconds] + 3600]]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

# Create JWT with EC private key
set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg ES256]
```

### JWT with Complex Claims

```tcl
set header [dict create alg HS256 typ JWT]
set payload [dict create \
    sub "complex_user" \
    iss "complex-app.com" \
    aud "api.example.com" \
    exp [expr [clock seconds] + 7200] \
    iat [clock seconds] \
    nbf [clock seconds] \
    jti "unique-token-id" \
    custom_claim "custom_value" \
    roles [list "user" "admin"] \
    permissions [dict create \
        read true \
        write true \
        delete false] \
    metadata [dict create \
        version "1.0" \
        environment "production"]]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "complex_secret" -alg HS256]
```

### JWT with Timing Claims

```tcl
set current_time [clock seconds]
set header [dict create alg HS256 typ JWT]
set payload [dict create \
    sub "timing_user" \
    iss "timing-app.com" \
    iat $current_time \
    exp [expr $current_time + 3600] \
    nbf [expr $current_time - 60]]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "timing_secret" -alg HS256]
```

### JWT with Custom Header Fields

```tcl
set header [dict create \
    alg HS256 \
    typ JWT \
    kid "key-id-123" \
    x5t "thumbprint-456" \
    custom_header "custom_value"]
set payload [dict create sub "custom_user" iss "custom-app.com"]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "custom_secret" -alg HS256]
```

## Error Handling

### Missing Required Parameters

```tcl
# Missing parameters
if {[catch {tossl::jwt::create} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}

# Missing key and algorithm
if {[catch {tossl::jwt::create -header "{}" -payload "{}"} result]} {
    puts "Error: $result"
    # Expected: "Missing required parameters"
}

# Missing payload
if {[catch {tossl::jwt::create -header "{}" -key "secret" -alg HS256} result]} {
    puts "Error: $result"
    # Expected: "Missing required parameters"
}
```

### Invalid Key for Algorithm

```tcl
# Invalid RSA key for RSA algorithm
if {[catch {
    tossl::jwt::create -header "{}" -payload "{}" -key "invalid_key" -alg RS256
} result]} {
    puts "Error: $result"
    # Expected: "Invalid RSA private key or PEM format error"
}

# Invalid EC key for EC algorithm
if {[catch {
    tossl::jwt::create -header "{}" -payload "{}" -key "invalid_key" -alg ES256
} result]} {
    puts "Error: $result"
    # Expected: "Invalid EC private key or PEM format error"
}
```

### Invalid Algorithm

```tcl
# Invalid algorithm defaults to HS256
set jwt [tossl::jwt::create -header "{}" -payload "{}" -key "secret" -alg INVALID]
# This will work with HS256 verification
```

### Encoding Errors

```tcl
# Invalid JSON in header or payload
if {[catch {
    tossl::jwt::create -header "invalid json" -payload "{}" -key "secret" -alg HS256
} result]} {
    puts "Error: $result"
    # May fail during base64url encoding
}
```

## Security Considerations

### ⚠️ Important Security Warnings

1. **Key Management**: Store private keys securely and never expose them in code or logs.

2. **Algorithm Selection**: Choose algorithms based on security requirements:
   - **HS256/384/512**: Good for symmetric scenarios, requires secure key sharing
   - **RS256/384/512**: Good for asymmetric scenarios, public key distribution
   - **ES256/384/512**: Good for asymmetric scenarios with smaller key sizes

3. **Key Sizes**: Use appropriate key sizes:
   - HMAC: At least 256 bits (32 bytes)
   - RSA: At least 2048 bits
   - EC: At least 256 bits (P-256 curve)

4. **Token Expiration**: Always include expiration claims (`exp`) in production tokens.

5. **None Algorithm**: The "none" algorithm should only be used for testing and debugging.

### Secure Usage Patterns

```tcl
# ✅ SECURE: Use strong keys and appropriate algorithms
set jwt [tossl::jwt::create \
    -header $header_json \
    -payload $payload_json \
    -key $strong_private_key \
    -alg RS256]

# ✅ SECURE: Include expiration and other security claims
set payload [dict create \
    sub $user_id \
    iss $issuer \
    aud $audience \
    exp [expr [clock seconds] + $token_lifetime] \
    iat [clock seconds] \
    nbf [clock seconds]]

# ❌ UNSAFE: Using weak keys or no expiration
set jwt [tossl::jwt::create \
    -header $header_json \
    -payload $payload_json \
    -key "weak_secret" \
    -alg HS256]
```

## Integration with Other Commands

### Complete JWT Workflow

```tcl
proc create_secure_jwt {user_id issuer audience lifetime} {
    # Generate strong key
    set key_data [tossl::key::generate -type rsa -bits 2048]
    set private_key [dict get $key_data private]
    
    # Create header and payload
    set header [dict create alg RS256 typ JWT]
    set payload [dict create \
        sub $user_id \
        iss $issuer \
        aud $audience \
        exp [expr [clock seconds] + $lifetime] \
        iat [clock seconds]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    # Create JWT
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg RS256]
    
    return [dict create \
        jwt $jwt \
        public_key [dict get $key_data public]]
}

# Usage
set result [create_secure_jwt "user123" "myapp.com" "api.example.com" 3600]
set jwt [dict get $result jwt]
set public_key [dict get $result public_key]
```

### JWT with Claims Validation

```tcl
proc create_validated_jwt {user_id issuer audience} {
    # Create JWT
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub $user_id \
        iss $issuer \
        aud $audience \
        exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "secret" -alg HS256]
    
    # Validate the created JWT
    set validate_result [tossl::jwt::validate -token $jwt -issuer $issuer -audience $audience]
    
    if {![dict get $validate_result valid]} {
        error "JWT validation failed: [dict get $validate_result error]"
    }
    
    return $jwt
}
```

### JWT Factory Pattern

```tcl
proc jwt_factory {algorithm key} {
    return [list \
        create [list apply {{header payload key alg} {
            set header_json [tossl::json::generate $header]
            set payload_json [tossl::json::generate $payload]
            return [tossl::jwt::create -header $header_json -payload $payload_json -key $key -alg $alg]
        }} $key $algorithm]] \
        verify [list apply {{token key alg} {
            return [tossl::jwt::verify -token $token -key $key -alg $alg]
        }} $key $algorithm]]
}

# Usage
set factory [jwt_factory HS256 "my_secret"]
set create_cmd [lindex $factory 0]
set verify_cmd [lindex $factory 1]

set header [dict create alg HS256 typ JWT]
set payload [dict create sub "user" iss "app.com"]
set jwt [apply $create_cmd $header $payload]

set verify_result [apply $verify_cmd $jwt]
```

## Performance Considerations

### Creation Performance

- **HMAC algorithms**: Fastest, typically microseconds per token
- **RSA algorithms**: Moderate, depends on key size (2048-bit: ~1-5ms)
- **EC algorithms**: Fast, typically 1-2ms per token
- **None algorithm**: Fastest, no cryptographic operations

### Benchmark Example

```tcl
proc benchmark_jwt_creation {algorithm key iterations} {
    set header [dict create alg $algorithm typ JWT]
    set payload [dict create sub "user" iss "test.com"]
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $key -alg $algorithm]
    }
    
    set end_time [clock milliseconds]
    set duration [expr $end_time - $start_time]
    
    puts "Created $iterations JWTs with $algorithm in ${duration}ms"
    puts "Average: [expr $duration.0 / $iterations]ms per JWT"
}

# Example usage
benchmark_jwt_creation HS256 "secret" 1000
benchmark_jwt_creation RS256 $private_key 100
benchmark_jwt_creation ES256 $ec_private_key 100
```

### Memory Usage

- **Minimal allocation**: JWT creation uses minimal memory allocation
- **No memory leaks**: All allocated memory is properly freed
- **Efficient encoding**: Base64URL encoding is optimized for performance

## Error Messages

| Error Condition | Error Message |
|----------------|---------------|
| Wrong number of arguments | `wrong # args: should be "tossl::jwt::create -header <header_dict> -payload <payload_dict> -key <key> -alg <algorithm>"` |
| Missing required parameters | `Missing required parameters` |
| Invalid RSA private key | `Invalid RSA private key or PEM format error` |
| Invalid EC private key | `Invalid EC private key or PEM format error` |
| Failed to create BIO | `Failed to create BIO for RSA/EC key` |
| Failed to generate signature | `Failed to generate signature` |
| Failed to encode | `Failed to encode header or payload` |

## Related Commands

- `::tossl::jwt::verify` - Verify JWT signatures
- `::tossl::jwt::decode` - Decode JWT without verification
- `::tossl::jwt::validate` - Validate JWT claims and signature
- `::tossl::jwt::extract_claims` - Extract specific JWT claims
- `::tossl::key::generate` - Generate cryptographic keys
- `::tossl::json::generate` - Generate JSON strings
- `::tossl::json::parse` - Parse JSON strings

## Standards Compliance

This command implements JWT creation according to RFC 7519 (JSON Web Token) specifications:

- JWT structure (header.payload.signature)
- Base64URL encoding (RFC 4648)
- JSON encoding of header and payload
- Cryptographic signatures using OpenSSL
- Algorithm support for HMAC, RSA, and EC

## Implementation Notes

### Empty Signature Handling

The "none" algorithm creates JWTs with empty signature parts, which are now properly handled by all JWT functions:
- `::tossl::jwt::decode` - Correctly handles empty signature parts
- `::tossl::jwt::verify` - Correctly handles empty signature parts
- `::tossl::jwt::validate` - Correctly handles empty signature parts
- `::tossl::jwt::extract_claims` - Correctly handles empty signature parts

The implementation uses manual string parsing instead of `strtok` to properly handle empty signature parts.

## See Also

- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [RFC 4648 - Base64URL Encoding](https://tools.ietf.org/html/rfc4648)
- `::tossl::jwt::verify` - For JWT verification
- `::tossl::jwt::validate` - For comprehensive JWT validation
- `::tossl::key::generate` - For key generation 