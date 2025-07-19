# ::tossl::jwt::decode

Decode a JWT (JSON Web Token) without verification, extracting the header, payload, and signature components.

## Syntax

    tossl::jwt::decode -token <jwt_string>

## Description

The `::tossl::jwt::decode` command decodes a JWT token into its constituent parts without performing any cryptographic verification. This is useful for:

- Inspecting JWT contents for debugging purposes
- Extracting claims from unverified tokens
- Analyzing JWT structure and metadata
- Preparing tokens for manual verification

**Important Security Note**: This command does NOT verify the token's signature. Use `::tossl::jwt::verify` for cryptographic verification or `::tossl::jwt::validate` for comprehensive validation including claims checking.

## Parameters

- `-token <jwt_string>`: The JWT token string to decode (required)

## Return Value

Returns a dictionary containing the decoded JWT components:

- `header`: The decoded JWT header as a JSON string
- `payload`: The decoded JWT payload as a JSON string  
- `signature`: The JWT signature (base64url-encoded)

## Examples

### Basic JWT Decoding

```tcl
# Create a JWT token
set header [dict create alg HS256 typ JWT]
set payload [dict create sub user123 iss example.com exp [expr [clock seconds] + 3600]]
set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]
set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "secret" -alg HS256]

# Decode the JWT
set decoded [tossl::jwt::decode -token $jwt]

# Extract and parse components
set header_dict [tossl::json::parse [dict get $decoded header]]
set payload_dict [tossl::json::parse [dict get $decoded payload]]
set signature [dict get $decoded signature]

puts "Algorithm: [dict get $header_dict alg]"
puts "Subject: [dict get $payload_dict sub]"
puts "Issuer: [dict get $payload_dict iss]"
puts "Signature: $signature"
```

### Inspecting JWT Claims

```tcl
# Decode a JWT and extract specific claims
set decoded [tossl::jwt::decode -token $jwt_token]
set payload [tossl::json::parse [dict get $decoded payload]]

# Check for specific claims
if {[dict exists $payload sub]} {
    puts "Subject: [dict get $payload sub]"
}
if {[dict exists $payload exp]} {
    puts "Expires: [clock format [dict get $payload exp]]"
}
if {[dict exists $payload custom_claim]} {
    puts "Custom: [dict get $payload custom_claim]"
}
```

### Debugging JWT Structure

```tcl
# Decode and analyze JWT structure
set decoded [tossl::jwt::decode -token $jwt_token]

puts "=== JWT Structure Analysis ==="
puts "Header: [dict get $decoded header]"
puts "Payload: [dict get $decoded payload]"
puts "Signature length: [string length [dict get $decoded signature]]"

# Parse header for algorithm info
set header [tossl::json::parse [dict get $decoded header]]
puts "Algorithm: [dict get $header alg]"
puts "Type: [dict get $header typ]"
```

### Working with Different JWT Algorithms

```tcl
# Decode JWTs with different signing algorithms
set algorithms {HS256 HS384 HS512 RS256 ES256}

foreach alg $algorithms {
    # Create JWT with specific algorithm
    set header [dict create alg $alg typ JWT]
    set payload [dict create sub "user" iss "example.com"]
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    if {[string match "HS*" $alg]} {
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "secret" -alg $alg]
    } else {
        # Use appropriate key for RSA/EC algorithms
        set key_data [tossl::key::generate -type [string tolower [string range $alg 0 1]] -bits 2048]
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key [dict get $key_data private] -alg $alg]
    }
    
    # Decode and verify algorithm
    set decoded [tossl::jwt::decode -token $jwt]
    set header_dict [tossl::json::parse [dict get $decoded header]]
    puts "Algorithm $alg: [dict get $header_dict alg]"
}
```

## Error Handling

### Invalid JWT Format

```tcl
if {[catch {
    set decoded [tossl::jwt::decode -token "invalid.jwt.format"]
} result]} {
    puts "Error: $result"
    # Expected: "Invalid JWT format"
}
```

### Missing Token Parts

```tcl
if {[catch {
    set decoded [tossl::jwt::decode -token "header.payload"]
} result]} {
    puts "Error: $result"
    # Expected: "Invalid JWT format"
}
```

### Invalid Base64URL Encoding

```tcl
if {[catch {
    set decoded [tossl::jwt::decode -token "invalid.base64.part"]
} result]} {
    puts "Error: $result"
    # Expected: "Failed to decode JWT parts"
}
```

### Wrong Number of Arguments

```tcl
if {[catch {
    tossl::jwt::decode
} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}

if {[catch {
    tossl::jwt::decode -token "test" extra
} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}
```

## Security Considerations

### ⚠️ Important Security Warnings

1. **No Cryptographic Verification**: This command does NOT verify the JWT signature. The token may be tampered with or forged.

2. **Use for Debugging Only**: Only use this command for debugging, logging, or analysis purposes.

3. **Always Verify Before Trusting**: For production use, always verify JWTs using `::tossl::jwt::verify` or `::tossl::jwt::validate`.

4. **Sensitive Data Exposure**: Decoded payloads may contain sensitive information. Handle with appropriate security measures.

### Secure Usage Pattern

```tcl
# ❌ UNSAFE: Trusting decoded data without verification
set decoded [tossl::jwt::decode -token $jwt]
set payload [tossl::json::parse [dict get $decoded payload]]
set user_id [dict get $payload sub]  # Could be forged!

# ✅ SAFE: Verify before trusting
set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg RS256]
if {[dict get $verify_result valid]} {
    set decoded [tossl::jwt::decode -token $jwt]
    set payload [tossl::json::parse [dict get $decoded payload]]
    set user_id [dict get $payload sub]  # Now trusted
} else {
    puts "Token verification failed"
}
```

## Integration with Other Commands

### Combined with Verification

```tcl
proc secure_jwt_decode {token key alg} {
    # First verify the token
    set verify_result [tossl::jwt::verify -token $token -key $key -alg $alg]
    
    if {![dict get $verify_result valid]} {
        error "JWT verification failed: [dict get $verify_result error]"
    }
    
    # Then decode the verified token
    return [tossl::jwt::decode -token $token]
}

# Usage
set decoded [secure_jwt_decode $jwt $public_key RS256]
```

### Combined with Claims Validation

```tcl
proc decode_and_validate {token issuer audience} {
    # Decode first
    set decoded [tossl::jwt::decode -token $token]
    set payload [tossl::json::parse [dict get $decoded payload]]
    
    # Then validate claims
    set validate_result [tossl::jwt::validate -token $token -issuer $issuer -audience $audience]
    
    return [dict create \
        decoded $decoded \
        payload $payload \
        valid [dict get $validate_result valid]]
}
```

### JWT Analysis Tool

```tcl
proc analyze_jwt {token} {
    set result [dict create]
    
    # Decode the token
    if {[catch {
        set decoded [tossl::jwt::decode -token $token]
        dict set result decoded $decoded
        
        # Parse header and payload
        set header [tossl::json::parse [dict get $decoded header]]
        set payload [tossl::json::parse [dict get $decoded payload]]
        
        dict set result header $header
        dict set result payload $payload
        dict set result signature_length [string length [dict get $decoded signature]]
        
        # Extract common claims
        if {[dict exists $payload iss]} {
            dict set result issuer [dict get $payload iss]
        }
        if {[dict exists $payload sub]} {
            dict set result subject [dict get $payload sub]
        }
        if {[dict exists $payload exp]} {
            dict set result expires [dict get $payload exp]
        }
        
    } error]} {
        dict set result error $error
    }
    
    return $result
}
```

## Performance Considerations

### Decoding Performance

- **Fast Operation**: JWT decoding is a fast operation, typically completing in microseconds
- **Memory Efficient**: Minimal memory allocation for base64url decoding
- **No Cryptographic Operations**: No expensive signature verification or key operations

### Benchmark Example

```tcl
proc benchmark_jwt_decode {token iterations} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set decoded [tossl::jwt::decode -token $token]
    }
    
    set end_time [clock milliseconds]
    set duration [expr $end_time - $start_time]
    
    puts "Decoded $iterations JWTs in ${duration}ms"
    puts "Average: [expr $duration.0 / $iterations]ms per decode"
}

# Example usage
set jwt [create_test_jwt]
benchmark_jwt_decode $jwt 1000
```

## Error Messages

| Error Condition | Error Message |
|----------------|---------------|
| Wrong number of arguments | `wrong # args: should be "tossl::jwt::decode -token <jwt_string>"` |
| Invalid JWT format (missing parts) | `Invalid JWT format` |
| Failed base64url decoding | `Failed to decode JWT parts` |
| Empty token | `Invalid JWT format` |

## Related Commands

- `::tossl::jwt::create` - Create JWT tokens
- `::tossl::jwt::verify` - Verify JWT signatures
- `::tossl::jwt::validate` - Validate JWT claims and signature
- `::tossl::jwt::extract_claims` - Extract specific JWT claims
- `::tossl::json::parse` - Parse JSON strings
- `::tossl::json::generate` - Generate JSON strings

## Standards Compliance

This command implements JWT decoding according to RFC 7519 (JSON Web Token) specifications:

- Base64URL encoding/decoding (RFC 4648)
- JWT structure (header.payload.signature)
- JSON parsing of header and payload
- No signature verification (as per command purpose)

## See Also

- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [RFC 4648 - Base64URL Encoding](https://tools.ietf.org/html/rfc4648)
- `::tossl::jwt::verify` - For secure JWT verification
- `::tossl::jwt::validate` - For comprehensive JWT validation 