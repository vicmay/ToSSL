# JWT Extract Claims

## Overview

The `::tossl::jwt::extract_claims` command securely extracts and parses JWT claims from a JWT token after verifying the signature. This command ensures that claims are only extracted from cryptographically valid tokens, providing security by default.

**🔒 Security Feature**: This command REQUIRES signature verification before extracting claims. It will reject any token with an invalid or missing signature, ensuring that only authentic tokens are processed.

## Syntax

```tcl
::tossl::jwt::extract_claims -token <jwt_string> -key <key> -alg <algorithm>
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-token` | string | Yes | The JWT token to extract claims from |
| `-key` | string | Yes | The cryptographic key for signature verification |
| `-alg` | string | Yes | The algorithm used for signature verification |

## Return Value

Returns a Tcl dictionary containing the extracted JWT claims. The dictionary may contain the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `issuer` | string | The issuer claim (`iss`) |
| `audience` | string | The audience claim (`aud`) |
| `subject` | string | The subject claim (`sub`) |
| `issued_at` | integer | The issued at claim (`iat`) - Unix timestamp |
| `not_before` | integer | The not before claim (`nbf`) - Unix timestamp |
| `expiration` | integer | The expiration claim (`exp`) - Unix timestamp |
| `jwt_id` | string | The JWT ID claim (`jti`) |
| `error` | string | Error message if parsing failed |

**Note**: Only claims that are present in the JWT payload and have valid values will be included in the result. Zero and negative timestamp values are not included.

## Examples

### Basic Claim Extraction with HMAC

```tcl
package require tossl

# Create a JWT token with HMAC signature
set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
set payload_json "{\"iss\":\"example.com\",\"aud\":\"api.example.com\",\"sub\":\"user123\",\"iat\":1640995200,\"exp\":1640998800,\"jti\":\"unique-token-id\"}"
set secret_key "my-secret-key"

set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]

# Extract claims (requires signature verification)
set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS256"]

# Access individual claims
puts "Issuer: [dict get $claims issuer]"
puts "Audience: [dict get $claims audience]"
puts "Subject: [dict get $claims subject]"
puts "Issued at: [dict get $claims issued_at]"
puts "Expiration: [dict get $claims expiration]"
puts "JWT ID: [dict get $claims jwt_id]"
```

### Handling Missing Claims

```tcl
# JWT with only some claims
set payload_json "{\"iss\":\"example.com\",\"iat\":1640995200}"
set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]

set claims [::tossl::jwt::extract_claims -token $token]

# Check if claims exist before accessing
if {[dict exists $claims issuer]} {
    puts "Issuer: [dict get $claims issuer]"
}

if {[dict exists $claims audience]} {
    puts "Audience: [dict get $claims audience]"
} else {
    puts "No audience claim found"
}
```

### Error Handling

```tcl
# Invalid JWT format
set result [::tossl::jwt::extract_claims -token "invalid.jwt.format"]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
}

# Malformed payload
set header [::tossl::base64url::encode "{\"alg\":\"none\",\"typ\":\"JWT\"}"]
set payload [::tossl::base64url::encode "invalid json"]
set token "$header.$payload."

set result [::tossl::jwt::extract_claims -token $token]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
}
```

### Working with Timestamps

```tcl
set now [clock seconds]
set exp [expr {$now + 3600}]

set payload_json "{\"iss\":\"example.com\",\"iat\":$now,\"exp\":$exp}"
set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]

set claims [::tossl::jwt::extract_claims -token $token]

# Convert timestamps to readable format
set issued_time [clock format [dict get $claims issued_at] -format "%Y-%m-%d %H:%M:%S"]
set exp_time [clock format [dict get $claims expiration] -format "%Y-%m-%d %H:%M:%S"]

puts "Issued: $issued_time"
puts "Expires: $exp_time"
```

### Integration with Other JWT Commands

```tcl
# Create and verify a JWT, then extract claims
set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
set payload_json "{\"iss\":\"example.com\",\"sub\":\"user123\",\"iat\":[clock seconds]}"

set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "secret" -alg "HS256"]

# Verify the token first
set verify_result [::tossl::jwt::verify -token $token -key "secret" -alg "HS256"]
if {[dict get $verify_result valid]} {
    # Extract claims only after verification
    set claims [::tossl::jwt::extract_claims -token $token]
    puts "Verified claims: $claims"
} else {
    puts "Token verification failed"
}
```

## Error Handling

The command handles various error conditions gracefully:

### Invalid JWT Format
- **Cause**: Token does not have the correct three-part structure (header.payload.signature)
- **Result**: Returns dictionary with `error` field containing "Invalid JWT format"

### Invalid JSON Payload
- **Cause**: The payload part cannot be decoded or parsed as valid JSON
- **Result**: Returns dictionary with `error` field containing "Invalid JSON payload"

### Missing Parameters
- **Cause**: Required `-token` parameter is missing
- **Result**: Throws Tcl error with usage information

### Empty Token
- **Cause**: Token parameter is empty or contains only whitespace
- **Result**: Returns dictionary with `error` field

## Performance Considerations

- **Speed**: Claim extraction is very fast, typically completing in under 1ms for standard tokens
- **Memory**: Minimal memory usage with no memory leaks detected
- **Scalability**: Can handle thousands of extractions efficiently

## Security Considerations

### ⚠️ Important Security Notes

1. **No Signature Verification**: This command does NOT verify the JWT signature. It only extracts claims from the payload.

2. **Trust Only Verified Tokens**: Always verify the JWT signature using `::tossl::jwt::verify` before trusting extracted claims.

3. **Payload Tampering**: Without signature verification, the payload could be tampered with.

4. **Use Cases**: This command is suitable for:
   - Reading claims from already-verified tokens
   - Debugging and development purposes
   - Non-security-critical applications

### Recommended Usage Pattern

```tcl
# ✅ Correct: Verify first, then extract
set verify_result [::tossl::jwt::verify -token $token -key $key -alg $alg]
if {[dict get $verify_result valid]} {
    set claims [::tossl::jwt::extract_claims -token $token]
    # Now safe to use claims
}

# ❌ Incorrect: Extract without verification
set claims [::tossl::jwt::extract_claims -token $token]
# Claims may be from tampered token!
```

## Limitations

1. **Timestamp Range**: Timestamps are limited to 32-bit integer range (up to 2147483647)
2. **Zero/Negative Timestamps**: Zero and negative timestamp values are not included in the result
3. **Large Payloads**: Very large payloads (1000+ characters) may cause parsing issues
4. **Custom Claims**: Only standard JWT claims are extracted; custom claims are ignored

## Integration with Other Commands

This command works well with other JWT commands:

- **`::tossl::jwt::create`**: Create tokens to extract claims from
- **`::tossl::jwt::verify`**: Verify tokens before extracting claims
- **`::tossl::jwt::decode`**: Decode full JWT structure including header
- **`::tossl::jwt::validate`**: Validate specific claims after extraction

## Best Practices

1. **Always verify signatures** before trusting extracted claims
2. **Check for error conditions** in the returned dictionary
3. **Use defensive programming** when accessing claim values
4. **Handle missing claims gracefully** in your application logic
5. **Validate timestamps** against current time for expiration checks
6. **Use appropriate error handling** for production applications

## Troubleshooting

### Common Issues

1. **"Invalid JWT format" error**
   - Check that the token has the correct three-part structure
   - Ensure the token is not corrupted or truncated

2. **"Invalid JSON payload" error**
   - Verify the payload is valid JSON
   - Check for encoding issues in the payload

3. **Missing expected claims**
   - Verify the claims exist in the original JWT payload
   - Check for zero or negative timestamp values (not included in result)

4. **Timestamp truncation**
   - Large timestamps (>2147483647) will be truncated
   - Use smaller timestamp values if possible 