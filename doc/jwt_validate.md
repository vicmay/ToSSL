# JWT Validate Command

## Overview

The `::tossl::jwt::validate` command validates JWT (JSON Web Token) claims including expiration time, issuer, audience, and not-before time. This command parses the JWT payload and performs claim validation according to RFC 7519 standards.

## Syntax

```tcl
::tossl::jwt::validate -token <jwt_string> ?-audience <aud>? ?-issuer <iss>? ?-check_expiration <bool>?
```

## Parameters

- `-token <jwt_string>` (required): The JWT token string to validate
- `-audience <aud>` (optional): Expected audience value to validate against
- `-issuer <iss>` (optional): Expected issuer value to validate against  
- `-check_expiration <bool>` (optional): Whether to check token expiration (default: 1)

## Return Value

Returns a Tcl dictionary containing validation results:

```tcl
{
    valid <boolean>           # 1 if token is valid, 0 if invalid
    issuer <string>          # Token issuer (if present)
    audience <string>        # Token audience (if present)
    subject <string>         # Token subject (if present)
    issued_at <integer>      # Token issued at timestamp (if present)
    not_before <integer>     # Token not-before timestamp (if present)
    expiration <integer>     # Token expiration timestamp (if present)
    jwt_id <string>          # Token JWT ID (if present)
    error <string>           # Error message (if validation failed)
}
```

## Validation Rules

The command validates the following JWT claims:

1. **Expiration (exp)**: Token must not be expired (unless `-check_expiration 0`)
2. **Not Before (nbf)**: Token must not be used before the not-before time
3. **Issuer (iss)**: Token issuer must match expected issuer (if both are provided)
4. **Audience (aud)**: Token audience must match expected audience (if both are provided)

## Examples

### Basic Validation

```tcl
package require tossl

# Create a valid JWT token
set now [clock seconds]
set exp [expr {$now + 3600}]
set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"

set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]

# Validate the token
set result [::tossl::jwt::validate -token $token]
puts "Valid: [dict get $result valid]"
puts "Issuer: [dict get $result issuer]"
puts "Audience: [dict get $result audience]"
```

### Validation with Issuer Check

```tcl
# Validate with specific issuer
set result [::tossl::jwt::validate -token $token -issuer "test-issuer"]
if {[dict get $result valid]} {
    puts "Token is valid with correct issuer"
} else {
    puts "Token validation failed: [dict get $result error]"
}
```

### Validation with Audience Check

```tcl
# Validate with specific audience
set result [::tossl::jwt::validate -token $token -audience "test-audience"]
if {[dict get $result valid]} {
    puts "Token is valid with correct audience"
} else {
    puts "Token validation failed: [dict get $result error]"
}
```

### Validation with All Checks

```tcl
# Validate with issuer and audience checks
set result [::tossl::jwt::validate -token $token -issuer "test-issuer" -audience "test-audience"]
if {[dict get $result valid]} {
    puts "Token is valid with all checks"
} else {
    puts "Token validation failed: [dict get $result error]"
}
```

### Disabled Expiration Check

```tcl
# Validate without checking expiration
set result [::tossl::jwt::validate -token $token -check_expiration 0]
puts "Valid (no expiration check): [dict get $result valid]"
```

### Expired Token Validation

```tcl
# Create an expired token
set now [clock seconds]
set exp [expr {$now - 3600}]  # 1 hour ago
set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
set payload_json "{\"iss\":\"test-issuer\",\"iat\":[expr {$now - 7200}],\"exp\":$exp}"

set expired_token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]

# Validate expired token
set result [::tossl::jwt::validate -token $expired_token]
if {![dict get $result valid]} {
    puts "Token is expired: [dict get $result error]"
}
```

### Not-Before Token Validation

```tcl
# Create a token with not-before time in the future
set now [clock seconds]
set nbf [expr {$now + 3600}]  # 1 hour from now
set exp [expr {$now + 7200}]
set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
set payload_json "{\"iss\":\"test-issuer\",\"iat\":$now,\"nbf\":$nbf,\"exp\":$exp}"

set future_token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]

# Validate token with not-before time
set result [::tossl::jwt::validate -token $future_token]
if {![dict get $result valid]} {
    puts "Token not yet valid: [dict get $result error]"
}
```

## Error Handling

The command handles various error conditions:

### Invalid JWT Format

```tcl
set result [::tossl::jwt::validate -token "invalid.jwt.format"]
puts "Valid: [dict get $result valid]"
puts "Error: [dict get $result error]"
# Output: Valid: 1, Error: Invalid JSON payload
```

### Malformed Payload

```tcl
set header [::tossl::base64url::encode "{\"alg\":\"none\",\"typ\":\"JWT\"}"]
set payload [::tossl::base64url::encode "invalid json"]
set token "$header.$payload."

set result [::tossl::jwt::validate -token $token]
puts "Valid: [dict get $result valid]"
puts "Error: [dict get $result error]"
# Output: Valid: 1, Error: Invalid JSON payload
```

### Missing Parameters

```tcl
# Missing token parameter
if {[catch {::tossl::jwt::validate -issuer "test"} result]} {
    puts "Error: $result"
}
```

## Performance Considerations

The command is optimized for performance:

- Manual JWT parsing to handle empty signature parts
- Efficient JSON parsing using json-c library
- Minimal memory allocations
- Fast timestamp comparisons

## Security Notes

1. **Signature Verification**: This command only validates claims, not cryptographic signatures. Use `::tossl::jwt::verify` for signature verification.

2. **Clock Skew**: The validation uses the system clock. Consider clock skew in distributed systems.

3. **Missing Claims**: If a required claim is missing from the token, the validation may still pass depending on the validation logic.

4. **Error Information**: The command always returns `valid=1` but includes error messages when issues are detected.

## Integration with Other JWT Commands

This command works with other JWT commands:

```tcl
# Create and validate a token
set token [::tossl::jwt::create -header $header -payload $payload -key $key -alg $alg]
set validation [::tossl::jwt::validate -token $token -issuer $expected_issuer]

# Verify signature separately
set verification [::tossl::jwt::verify -token $token -key $key -alg $alg]

# Decode token for inspection
set decoded [::tossl::jwt::decode -token $token]
```

## See Also

- `::tossl::jwt::create` - Create JWT tokens
- `::tossl::jwt::verify` - Verify JWT signatures
- `::tossl::jwt::decode` - Decode JWT tokens
- `::tossl::jwt::extract_claims` - Extract claims from JWT tokens 