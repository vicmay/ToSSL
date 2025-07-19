# OIDC ID Token Validation

## Overview

The `tossl::oidc::validate_id_token` command validates OpenID Connect ID tokens according to the OpenID Connect Core 1.0 specification. This command performs comprehensive validation including issuer verification, audience validation, expiration checks, nonce validation, and claims extraction.

## Command Syntax

```tcl
tossl::oidc::validate_id_token -token <id_token> -issuer <issuer> -audience <audience> ?-nonce <nonce>? ?-max_age <seconds>? ?-acr_values <acr>? ?-auth_time <timestamp>?
```

## Parameters

### Required Parameters

- **`-token`** `<id_token>`: The JWT ID token to validate
- **`-issuer`** `<issuer>`: The expected issuer (must match the `iss` claim)
- **`-audience`** `<audience>`: The expected audience (must match the `aud` claim)

### Optional Parameters

- **`-nonce`** `<nonce>`: The nonce value to validate against the token's `nonce` claim
- **`-max_age`** `<seconds>`: Maximum age in seconds for the `auth_time` claim
- **`-acr_values`** `<acr>`: Expected Authentication Context Class Reference (ACR) value
- **`-auth_time`** `<timestamp>`: Current authentication time for max_age validation

## Return Value

Returns a dictionary containing validation results and extracted claims:

```tcl
{
    valid 1
    issuer "https://accounts.google.com"
    audience "your_client_id"
    subject "user123"
    nonce "generated_nonce"
    issued_at 1640995200
    expiration 1640998800
    auth_time 1640994900
    acr "urn:mace:incommon:iap:bronze"
    error "validation_error_message"  ;# Only present if valid=0
}
```

## Validation Rules

The command performs the following validations according to OpenID Connect Core 1.0:

1. **JWT Format**: Validates that the token is a properly formatted JWT
2. **Issuer Validation**: Ensures the `iss` claim matches the expected issuer
3. **Audience Validation**: Ensures the `aud` claim matches the expected audience
4. **Expiration Validation**: Checks that the token has not expired (`exp` claim)
5. **Not-Before Validation**: Ensures the token is not used before its `nbf` time
6. **Nonce Validation**: Validates the `nonce` claim if provided
7. **Max Age Validation**: Checks `auth_time` against `max_age` if provided
8. **ACR Validation**: Validates the `acr` claim if provided

## Examples

### Basic ID Token Validation

```tcl
# Validate a basic ID token
set result [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "your_client_id"]

if {[dict get $result valid]} {
    puts "Token is valid for user: [dict get $result subject]"
} else {
    puts "Token validation failed: [dict get $result error]"
}
```

### ID Token with Nonce Validation

```tcl
# Generate nonce for CSRF protection
set nonce [tossl::oidc::generate_nonce]

# Validate token with nonce
set result [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "your_client_id" \
    -nonce $nonce]

if {![dict get $result valid]} {
    error "Token validation failed: [dict get $result error]"
}
```

### ID Token with Max Age Validation

```tcl
# Validate token with max_age (5 minutes)
set result [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "your_client_id" \
    -max_age 300]

if {![dict get $result valid]} {
    error "Token validation failed: [dict get $result error]"
}
```

### Complete OIDC Flow Example

```tcl
# 1. Generate nonce for the authorization request
set nonce [tossl::oidc::generate_nonce]

# 2. Create authorization URL with nonce
set auth_url [tossl::oauth2::authorization_url \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url "https://accounts.google.com/o/oauth2/v2/auth"]

# 3. After user authorization, exchange code for tokens
set tokens [tossl::oauth2::exchange_code \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -code $auth_code \
    -redirect_uri "https://your-app.com/callback" \
    -token_url "https://oauth2.googleapis.com/token"]

# 4. Validate the ID token
set id_token [dict get $tokens id_token]
set result [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "your_client_id" \
    -nonce $nonce]

if {![dict get $result valid]} {
    error "ID token validation failed: [dict get $result error]"
}

puts "User authenticated: [dict get $result subject]"
```

## Error Handling

The command returns detailed error messages for validation failures:

- **"Invalid JWT format"**: Token is not a valid JWT structure
- **"Invalid JWT payload"**: Token payload cannot be parsed as JSON
- **"Issuer mismatch"**: Token issuer does not match expected issuer
- **"Audience mismatch"**: Token audience does not match expected audience
- **"Token expired"**: Token has expired (exp claim)
- **"Token not yet valid (nbf)"**: Token is not yet valid (nbf claim)
- **"Nonce mismatch"**: Token nonce does not match expected nonce
- **"Authentication too old (max_age)"**: Auth time exceeds max_age limit
- **"ACR mismatch"**: Token ACR does not match expected ACR

## Security Considerations

1. **Always validate the issuer**: Ensures tokens come from the expected OpenID Provider
2. **Always validate the audience**: Prevents token reuse across different clients
3. **Use nonce validation**: Provides CSRF protection for authorization flows
4. **Check expiration times**: Ensures tokens are not used after expiration
5. **Validate max_age**: Ensures authentication freshness for sensitive operations
6. **Verify ACR values**: Ensures appropriate authentication context for the operation

## Integration with Other OIDC Commands

This command works seamlessly with other OIDC commands:

- **`tossl::oidc::generate_nonce`**: Generate nonces for CSRF protection
- **`tossl::oidc::discover`**: Get issuer information for validation
- **`tossl::oidc::fetch_jwks`**: Fetch public keys for signature verification (future enhancement)

## Notes

- The command currently validates JWT structure and claims but does not verify signatures
- Signature verification will be added in a future enhancement using JWKS
- All time-based validations use the current system time
- The command is designed to be secure by default and fail validation on any error 