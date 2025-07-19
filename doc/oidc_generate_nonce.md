# ::tossl::oidc::generate_nonce

Generate a cryptographically secure nonce (number used once) for OpenID Connect CSRF protection.

## Syntax

    tossl::oidc::generate_nonce

## Description

Generates a cryptographically secure nonce value for use in OpenID Connect flows. A nonce is a unique, random string that helps prevent Cross-Site Request Forgery (CSRF) attacks by ensuring that the authorization request and token response are linked.

The generated nonce:
- Uses cryptographically secure random number generation (OpenSSL RAND_bytes)
- Is base64url-encoded for safe transmission in URLs
- Has a length of approximately 32-64 characters
- Is suitable for use in OIDC authorization requests and ID token validation

## Return Value

Returns a base64url-encoded string containing the generated nonce.

## Examples

### Basic Nonce Generation

```tcl
# Generate a nonce for OIDC flow
set nonce [tossl::oidc::generate_nonce]
puts "Generated nonce: $nonce"
```

### OIDC Authorization Flow

```tcl
# Generate nonce and state for OIDC authorization
set nonce [tossl::oidc::generate_nonce]
set state [tossl::oauth2::generate_state]

# Create authorization URL with nonce
set auth_url [tossl::oauth2::authorization_url \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "openid profile email" \
    -state $state \
    -authorization_url "https://accounts.google.com/o/oauth2/v2/auth"]

# Store nonce for later validation
set stored_nonce $nonce

puts "Authorization URL: $auth_url"
puts "Nonce to validate later: $stored_nonce"
```

### Multiple Nonce Generation

```tcl
# Generate multiple nonces for different sessions
set nonces {}
for {set i 0} {$i < 5} {incr i} {
    lappend nonces [tossl::oidc::generate_nonce]
}

# Each nonce should be unique
set unique_nonces [lsort -unique $nonces]
if {[llength $unique_nonces] == [llength $nonces]} {
    puts "All nonces are unique"
} else {
    puts "Warning: Duplicate nonces detected"
}
```

### Nonce Validation (Future Implementation)

```tcl
# Generate nonce for authorization request
set nonce [tossl::oidc::generate_nonce]

# Store nonce securely (in session, database, etc.)
set session_nonce $nonce

# Later, when validating ID token
if {[catch {
    set validation [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer $issuer \
        -audience $client_id \
        -nonce $session_nonce]
    
    if {[dict get $validation valid]} {
        puts "ID token validated successfully"
    } else {
        puts "ID token validation failed"
    }
} result]} {
    puts "Validation error: $result"
}
```

## Security Considerations

### CSRF Protection

The nonce provides protection against CSRF attacks by ensuring that:
1. The authorization request and token response are linked
2. An attacker cannot replay an authorization code
3. The ID token contains the same nonce that was sent in the authorization request

### Nonce Storage

Store the generated nonce securely:
- **Session Storage**: Store in server-side session
- **Database**: Store with user session data
- **Secure Cookie**: Store in HTTP-only, secure cookie
- **Memory**: Store in application memory (for short-lived sessions)

### Nonce Validation

When validating ID tokens, ensure that:
1. The nonce in the ID token matches the stored nonce
2. The nonce is used only once
3. The nonce is associated with the correct user session

### Nonce Lifetime

Nonces should have a reasonable lifetime:
- **Short-lived**: 5-15 minutes for typical web applications
- **Session-bound**: Expire when user session expires
- **Single-use**: Each nonce should be used only once

## Error Handling

### Random Number Generation Failure

```tcl
if {[catch {
    set nonce [tossl::oidc::generate_nonce]
} result]} {
    puts "Failed to generate nonce: $result"
    # Handle random number generation failure
    # This could indicate system entropy issues
}
```

## Performance

- **Generation Time**: < 1 millisecond
- **Memory Usage**: Minimal (32-64 bytes per nonce)
- **Entropy Source**: Uses OpenSSL's cryptographically secure random number generator

## Integration with OAuth2

This command is designed to work seamlessly with the existing OAuth2 infrastructure:

```tcl
# Complete OIDC flow with nonce
set nonce [tossl::oidc::generate_nonce]
set state [tossl::oauth2::generate_state]

# Create authorization URL
set auth_url [tossl::oauth2::authorization_url \
    -client_id $client_id \
    -redirect_uri $redirect_uri \
    -scope "openid profile email" \
    -state $state \
    -authorization_url $authorization_endpoint]

# Store nonce and state for later validation
set session_data [dict create \
    nonce $nonce \
    state $state \
    timestamp [clock seconds]]

# Later, validate the response
if {[dict get $session_data state] == $received_state} {
    # State is valid, proceed with token exchange
    set tokens [tossl::oauth2::exchange_code \
        -client_id $client_id \
        -client_secret $client_secret \
        -code $auth_code \
        -redirect_uri $redirect_uri \
        -token_url $token_url]
    
    # Validate ID token with nonce
    # (Future implementation)
}
```

## Best Practices

1. **Always Use Nonces**: Include a nonce in every OIDC authorization request
2. **Store Securely**: Keep nonces in secure, server-side storage
3. **Validate Promptly**: Validate nonces as soon as possible after token receipt
4. **Single Use**: Each nonce should be used only once
5. **Reasonable Lifetime**: Set appropriate expiration times for nonces
6. **Error Handling**: Handle nonce validation failures gracefully

## See Also

- `::tossl::oidc::discover` - Discover OIDC provider configuration
- `::tossl::oauth2::generate_state` - Generate OAuth2 state parameter
- `::tossl::oauth2::authorization_url` - Create OAuth2 authorization URLs
- `::tossl::jwt::validate` - Validate JWT tokens (for future nonce validation) 