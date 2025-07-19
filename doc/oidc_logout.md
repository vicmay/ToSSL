# OIDC Logout (RP-Initiated Logout)

## Overview

The OIDC logout commands provide support for OpenID Connect RP-Initiated Logout 1.0. These commands allow you to initiate user logout sessions, generate logout URLs, and validate logout responses from OpenID Connect providers.

## Commands

### `tossl::oidc::logout_url`

Generates a logout URL for redirecting users to the OpenID Connect provider's logout endpoint.

#### Syntax

```tcl
tossl::oidc::logout_url -id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?
```

#### Parameters

- **`-id_token_hint`** `<id_token>`: The ID token to include as a hint for the logout
- **`-end_session_endpoint`** `<url>`: The end session endpoint URL from the OIDC provider
- **`-post_logout_redirect_uri`** `<uri>`: (Optional) URI to redirect to after logout
- **`-state`** `<state>`: (Optional) State parameter for CSRF protection

#### Return Value

Returns a complete logout URL with all parameters properly encoded.

#### Example

```tcl
# Generate basic logout URL
set logout_url [tossl::oidc::logout_url \
    -id_token_hint $id_token \
    -end_session_endpoint "https://accounts.google.com/o/oauth2/v2/logout"]

puts "Logout URL: $logout_url"

# Generate logout URL with redirect and state
set logout_url [tossl::oidc::logout_url \
    -id_token_hint $id_token \
    -end_session_endpoint "https://accounts.google.com/o/oauth2/v2/logout" \
    -post_logout_redirect_uri "https://myapp.com/logout" \
    -state "logout_state_123"]
```

### `tossl::oidc::end_session`

Performs an end session request to the OpenID Connect provider.

#### Syntax

```tcl
tossl::oidc::end_session -id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?
```

#### Parameters

- **`-id_token_hint`** `<id_token>`: The ID token to include as a hint for the logout
- **`-end_session_endpoint`** `<url>`: The end session endpoint URL from the OIDC provider
- **`-post_logout_redirect_uri`** `<uri>`: (Optional) URI to redirect to after logout
- **`-state`** `<state>`: (Optional) State parameter for CSRF protection

#### Return Value

Returns a dictionary containing the logout result:

```tcl
{
    success 1
    response "logout response data"
}
```

#### Example

```tcl
# Perform end session request
set result [tossl::oidc::end_session \
    -id_token_hint $id_token \
    -end_session_endpoint "https://accounts.google.com/o/oauth2/v2/logout" \
    -post_logout_redirect_uri "https://myapp.com/logout" \
    -state "logout_state_123"]

if {[dict get $result success]} {
    puts "Logout successful"
} else {
    puts "Logout failed"
}
```

### `tossl::oidc::validate_logout_response`

Validates a logout response from the OpenID Connect provider.

#### Syntax

```tcl
tossl::oidc::validate_logout_response -response <response_data>
```

#### Parameters

- **`-response`** `<response_data>`: The logout response data to validate

#### Return Value

Returns a validation result with response type and content:

```tcl
# Empty response (successful logout)
{
    valid 1
    type "empty_response"
}

# JSON response
{
    valid 1
    type "json_response"
    response "{\"status\": \"success\"}"
}

# Error response
{
    valid 0
    type "error_response"
    error "invalid_token"
    error_description "The provided token is invalid"
}

# Text response
{
    valid 1
    type "text_response"
    response "User successfully logged out"
}
```

#### Example

```tcl
# Validate logout response
set result [tossl::oidc::validate_logout_response -response $logout_response]

if {[dict get $result valid]} {
    puts "Logout response is valid"
    puts "Response type: [dict get $result type]"
} else {
    puts "Logout response is invalid"
    puts "Error: [dict get $result error]"
}
```

## Complete OIDC Logout Flow

```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Generate state for CSRF protection
set logout_state [tossl::oauth2::generate_state]

# 3. Generate logout URL
set logout_url [tossl::oidc::logout_url \
    -id_token_hint $id_token \
    -end_session_endpoint [dict get $config end_session_endpoint] \
    -post_logout_redirect_uri "https://myapp.com/logout" \
    -state $logout_state]

puts "Redirect user to: $logout_url"

# 4. Alternatively, perform direct end session request
set result [tossl::oidc::end_session \
    -id_token_hint $id_token \
    -end_session_endpoint [dict get $config end_session_endpoint] \
    -post_logout_redirect_uri "https://myapp.com/logout" \
    -state $logout_state]

# 5. Validate the logout response
set validation [tossl::oidc::validate_logout_response \
    -response [dict get $result response]]

if {[dict get $validation valid]} {
    puts "User successfully logged out"
    # Clear local session data
    # Redirect user to logout page
} else {
    puts "Logout failed: [dict get $validation error]"
}
```

## Supported Response Types

The logout validation supports multiple response types:

### Empty Response
- **Type**: `empty_response`
- **Description**: Empty response indicating successful logout
- **Valid**: Yes

### JSON Response
- **Type**: `json_response`
- **Description**: JSON response with status information
- **Valid**: Yes (unless it contains an error field)

### Error Response
- **Type**: `error_response`
- **Description**: JSON response with error information
- **Valid**: No
- **Fields**: `error`, `error_description`

### Text Response
- **Type**: `text_response`
- **Description**: Plain text response
- **Valid**: Yes

## Error Handling

The logout commands provide comprehensive error handling:

### Common Errors

- **"Missing required parameters"**: Missing id_token_hint or end_session_endpoint
- **"Logout URL too long"**: Generated URL exceeds maximum length
- **"Failed to perform end session request"**: Network or HTTP error
- **Invalid response types**: Unsupported response formats

### Error Handling Example

```tcl
if {[catch {
    set logout_url [tossl::oidc::logout_url \
        -id_token_hint $id_token \
        -end_session_endpoint $end_session_endpoint]
} result]} {
    puts "Logout URL generation failed: $result"
    return
}

if {[catch {
    set result [tossl::oidc::end_session \
        -id_token_hint $id_token \
        -end_session_endpoint $end_session_endpoint]
} result]} {
    puts "End session request failed: $result"
    return
}

# Validate response
if {[catch {
    set validation [tossl::oidc::validate_logout_response \
        -response [dict get $result response]]
} result]} {
    puts "Response validation failed: $result"
    return
}
```

## Security Considerations

1. **Always use HTTPS**: Only use end session endpoints over HTTPS
2. **Validate state parameter**: Use state parameter for CSRF protection
3. **Clear local session**: Clear local session data after successful logout
4. **Handle errors gracefully**: Implement proper error handling for logout failures
5. **Validate responses**: Always validate logout responses before proceeding
6. **Use id_token_hint**: Include ID token hint for better logout experience

## Integration with Other OIDC Commands

The logout commands work seamlessly with other OIDC functionality:

- **`tossl::oidc::discover`**: Get end session endpoint URL from provider discovery
- **`tossl::oidc::validate_id_token`**: Validate ID token before using as hint
- **`tossl::oauth2::generate_state`**: Generate state parameter for CSRF protection

## Notes

- The end session endpoint is optional for OIDC providers
- Some providers may not support all logout parameters
- The `id_token_hint` parameter is recommended but not always required
- Logout responses vary by provider (empty, JSON, HTML, etc.)
- Always clear local session data after successful logout
- Consider implementing front-channel logout for better security 