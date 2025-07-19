# OIDC UserInfo Endpoint

## Overview

The OIDC UserInfo endpoint commands provide support for RFC 7662 (UserInfo Endpoint) functionality. These commands allow you to fetch user profile information from OpenID Connect providers, validate UserInfo responses, and extract specific user claims.

## Commands

### `tossl::oidc::userinfo`

Fetches user information from the UserInfo endpoint using an access token.

#### Syntax

```tcl
tossl::oidc::userinfo -access_token <token> -userinfo_url <url> ?-headers <headers>?
```

#### Parameters

- **`-access_token`** `<token>`: The OAuth2 access token for authentication
- **`-userinfo_url`** `<url>`: The UserInfo endpoint URL
- **`-headers`** `<headers>`: (Optional) Additional HTTP headers

#### Return Value

Returns a dictionary containing user profile information:

```tcl
{
    sub "1234567890"
    name "John Doe"
    given_name "John"
    family_name "Doe"
    email "john.doe@example.com"
    email_verified true
    picture "https://example.com/john.jpg"
    # ... other available claims
}
```

#### Example

```tcl
# Fetch user information from Google
set userinfo [tossl::oidc::userinfo \
    -access_token $access_token \
    -userinfo_url "https://www.googleapis.com/oauth2/v3/userinfo"]

puts "User: [dict get $userinfo name]"
puts "Email: [dict get $userinfo email]"
```

### `tossl::oidc::validate_userinfo`

Validates a UserInfo response by checking the subject claim.

#### Syntax

```tcl
tossl::oidc::validate_userinfo -userinfo <userinfo_data> -expected_subject <subject>
```

#### Parameters

- **`-userinfo`** `<userinfo_data>`: The UserInfo JSON response data
- **`-expected_subject`** `<subject>`: The expected subject identifier

#### Return Value

Returns a validation result:

```tcl
{
    valid 1
    subject "1234567890"
}
```

#### Example

```tcl
# Validate UserInfo response
set result [tossl::oidc::validate_userinfo \
    -userinfo $userinfo_data \
    -expected_subject "1234567890"]

if {![dict get $result valid]} {
    error "UserInfo validation failed"
}
```

### `tossl::oidc::extract_user_claims`

Extracts specific claims from UserInfo data.

#### Syntax

```tcl
tossl::oidc::extract_user_claims -userinfo <userinfo_data> -claims {claim1 claim2 ...}
```

#### Parameters

- **`-userinfo`** `<userinfo_data>`: The UserInfo JSON response data
- **`-claims`** `{claim1 claim2 ...}`: List of claim names to extract

#### Return Value

Returns a dictionary containing only the requested claims:

```tcl
{
    name "John Doe"
    email "john.doe@example.com"
    picture "https://example.com/john.jpg"
}
```

#### Example

```tcl
# Extract specific claims
set claims [tossl::oidc::extract_user_claims \
    -userinfo $userinfo_data \
    -claims {name email picture}]

puts "Name: [dict get $claims name]"
puts "Email: [dict get $claims email]"
```

## Supported Claims

The UserInfo commands support all standard OpenID Connect claims:

### Standard Claims
- **`sub`**: Subject identifier (required)
- **`name`**: Full name
- **`given_name`**: First name
- **`family_name`**: Last name
- **`middle_name`**: Middle name
- **`nickname`**: Nickname
- **`preferred_username`**: Preferred username
- **`profile`**: Profile URL
- **`picture`**: Profile picture URL
- **`website`**: Website URL
- **`email`**: Email address
- **`email_verified`**: Email verification status (boolean)
- **`gender`**: Gender
- **`birthdate`**: Birth date
- **`zoneinfo`**: Time zone
- **`locale`**: Locale
- **`phone_number`**: Phone number
- **`phone_number_verified`**: Phone verification status (boolean)
- **`address`**: Address (JSON object)
- **`updated_at`**: Last update timestamp

## Complete OIDC Flow Example

```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Generate nonce for CSRF protection
set nonce [tossl::oidc::generate_nonce]

# 3. Create authorization URL
set auth_url [tossl::oauth2::authorization_url \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url [dict get $config authorization_endpoint]]

puts "Visit: $auth_url"

# 4. Exchange code for tokens
set tokens [tossl::oauth2::exchange_code \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -code $auth_code \
    -redirect_uri "https://your-app.com/callback" \
    -token_url [dict get $config token_endpoint]]

# 5. Validate ID token
set id_token [dict get $tokens id_token]
set validation [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer [dict get $config issuer] \
    -audience "your_client_id" \
    -nonce $nonce]

if {![dict get $validation valid]} {
    error "ID token validation failed: [dict get $validation error]"
}

# 6. Get user profile from UserInfo endpoint
set userinfo [tossl::oidc::userinfo \
    -access_token [dict get $tokens access_token] \
    -userinfo_url [dict get $config userinfo_endpoint]]

# 7. Validate UserInfo subject matches ID token
set userinfo_validation [tossl::oidc::validate_userinfo \
    -userinfo $userinfo \
    -expected_subject [dict get $validation subject]]

if {![dict get $userinfo_validation valid]} {
    error "UserInfo validation failed"
}

# 8. Extract specific user claims
set user_claims [tossl::oidc::extract_user_claims \
    -userinfo $userinfo \
    -claims {name email picture}]

puts "Welcome, [dict get $user_claims name]!"
puts "Email: [dict get $user_claims email]"
```

## Error Handling

The UserInfo commands provide comprehensive error handling:

### Common Errors

- **"Failed to fetch UserInfo"**: Network or HTTP error
- **"Invalid JSON response"**: Malformed UserInfo response
- **"Missing 'sub' field in UserInfo"**: Required subject claim missing
- **"Subject mismatch in UserInfo"**: Subject doesn't match expected value
- **"Invalid UserInfo data"**: Invalid JSON format

### Error Handling Example

```tcl
if {[catch {
    set userinfo [tossl::oidc::userinfo \
        -access_token $access_token \
        -userinfo_url $userinfo_url]
} result]} {
    puts "UserInfo error: $result"
    # Handle error appropriately
    return
}

# Validate the response
if {[catch {
    set validation [tossl::oidc::validate_userinfo \
        -userinfo $userinfo \
        -expected_subject $expected_subject]
} result]} {
    puts "Validation error: $result"
    return
}
```

## Security Considerations

1. **Always validate the subject**: Ensure UserInfo subject matches ID token subject
2. **Use HTTPS**: Only use UserInfo endpoints over HTTPS
3. **Validate access tokens**: Ensure access tokens are valid and not expired
4. **Check claim values**: Validate important claims like email verification status
5. **Handle errors gracefully**: Implement proper error handling for network failures

## Integration with Other OIDC Commands

The UserInfo commands work seamlessly with other OIDC functionality:

- **`tossl::oidc::discover`**: Get UserInfo endpoint URL from provider discovery
- **`tossl::oidc::validate_id_token`**: Validate ID token before using UserInfo
- **`tossl::oauth2::exchange_code`**: Get access token for UserInfo requests

## Notes

- The UserInfo endpoint requires a valid OAuth2 access token
- UserInfo responses are typically cached by the OpenID Provider
- Not all providers support all standard claims
- The `address` claim is returned as a JSON string for complex objects
- Boolean claims like `email_verified` are properly typed in Tcl 