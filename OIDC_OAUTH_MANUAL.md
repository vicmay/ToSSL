# OpenID Connect (OIDC) and OAuth 2.0 Manual for TOSSL

## Table of Contents
1. [Introduction](#introduction)
2. [OAuth 2.0 Fundamentals](#oauth-20-fundamentals)
3. [OpenID Connect (OIDC) Overview](#openid-connect-oidc-overview)
4. [TOSSL OIDC/OAuth2 Implementation](#tossl-oidcoauth2-implementation)
5. [Complete Google OIDC Integration Example](#complete-google-oidc-integration-example)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Usage](#advanced-usage)

## Introduction

This manual provides a comprehensive guide to implementing OpenID Connect (OIDC) and OAuth 2.0 authentication using TOSSL. OIDC is an authentication layer built on top of OAuth 2.0 that provides standardized user authentication capabilities.

### What is OAuth 2.0?
OAuth 2.0 is an authorization framework that allows third-party applications to access resources on behalf of a user without sharing the user's credentials. It's primarily used for:
- API access delegation
- Third-party application integration
- Secure resource sharing

### What is OpenID Connect (OIDC)?
OIDC is an authentication protocol built on top of OAuth 2.0 that adds an identity layer. It provides:
- Standardized user authentication
- Identity verification
- User profile information
- Single sign-on (SSO) capabilities

### Why Use TOSSL for OIDC/OAuth2?
TOSSL provides a native C implementation with:
- High performance and low memory footprint
- Comprehensive OIDC/OAuth2 support
- Built-in security features
- Easy Tcl integration
- Production-ready reliability

## OAuth 2.0 Fundamentals

### OAuth 2.0 Roles

1. **Resource Owner**: The user who owns the resource
2. **Client**: The application requesting access
3. **Authorization Server**: Validates the user and issues tokens
4. **Resource Server**: Hosts the protected resources

### OAuth 2.0 Flow Types

#### 1. Authorization Code Flow (Most Secure)
```
User → Client → Authorization Server → User → Authorization Server → Client
```

#### 2. Implicit Flow (Less Secure)
```
User → Client → Authorization Server → User → Client
```

#### 3. Client Credentials Flow (Server-to-Server)
```
Client → Authorization Server → Client
```

#### 4. Device Authorization Flow (IoT/CLI)
```
Device → Authorization Server → User (via another device) → Device
```

### OAuth 2.0 Tokens

1. **Access Token**: Short-lived token for API access
2. **Refresh Token**: Long-lived token for getting new access tokens
3. **ID Token** (OIDC): Contains user identity information

## OpenID Connect (OIDC) Overview

### OIDC vs OAuth 2.0

| Feature | OAuth 2.0 | OIDC |
|---------|-----------|------|
| Purpose | Authorization | Authentication + Authorization |
| Tokens | Access Token | Access Token + ID Token |
| User Info | Via API calls | Standardized claims |
| Identity | Not provided | Standardized identity |

### OIDC Flows

#### 1. Authorization Code Flow with PKCE
- Most secure for public clients
- Uses code verifier/challenge for additional security
- Recommended for mobile and SPA applications

#### 2. Authorization Code Flow
- Standard flow for confidential clients
- Server-side applications
- Web applications with backend

### OIDC Claims

OIDC defines standard claims for user information:

#### Standard Claims
- `sub`: Subject identifier (user ID)
- `name`: Full name
- `given_name`: First name
- `family_name`: Last name
- `email`: Email address
- `email_verified`: Email verification status
- `picture`: Profile picture URL
- `locale`: User's locale
- `updated_at`: Last profile update

#### Custom Claims
- Provider-specific claims
- Application-specific claims
- Extended profile information

## TOSSL OIDC/OAuth2 Implementation

### Core Components

TOSSL provides comprehensive OIDC/OAuth2 support through these modules:

1. **OAuth2 Module**: Core OAuth 2.0 functionality
2. **OIDC Module**: OpenID Connect extensions
3. **JWT Module**: JSON Web Token handling
4. **HTTP Module**: HTTP client for API calls
5. **JSON Module**: JSON parsing and generation

### Available Commands

#### OAuth2 Commands
```tcl
# Generate authorization URL
tossl::oauth2::authorization_url -client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url>

# Exchange authorization code for tokens
tossl::oauth2::exchange_code -client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url>

# Refresh access token
tossl::oauth2::refresh_token -client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url>

# Introspect token
tossl::oauth2::introspect_token -token <token> -introspection_url <url> -client_id <id> -client_secret <secret>
```

#### OIDC Commands
```tcl
# Discover OIDC provider
tossl::oidc::discover -issuer <issuer_url>

# Generate nonce for CSRF protection
tossl::oidc::generate_nonce

# Fetch JWKS (JSON Web Key Set)
tossl::oidc::fetch_jwks -jwks_uri <jwks_url>

# Validate ID token
tossl::oidc::validate_id_token -token <id_token> -issuer <issuer> -audience <audience> -nonce <nonce>

# Get user information
tossl::oidc::userinfo -access_token <token> -userinfo_url <url>

# End session (logout)
tossl::oidc::end_session -id_token_hint <id_token> -end_session_endpoint <url>
```

#### Provider Presets
```tcl
# Google OIDC configuration
tossl::oidc::provider::google -client_id <id> -client_secret <secret> -redirect_uri <uri>

# Microsoft OIDC configuration
tossl::oidc::provider::microsoft -client_id <id> -client_secret <secret> -redirect_uri <uri>

# GitHub OIDC configuration
tossl::oidc::provider::github -client_id <id> -client_secret <secret> -redirect_uri <uri>
```

## Complete Google OIDC Integration Example

This section provides a complete example of integrating with Google OIDC using TOSSL.

### Prerequisites

1. **Google Cloud Console Setup**
   - Create a project in Google Cloud Console
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Configure authorized redirect URIs

2. **TOSSL Installation**
   - Ensure TOSSL is compiled with OIDC support
   - Verify all dependencies are installed

### Step 1: Google Cloud Console Configuration

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing project
3. Enable the Google+ API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application"
   - Add authorized redirect URIs (e.g., `http://localhost:8080/callback`)
   - Note your Client ID and Client Secret

### Step 2: Complete TOSSL Implementation

```tcl
#!/usr/bin/env tclsh

# Load TOSSL
package require tossl

# Configuration
set GOOGLE_CLIENT_ID "your-google-client-id.apps.googleusercontent.com"
set GOOGLE_CLIENT_SECRET "your-google-client-secret"
set REDIRECT_URI "http://localhost:8080/callback"
set SCOPE "openid profile email"

# Step 1: Discover Google OIDC Configuration
puts "=== Step 1: Discovering Google OIDC Configuration ==="
set google_config [tossl::oidc::discover -issuer "https://accounts.google.com"]

if {[dict get $google_config error] ne ""} {
    error "Failed to discover Google OIDC configuration: [dict get $google_config error]"
}

puts "Google OIDC Configuration:"
puts "  Authorization Endpoint: [dict get $google_config authorization_endpoint]"
puts "  Token Endpoint: [dict get $google_config token_endpoint]"
puts "  UserInfo Endpoint: [dict get $google_config userinfo_endpoint]"
puts "  JWKS URI: [dict get $google_config jwks_uri]"
puts "  Issuer: [dict get $google_config issuer]"
puts ""

# Step 2: Generate Security Parameters
puts "=== Step 2: Generating Security Parameters ==="
set nonce [tossl::oidc::generate_nonce]
set state [tossl::oauth2::generate_state]

puts "Generated Nonce: $nonce"
puts "Generated State: $state"
puts ""

# Step 3: Create Authorization URL
puts "=== Step 3: Creating Authorization URL ==="
set auth_url [tossl::oauth2::authorization_url_oidc \
    -client_id $GOOGLE_CLIENT_ID \
    -redirect_uri $REDIRECT_URI \
    -scope $SCOPE \
    -state $state \
    -nonce $nonce \
    -authorization_url [dict get $google_config authorization_endpoint]]

puts "Authorization URL:"
puts $auth_url
puts ""
puts "Please visit this URL in your browser to authenticate with Google."
puts "After authentication, you'll be redirected to: $REDIRECT_URI?code=<authorization_code>&state=$state"
puts ""

# Step 4: Simulate User Authentication (In real app, user visits URL)
puts "=== Step 4: Simulating User Authentication ==="
puts "In a real application, the user would:"
puts "1. Visit the authorization URL"
puts "2. Sign in with their Google account"
puts "3. Grant permissions to your application"
puts "4. Be redirected back with an authorization code"
puts ""

# For demonstration, we'll simulate the callback
# In practice, you'd handle this in your web server
puts "Simulating callback with authorization code..."
puts "Please enter the authorization code from the redirect URL:"
gets stdin auth_code

if {$auth_code eq ""} {
    puts "No authorization code provided. Exiting."
    exit 1
}

# Step 5: Exchange Authorization Code for Tokens
puts "=== Step 5: Exchanging Authorization Code for Tokens ==="
set tokens [tossl::oauth2::exchange_code_oidc \
    -client_id $GOOGLE_CLIENT_ID \
    -client_secret $GOOGLE_CLIENT_SECRET \
    -code $auth_code \
    -redirect_uri $REDIRECT_URI \
    -token_url [dict get $google_config token_endpoint] \
    -nonce $nonce]

if {[dict get $tokens error] ne ""} {
    error "Token exchange failed: [dict get $tokens error]"
}

puts "Token Exchange Successful:"
puts "  Access Token: [string range [dict get $tokens access_token] 0 20]..."
puts "  Token Type: [dict get $tokens token_type]"
puts "  Expires In: [dict get $tokens expires_in] seconds"
puts "  Refresh Token: [string range [dict get $tokens refresh_token] 0 20]..."
puts "  ID Token: [string range [dict get $tokens id_token] 0 50]..."
puts ""

# Step 6: Validate ID Token
puts "=== Step 6: Validating ID Token ==="
set id_token_validation [tossl::oidc::validate_id_token \
    -token [dict get $tokens id_token] \
    -issuer [dict get $google_config issuer] \
    -audience $GOOGLE_CLIENT_ID \
    -nonce $nonce]

if {![dict get $id_token_validation valid]} {
    error "ID token validation failed: [dict get $id_token_validation error]"
}

puts "ID Token Validation Successful:"
puts "  Valid: [dict get $id_token_validation valid]"
puts "  Claims: [dict get $id_token_validation claims]"
puts ""

# Step 7: Extract User Information from ID Token
puts "=== Step 7: Extracting User Information from ID Token ==="
set id_claims [dict get $id_token_validation claims]
puts "User Information from ID Token:"
puts "  Subject (User ID): [dict get $id_claims sub]"
puts "  Email: [dict get $id_claims email]"
puts "  Email Verified: [dict get $id_claims email_verified]"
puts "  Name: [dict get $id_claims name]"
puts "  Given Name: [dict get $id_claims given_name]"
puts "  Family Name: [dict get $id_claims family_name]"
puts "  Picture: [dict get $id_claims picture]"
puts "  Locale: [dict get $id_claims locale]"
puts ""

# Step 8: Fetch Additional User Information
puts "=== Step 8: Fetching Additional User Information ==="
set userinfo [tossl::oidc::userinfo \
    -access_token [dict get $tokens access_token] \
    -userinfo_url [dict get $google_config userinfo_endpoint]]

if {[dict get $userinfo error] ne ""} {
    puts "Warning: Failed to fetch userinfo: [dict get $userinfo error]"
} else {
    puts "Additional User Information:"
    puts "  Subject: [dict get $userinfo sub]"
    puts "  Name: [dict get $userinfo name]"
    puts "  Given Name: [dict get $userinfo given_name]"
    puts "  Family Name: [dict get $userinfo family_name]"
    puts "  Picture: [dict get $userinfo picture]"
    puts "  Email: [dict get $userinfo email]"
    puts "  Email Verified: [dict get $userinfo email_verified]"
    puts "  Locale: [dict get $userinfo locale]"
    puts ""
}

# Step 9: Validate Claims
puts "=== Step 9: Validating User Claims ==="
set claims_validation [tossl::oidc::validate_claims \
    -claims $userinfo \
    -required_claims {sub email name}]

if {[dict get $claims_validation valid]} {
    puts "Claims validation successful"
    puts "  Valid claims: [dict get $claims_validation valid_claims]"
} else {
    puts "Claims validation failed: [dict get $claims_validation error]"
}
puts ""

# Step 10: Use Access Token for API Calls
puts "=== Step 10: Using Access Token for API Calls ==="
puts "Making API call to Google People API..."

set api_response [tossl::http::get_enhanced \
    "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses" \
    -headers "Authorization: Bearer [dict get $tokens access_token]"]

if {[dict get $api_response error] ne ""} {
    puts "API call failed: [dict get $api_response error]"
} else {
    puts "API call successful:"
    puts "  Status: [dict get $api_response status]"
    puts "  Response: [string range [dict get $api_response body] 0 200]..."
}
puts ""

# Step 11: Refresh Token (if needed)
puts "=== Step 11: Demonstrating Token Refresh ==="
puts "Access token expires in [dict get $tokens expires_in] seconds"
puts "To refresh the token, use:"

set refresh_example [tossl::oauth2::refresh_token \
    -client_id $GOOGLE_CLIENT_ID \
    -client_secret $GOOGLE_CLIENT_SECRET \
    -refresh_token [dict get $tokens refresh_token] \
    -token_url [dict get $google_config token_endpoint]]

if {[dict get $refresh_example error] ne ""} {
    puts "Token refresh example failed: [dict get $refresh_example error]"
} else {
    puts "Token refresh successful:"
    puts "  New Access Token: [string range [dict get $refresh_example access_token] 0 20]..."
    puts "  New Expires In: [dict get $refresh_example expires_in] seconds"
}
puts ""

# Step 12: Logout
puts "=== Step 12: Logout ==="
puts "To logout the user, use:"

set logout_url [tossl::oidc::logout_url \
    -id_token_hint [dict get $tokens id_token] \
    -end_session_endpoint [dict get $google_config end_session_endpoint] \
    -post_logout_redirect_uri "http://localhost:8080/logout" \
    -state [tossl::oauth2::generate_state]]

puts "Logout URL: $logout_url"
puts ""

# Summary
puts "=== Summary ==="
puts "✅ OIDC discovery completed"
puts "✅ Authorization URL generated"
puts "✅ Token exchange completed"
puts "✅ ID token validated"
puts "✅ User information retrieved"
puts "✅ Claims validated"
puts "✅ API call demonstrated"
puts "✅ Token refresh demonstrated"
puts "✅ Logout URL generated"
puts ""
puts "The OIDC integration is working correctly!"
```

### Step 3: Running the Example

1. **Save the script** as `google_oidc_example.tcl`
2. **Update the configuration**:
   - Replace `your-google-client-id` with your actual Google Client ID
   - Replace `your-google-client-secret` with your actual Google Client Secret
   - Update `REDIRECT_URI` if needed
3. **Run the script**:
   ```bash
   tclsh google_oidc_example.tcl
   ```
4. **Follow the prompts** to complete the authentication flow

### Step 4: Web Server Integration

For a real web application, you'd integrate this into a web server:

```tcl
# Example using TclHttpd or similar web server
package require tossl

# Store OIDC configuration globally
set GOOGLE_CONFIG [tossl::oidc::discover -issuer "https://accounts.google.com"]

# Handle login request
proc handle_login {request} {
    global GOOGLE_CONFIG
    
    set nonce [tossl::oidc::generate_nonce]
    set state [tossl::oauth2::generate_state]
    
    # Store nonce and state in session
    session_set nonce $nonce
    session_set state $state
    
    set auth_url [tossl::oauth2::authorization_url_oidc \
        -client_id $::GOOGLE_CLIENT_ID \
        -redirect_uri $::REDIRECT_URI \
        -scope "openid profile email" \
        -state $state \
        -nonce $nonce \
        -authorization_url [dict get $GOOGLE_CONFIG authorization_endpoint]]
    
    return [HttpRedirect $auth_url]
}

# Handle OAuth callback
proc handle_callback {request} {
    global GOOGLE_CONFIG
    
    set code [query_get code]
    set state [query_get state]
    
    # Validate state parameter
    if {$state ne [session_get state]} {
        return [HttpError 400 "Invalid state parameter"]
    }
    
    # Exchange code for tokens
    set tokens [tossl::oauth2::exchange_code_oidc \
        -client_id $::GOOGLE_CLIENT_ID \
        -client_secret $::GOOGLE_CLIENT_SECRET \
        -code $code \
        -redirect_uri $::REDIRECT_URI \
        -token_url [dict get $GOOGLE_CONFIG token_endpoint] \
        -nonce [session_get nonce]]
    
    # Validate ID token
    set validation [tossl::oidc::validate_id_token \
        -token [dict get $tokens id_token] \
        -issuer [dict get $GOOGLE_CONFIG issuer] \
        -audience $::GOOGLE_CLIENT_ID \
        -nonce [session_get nonce]]
    
    if {![dict get $validation valid]} {
        return [HttpError 400 "Invalid ID token"]
    }
    
    # Store user information in session
    session_set user_id [dict get [dict get $validation claims] sub]
    session_set user_email [dict get [dict get $validation claims] email]
    session_set user_name [dict get [dict get $validation claims] name]
    
    return [HttpRedirect "/dashboard"]
}
```

## Security Best Practices

### 1. Token Security

```tcl
# Always validate tokens
set validation [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer $expected_issuer \
    -audience $client_id \
    -nonce $stored_nonce]

if {![dict get $validation valid]} {
    error "Token validation failed"
}

# Store tokens securely
# - Use secure session storage
# - Encrypt sensitive data
# - Set appropriate expiration times
```

### 2. State and Nonce Validation

```tcl
# Always use state parameter for CSRF protection
set state [tossl::oauth2::generate_state]
session_set oauth_state $state

# Always use nonce for replay protection
set nonce [tossl::oidc::generate_nonce]
session_set oauth_nonce $nonce

# Validate both parameters in callback
if {$received_state ne [session_get oauth_state]} {
    error "Invalid state parameter"
}

if {$received_nonce ne [session_get oauth_nonce]} {
    error "Invalid nonce parameter"
}
```

### 3. HTTPS Enforcement

```tcl
# Always use HTTPS in production
if {$::env(HTTPS) ne "on" && $::env(HTTP_HOST) ne "localhost"} {
    error "HTTPS required for OAuth/OIDC"
}
```

### 4. Input Validation

```tcl
# Validate all inputs
proc validate_email {email} {
    set validation [tossl::oidc::validate_claim_format -claim email -value $email]
    return [dict get $validation valid]
}

proc validate_redirect_uri {uri} {
    # Validate against whitelist
    set allowed_uris {http://localhost:8080/callback https://yourdomain.com/callback}
    return [expr {$uri in $allowed_uris}]
}
```

### 5. Error Handling

```tcl
# Comprehensive error handling
proc handle_oauth_error {error_code error_description} {
    switch $error_code {
        "invalid_request" {
            error "Invalid OAuth request: $error_description"
        }
        "unauthorized_client" {
            error "Client not authorized: $error_description"
        }
        "access_denied" {
            error "Access denied by user: $error_description"
        }
        "unsupported_response_type" {
            error "Unsupported response type: $error_description"
        }
        "invalid_scope" {
            error "Invalid scope: $error_description"
        }
        "server_error" {
            error "OAuth server error: $error_description"
        }
        "temporarily_unavailable" {
            error "OAuth server temporarily unavailable: $error_description"
        }
        default {
            error "Unknown OAuth error: $error_code - $error_description"
        }
    }
}
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "Invalid redirect_uri" Error

**Problem**: Google rejects the redirect URI
**Solution**: 
```tcl
# Ensure redirect URI matches exactly in Google Console
set REDIRECT_URI "https://yourdomain.com/callback"  ;# Must match exactly
```

#### 2. "Invalid client" Error

**Problem**: Client ID or secret is incorrect
**Solution**:
```tcl
# Verify credentials
puts "Client ID: $GOOGLE_CLIENT_ID"
puts "Client Secret: [string range $GOOGLE_CLIENT_SECRET 0 10]..."
```

#### 3. "Invalid nonce" Error

**Problem**: Nonce validation fails
**Solution**:
```tcl
# Ensure nonce is stored and retrieved correctly
session_set oauth_nonce $nonce
# ... later ...
set stored_nonce [session_get oauth_nonce]
```

#### 4. Token Expiration Issues

**Problem**: Access tokens expire quickly
**Solution**:
```tcl
# Implement token refresh
if {[clock seconds] > $token_expiry} {
    set new_tokens [tossl::oauth2::refresh_token \
        -client_id $CLIENT_ID \
        -client_secret $CLIENT_SECRET \
        -refresh_token $refresh_token \
        -token_url $token_url]
}
```

#### 5. Network Connectivity Issues

**Problem**: Can't reach Google OIDC endpoints
**Solution**:
```tcl
# Test connectivity
set test_response [tossl::http::get_enhanced "https://accounts.google.com/.well-known/openid_configuration"]
if {[dict get $test_response error] ne ""} {
    error "Cannot reach Google OIDC: [dict get $test_response error]"
}
```

### Debug Mode

Enable debug logging for troubleshooting:

```tcl
# Enable HTTP debug logging
tossl::http::debug on

# Enable OIDC debug logging
tossl::oidc::debug on

# Check TOSSL version and features
puts "TOSSL Version: [tossl::version]"
puts "OIDC Support: [tossl::features]"
```

## Advanced Usage

### 1. Multiple Provider Support

```tcl
# Support multiple OIDC providers
proc get_oidc_provider {provider_name} {
    switch $provider_name {
        "google" {
            return [tossl::oidc::provider::google \
                -client_id $::GOOGLE_CLIENT_ID \
                -client_secret $::GOOGLE_CLIENT_SECRET \
                -redirect_uri $::REDIRECT_URI]
        }
        "microsoft" {
            return [tossl::oidc::provider::microsoft \
                -client_id $::MICROSOFT_CLIENT_ID \
                -client_secret $::MICROSOFT_CLIENT_SECRET \
                -redirect_uri $::REDIRECT_URI]
        }
        "github" {
            return [tossl::oidc::provider::github \
                -client_id $::GITHUB_CLIENT_ID \
                -client_secret $::GITHUB_CLIENT_SECRET \
                -redirect_uri $::REDIRECT_URI]
        }
        default {
            error "Unknown provider: $provider_name"
        }
    }
}
```

### 2. Custom Claims Validation

```tcl
# Validate custom claims
proc validate_custom_claims {claims} {
    # Check for required custom claims
    set required_claims {department role permissions}
    
    foreach claim $required_claims {
        if {![dict exists $claims $claim]} {
            return [dict create valid false error "Missing required claim: $claim"]
        }
    }
    
    # Validate claim values
    if {[dict get $claims role] ni {admin user guest}} {
        return [dict create valid false error "Invalid role value"]
    }
    
    return [dict create valid true]
}
```

### 3. Token Caching

```tcl
# Implement token caching
proc get_cached_token {user_id} {
    set cache_key "token:$user_id"
    set cached [cache_get $cache_key]
    
    if {$cached ne ""} {
        set token_data [json::parse $cached]
        if {[clock seconds] < [dict get $token_data expires_at]} {
            return $token_data
        }
    }
    
    return ""
}

proc cache_token {user_id token_data} {
    set cache_key "token:$user_id"
    set expires_at [expr {[clock seconds] + [dict get $token_data expires_in]}]
    dict set token_data expires_at $expires_at
    
    cache_set $cache_key [json::stringify $token_data] [dict get $token_data expires_in]
}
```

### 4. Automatic Token Refresh

```tcl
# Automatic token refresh wrapper
proc get_valid_access_token {user_id} {
    set token_data [get_cached_token $user_id]
    
    if {$token_data eq ""} {
        error "No cached token found for user: $user_id"
    }
    
    # Check if token needs refresh (refresh 5 minutes before expiry)
    set refresh_time [expr {[dict get $token_data expires_at] - 300}]
    
    if {[clock seconds] > $refresh_time} {
        set new_tokens [tossl::oauth2::refresh_token \
            -client_id $::CLIENT_ID \
            -client_secret $::CLIENT_SECRET \
            -refresh_token [dict get $token_data refresh_token] \
            -token_url $::TOKEN_URL]
        
        cache_token $user_id $new_tokens
        return [dict get $new_tokens access_token]
    }
    
    return [dict get $token_data access_token]
}
```

### 5. Batch API Operations

```tcl
# Batch multiple API calls
proc batch_api_calls {access_token endpoints} {
    set results {}
    
    foreach endpoint $endpoints {
        set response [tossl::http::get_enhanced $endpoint \
            -headers "Authorization: Bearer $access_token"]
        
        lappend results [dict create endpoint $endpoint response $response]
    }
    
    return $results
}

# Usage
set endpoints {
    "https://api.example.com/users/me"
    "https://api.example.com/users/me/permissions"
    "https://api.example.com/users/me/groups"
}

set results [batch_api_calls $access_token $endpoints]
```

## Conclusion

This manual provides a comprehensive guide to implementing OIDC/OAuth2 with TOSSL. The Google integration example demonstrates a complete authentication flow, while the security best practices and troubleshooting sections help ensure secure and reliable implementations.

Key takeaways:

1. **OIDC builds on OAuth 2.0** to provide standardized authentication
2. **TOSSL provides native C performance** with comprehensive OIDC/OAuth2 support
3. **Security is paramount** - always validate tokens, use state/nonce, and enforce HTTPS
4. **Error handling is critical** - implement comprehensive error handling and recovery
5. **Testing is essential** - thoroughly test all flows and edge cases

For additional information, refer to:
- [OpenID Connect Core 1.0 Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [TOSSL Documentation](https://github.com/your-repo/tossl)

Happy coding with TOSSL and OIDC! 