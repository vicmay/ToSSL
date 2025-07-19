# ::tossl::oidc::discover

Discover OpenID Connect provider configuration using RFC 8414 (OAuth 2.0 Authorization Server Metadata).

## Syntax

    tossl::oidc::discover -issuer <issuer_url>

## Parameters

- `-issuer <issuer_url>`: The OIDC issuer URL (required)

## Description

Performs OIDC discovery by fetching the provider configuration from the `.well-known/openid_configuration` endpoint. This command implements RFC 8414 (OAuth 2.0 Authorization Server Metadata) and returns a comprehensive configuration dictionary containing all supported endpoints, algorithms, and capabilities.

The discovery process:
1. Constructs the discovery URL: `{issuer}/.well-known/openid_configuration`
2. Fetches the configuration using HTTPS
3. Parses and validates the JSON response
4. Caches the result for performance
5. Returns a Tcl dictionary with all configuration parameters

## Return Value

Returns a Tcl dictionary containing the OIDC provider configuration with the following keys:

### Required Fields
- `issuer`: The OIDC issuer identifier
- `authorization_endpoint`: The authorization endpoint URL
- `token_endpoint`: The token endpoint URL

### Optional Fields
- `userinfo_endpoint`: The UserInfo endpoint URL
- `jwks_uri`: The JSON Web Key Set (JWKS) endpoint URL
- `end_session_endpoint`: The end session endpoint URL
- `service_documentation`: URL to service documentation
- `op_policy_uri`: URL to privacy policy
- `op_tos_uri`: URL to terms of service

### Supported Capabilities (Arrays)
- `scopes_supported`: List of supported OIDC scopes
- `response_types_supported`: List of supported response types
- `grant_types_supported`: List of supported grant types
- `claims_supported`: List of supported claims
- `token_endpoint_auth_methods_supported`: List of supported authentication methods
- `subject_types_supported`: List of supported subject types
- `id_token_signing_alg_values_supported`: List of supported ID token signing algorithms
- `id_token_encryption_alg_values_supported`: List of supported ID token encryption algorithms
- `userinfo_signing_alg_values_supported`: List of supported UserInfo signing algorithms
- `userinfo_encryption_alg_values_supported`: List of supported UserInfo encryption algorithms
- `request_object_signing_alg_values_supported`: List of supported request object signing algorithms
- `request_object_encryption_alg_values_supported`: List of supported request object encryption algorithms
- `display_values_supported`: List of supported display values
- `claims_locales_supported`: List of supported claims locales
- `ui_locales_supported`: List of supported UI locales

### Boolean Flags
- `claims_parameter_supported`: Whether claims parameter is supported
- `request_parameter_supported`: Whether request parameter is supported
- `request_uri_parameter_supported`: Whether request_uri parameter is supported
- `require_request_uri_registration`: Whether request_uri registration is required

## Examples

### Basic Discovery

```tcl
# Discover Google OIDC configuration
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# Access configuration values
puts "Issuer: [dict get $config issuer]"
puts "Authorization endpoint: [dict get $config authorization_endpoint]"
puts "Token endpoint: [dict get $config token_endpoint]"
puts "UserInfo endpoint: [dict get $config userinfo_endpoint]"
puts "JWKS URI: [dict get $config jwks_uri]"
```

### Check Supported Features

```tcl
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# Check supported scopes
if {[dict exists $config scopes_supported]} {
    puts "Supported scopes: [dict get $config scopes_supported]"
}

# Check supported ID token signing algorithms
if {[dict exists $config id_token_signing_alg_values_supported]} {
    puts "ID token signing algorithms: [dict get $config id_token_signing_alg_values_supported]"
}

# Check if claims parameter is supported
if {[dict get $config claims_parameter_supported]} {
    puts "Claims parameter is supported"
}
```

### Complete OIDC Flow Setup

```tcl
# Discover provider configuration
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# Generate OAuth2 authorization URL with OIDC scope
set nonce [tossl::oidc::generate_nonce]
set auth_url [tossl::oauth2::authorization_url \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url [dict get $config authorization_endpoint]]

puts "Visit: $auth_url"
```

## Error Handling

### Invalid Issuer URL

```tcl
if {[catch {
    set config [tossl::oidc::discover -issuer "https://invalid-issuer.example.com"]
} result]} {
    puts "Discovery failed: $result"
}
```

### Network Errors

```tcl
if {[catch {
    set config [tossl::oidc::discover -issuer "https://accounts.google.com"]
} result]} {
    puts "Network error: $result"
    # Handle network connectivity issues
}
```

### Missing Required Parameters

```tcl
if {[catch {
    tossl::oidc::discover
} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}
```

## Caching

The discovery results are automatically cached to improve performance. Subsequent calls to the same issuer will return the cached configuration without making additional HTTP requests.

## Security Considerations

1. **HTTPS Only**: Discovery only works with HTTPS URLs
2. **Certificate Validation**: SSL certificates are validated during discovery
3. **Timeout Protection**: Requests timeout after 30 seconds
4. **Input Validation**: Issuer URLs are validated before processing

## Performance

- **First Request**: ~1-5 seconds (network dependent)
- **Cached Requests**: < 1 millisecond
- **Memory Usage**: ~1-5 KB per cached configuration

## Integration with OAuth2

This command is designed to work seamlessly with the existing OAuth2 infrastructure:

```tcl
# Complete OIDC flow setup
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]
set nonce [tossl::oidc::generate_nonce]

# Use discovered endpoints with OAuth2 commands
set auth_url [tossl::oauth2::authorization_url \
    -client_id $client_id \
    -redirect_uri $redirect_uri \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url [dict get $config authorization_endpoint]]

# Later, exchange code for tokens
set tokens [tossl::oauth2::exchange_code \
    -client_id $client_id \
    -client_secret $client_secret \
    -code $auth_code \
    -redirect_uri $redirect_uri \
    -token_url [dict get $config token_endpoint]]
```

## See Also

- `::tossl::oidc::generate_nonce` - Generate OIDC nonce for CSRF protection
- `::tossl::oauth2::authorization_url` - Create OAuth2 authorization URLs
- `::tossl::oauth2::exchange_code` - Exchange authorization codes for tokens
- `::tossl::jwt::validate` - Validate JWT ID tokens 