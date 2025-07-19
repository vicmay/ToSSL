# ::tossl::oidc::fetch_jwks

Fetch and parse JSON Web Key Set (JWKS) from an OIDC provider's JWKS endpoint.

## Syntax

    tossl::oidc::fetch_jwks -jwks_uri <jwks_url>

## Parameters

- `-jwks_uri <jwks_url>`: The JWKS endpoint URL (required)

## Description

Fetches a JSON Web Key Set (JWKS) from the specified URL. JWKS is defined in RFC 7517 and contains a set of public keys that can be used to verify JWT signatures from the OIDC provider.

The JWKS fetching process:
1. Makes an HTTPS request to the JWKS endpoint
2. Parses and validates the JSON response
3. Caches the result for performance
4. Returns a Tcl dictionary with all public keys

## Return Value

Returns a Tcl dictionary containing the JWKS with the following structure:

```tcl
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id-1",
      "n": "modulus-value",
      "e": "exponent-value",
      "alg": "RS256",
      "use": "sig"
    },
    {
      "kty": "EC",
      "kid": "key-id-2",
      "crv": "P-256",
      "x": "x-coordinate",
      "y": "y-coordinate",
      "alg": "ES256",
      "use": "sig"
    }
  ]
}
```

## Examples

### Basic JWKS Fetching

```tcl
# Fetch JWKS from Google's OIDC provider
set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://www.googleapis.com/oauth2/v3/certs"]

# Access the keys
set keys [dict get $jwks keys]
puts "Found [llength $keys] public keys"
```

### Complete OIDC Flow with JWKS

```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Fetch JWKS for signature verification
set jwks [tossl::oidc::fetch_jwks -jwks_uri [dict get $config jwks_uri]]

# 3. Use JWKS for ID token validation (future implementation)
# set validation [tossl::oidc::validate_id_token \
#     -token $id_token \
#     -jwks $jwks \
#     -issuer [dict get $config issuer] \
#     -audience $client_id]
```

### JWKS with Specific Key Retrieval

```tcl
# Fetch JWKS
set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://example.com/.well-known/jwks.json"]

# Get a specific key by key ID
set specific_key [tossl::oidc::get_jwk -jwks $jwks -kid "specific-key-id"]

# Validate the JWKS structure
set validation [tossl::oidc::validate_jwks -jwks $jwks]
if {[dict get $validation valid]} {
    puts "JWKS is valid with [dict get $validation keys_count] keys"
}
```

## Error Handling

### Network Errors

```tcl
if {[catch {
    set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://invalid-url.example.com/jwks"]
} result]} {
    puts "JWKS fetch failed: $result"
    # Handle network connectivity issues
}
```

### Invalid JWKS Response

```tcl
if {[catch {
    set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://example.com/jwks"]
} result]} {
    puts "JWKS parsing failed: $result"
    # Handle invalid JWKS format
}
```

### Missing Required Parameters

```tcl
if {[catch {
    tossl::oidc::fetch_jwks
} result]} {
    puts "Error: $result"
    # Expected: "wrong # args: should be..."
}
```

## Caching

The JWKS results are automatically cached to improve performance. Subsequent calls to the same JWKS URI will return the cached keys without making additional HTTP requests.

**Note**: JWKS caching is currently in-memory only. For production use, consider implementing cache expiration based on the `Cache-Control` headers or a reasonable TTL.

## Security Considerations

1. **HTTPS Only**: JWKS requests only work with HTTPS URLs
2. **Certificate Validation**: SSL certificates are validated during requests
3. **Timeout Protection**: Requests timeout after 30 seconds
4. **Input Validation**: JWKS URLs are validated before processing
5. **Key Validation**: JWKS structure and key formats are validated

## Performance

- **First Request**: ~1-5 seconds (network dependent)
- **Cached Requests**: < 1 millisecond
- **Memory Usage**: ~1-10 KB per cached JWKS (depends on number of keys)

## Integration with Other OIDC Commands

This command is designed to work seamlessly with other OIDC commands:

```tcl
# Complete OIDC setup with JWKS
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]
set jwks [tossl::oidc::fetch_jwks -jwks_uri [dict get $config jwks_uri]]

# Validate JWKS structure
set jwks_validation [tossl::oidc::validate_jwks -jwks $jwks]
if {![dict get $jwks_validation valid]} {
    error "Invalid JWKS structure"
}

# Get specific key for signature verification
set signing_key [tossl::oidc::get_jwk -jwks $jwks -kid "specific-key-id"]

# Use with JWT validation (future)
# tossl::oidc::validate_id_token -token $id_token -jwks $jwks ...
```

## See Also

- `::tossl::oidc::discover` - Discover OIDC provider configuration
- `::tossl::oidc::get_jwk` - Get specific JWK by key ID
- `::tossl::oidc::validate_jwks` - Validate JWKS structure
- `::tossl::jwt::verify` - Verify JWT signatures (for future JWKS integration) 