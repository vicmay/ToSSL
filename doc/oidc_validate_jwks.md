# ::tossl::oidc::validate_jwks

Validate the structure and format of a JSON Web Key Set (JWKS).

## Syntax

    tossl::oidc::validate_jwks -jwks <jwks_data>

## Parameters

- `-jwks <jwks_data>`: The JWKS data to validate (required)

## Description

Validates a JSON Web Key Set (JWKS) to ensure it has the correct structure and format according to RFC 7517. This command performs structural validation without making network requests, making it useful for validating JWKS data before using it for JWT verification.

The validation checks:
1. Valid JSON format
2. Presence of the `keys` field
3. `keys` field is an array
4. Array contains at least one key
5. Each key has required fields (`kty` and `kid`)

## Return Value

Returns a Tcl dictionary with validation results:

```tcl
{
  "valid": true,
  "keys_count": 2,
  "valid_keys": 2
}
```

- `valid`: Boolean indicating if the JWKS is valid
- `keys_count`: Total number of keys in the JWKS
- `valid_keys`: Number of keys that have required fields

## Examples

### Basic JWKS Validation

```tcl
# Valid JWKS
set jwks_data {
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "n": "modulus-value",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "key-2",
      "crv": "P-256",
      "x": "x-coord",
      "y": "y-coord"
    }
  ]
}
}

set result [tossl::oidc::validate_jwks -jwks $jwks_data]
if {[dict get $result valid]} {
    puts "JWKS is valid with [dict get $result keys_count] keys"
} else {
    puts "JWKS validation failed"
}
```

### Validation Before JWK Retrieval

```tcl
# Validate JWKS before using it
set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://example.com/jwks.json"]

set validation [tossl::oidc::validate_jwks -jwks $jwks]
if {![dict get $validation valid]} {
    error "Invalid JWKS structure"
}

# Now safe to use for JWK retrieval
set key [tossl::oidc::get_jwk -jwks $jwks -kid "specific-key"]
```

### Error Handling Examples

```tcl
# Test various error conditions
set test_cases {
    {"Invalid JSON" "invalid json"}
    {"Missing keys field" "{}"}
    {"Empty keys array" '{"keys":[]}'}
    {"Keys not array" '{"keys":"not-an-array"}'}
}

foreach {description data} $test_cases {
    if {[catch {
        tossl::oidc::validate_jwks -jwks $data
    } result]} {
        puts "$description: $result"
    } else {
        puts "$description: Should have failed"
    }
}
```

### Complete OIDC Flow with Validation

```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Fetch JWKS
set jwks [tossl::oidc::fetch_jwks -jwks_uri [dict get $config jwks_uri]]

# 3. Validate JWKS structure
set validation [tossl::oidc::validate_jwks -jwks $jwks]
if {![dict get $validation valid]} {
    error "Invalid JWKS structure: expected [dict get $validation keys_count] keys, got [dict get $validation valid_keys] valid"
}

puts "JWKS validation passed: [dict get $validation valid_keys] valid keys out of [dict get $validation keys_count] total"

# 4. Use JWKS for JWT verification (future)
# set verified [tossl::oidc::validate_id_token -token $id_token -jwks $jwks ...]
```

## Error Handling

### Invalid JSON Format

```tcl
if {[catch {
    tossl::oidc::validate_jwks -jwks "invalid json"
} result]} {
    puts "Error: $result"
    # Expected: "Invalid JSON format"
}
```

### Missing Keys Field

```tcl
if {[catch {
    tossl::oidc::validate_jwks -jwks "{}"
} result]} {
    puts "Error: $result"
    # Expected: "Missing 'keys' field"
}
```

### Empty Keys Array

```tcl
if {[catch {
    tossl::oidc::validate_jwks -jwks '{"keys":[]}'
} result]} {
    puts "Error: $result"
    # Expected: "No keys found in JWKS"
}
```

### Invalid Keys Format

```tcl
if {[catch {
    tossl::oidc::validate_jwks -jwks '{"keys":"not-an-array"}'
} result]} {
    puts "Error: $result"
    # Expected: "Invalid 'keys' field format"
}
```

### Missing Required Key Fields

```tcl
# JWKS with keys missing required fields
set invalid_jwks {
{
  "keys": [
    {
      "kty": "RSA"
      # Missing "kid" field
    }
  ]
}
}

set result [tossl::oidc::validate_jwks -jwks $invalid_jwks]
if {[dict get $result valid_keys] < [dict get $result keys_count]} {
    puts "Some keys are missing required fields"
}
```

## Performance

- **Validation Time**: < 1 millisecond for typical JWKS
- **Memory Usage**: Minimal - only parses JSON structure
- **Scalability**: Handles JWKS with hundreds of keys efficiently

## Security Considerations

1. **Structural Validation Only**: This command only validates structure, not cryptographic properties
2. **No Network Requests**: Validation is performed locally without external calls
3. **Required Fields**: Ensures keys have minimum required fields for JWT verification
4. **Input Sanitization**: Validates JSON format before processing

## Integration with Other Commands

This command is designed to work with other OIDC commands:

```tcl
# Complete validation workflow
set jwks [tossl::oidc::fetch_jwks -jwks_uri "https://example.com/jwks.json"]

# Validate structure
set validation [tossl::oidc::validate_jwks -jwks $jwks]
if {![dict get $validation valid]} {
    error "JWKS validation failed"
}

# Use for specific key retrieval
set key [tossl::oidc::get_jwk -jwks $jwks -kid "specific-key"]

# Use for JWT verification (future)
# tossl::oidc::validate_id_token -token $id_token -jwks $jwks ...
```

## Common Use Cases

1. **Pre-flight Validation**: Validate JWKS before using it in production
2. **Error Detection**: Catch JWKS format issues early
3. **Quality Assurance**: Ensure JWKS meets requirements
4. **Debugging**: Identify issues with JWKS structure

## See Also

- `::tossl::oidc::fetch_jwks` - Fetch JWKS from provider
- `::tossl::oidc::get_jwk` - Get specific JWK by key ID
- `::tossl::oidc::validate_id_token` - Validate OIDC ID tokens (future)
- `::tossl::jwt::verify` - Verify JWT signatures (future) 