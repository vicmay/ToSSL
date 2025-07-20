# OIDC Claims Validation

## Overview

The OIDC claims validation commands provide comprehensive validation for OpenID Connect claims according to the OpenID Connect Core 1.0 specification. These commands allow you to validate required claims, check specific claim values, and validate claim formats.

## Commands

### `tossl::oidc::validate_claims`

Validates OIDC standard claims for presence and format compliance.

#### Syntax

```tcl
tossl::oidc::validate_claims -claims <claims_dict> -required_claims {claim1 claim2 ...}
```

#### Parameters

- **`-claims`** `<claims_dict>`: The claims JSON data to validate
- **`-required_claims`** `{claim1 claim2 ...}`: List of required claim names

#### Return Value

Returns a dictionary containing validation results:

```tcl
{
    valid 1
    missing_claims {}
    invalid_claims {}
}
```

#### Example

```tcl
# Validate required claims
set claims {
    {
        "sub": "1234567890",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "email_verified": true,
        "phone_number": "+1-555-123-4567",
        "picture": "https://example.com/john.jpg"
    }
}

set result [tossl::oidc::validate_claims \
    -claims $claims \
    -required_claims {sub name email email_verified phone_number picture}]

if {[dict get $result valid]} {
    puts "All required claims are present and valid"
} else {
    puts "Missing claims: [dict get $result missing_claims]"
    puts "Invalid claims: [dict get $result invalid_claims]"
}
```

### `tossl::oidc::check_claim`

Checks if a specific claim has the expected value.

#### Syntax

```tcl
tossl::oidc::check_claim -claims <claims_dict> -claim <claim_name> -value <expected_value>
```

#### Parameters

- **`-claims`** `<claims_dict>`: The claims JSON data
- **`-claim`** `<claim_name>`: The name of the claim to check
- **`-value`** `<expected_value>`: The expected value for the claim

#### Return Value

Returns a dictionary containing the check result:

```tcl
{
    matches 1
    claim_name "email"
    expected_value "john.doe@example.com"
    actual_value "john.doe@example.com"
}
```

#### Example

```tcl
# Check if email matches expected value
set result [tossl::oidc::check_claim \
    -claims $claims \
    -claim "email" \
    -value "john.doe@example.com"]

if {[dict get $result matches]} {
    puts "Email matches expected value"
} else {
    puts "Email does not match. Expected: [dict get $result expected_value]"
    puts "Actual: [dict get $result actual_value]"
}
```

### `tossl::oidc::validate_claim_format`

Validates the format of a specific claim value.

#### Syntax

```tcl
tossl::oidc::validate_claim_format -claim <claim_name> -value <claim_value>
```

#### Parameters

- **`-claim`** `<claim_name>`: The name of the claim to validate
- **`-value`** `<claim_value>`: The value to validate

#### Return Value

Returns a dictionary containing validation results:

```tcl
{
    valid 1
    claim_name "email"
    claim_value "john.doe@example.com"
}
```

If validation fails, an error message is included:

```tcl
{
    valid 0
    claim_name "email"
    claim_value "invalid-email"
    error "Invalid email format"
}
```

#### Example

```tcl
# Validate email format
set result [tossl::oidc::validate_claim_format \
    -claim "email" \
    -value "john.doe@example.com"]

if {[dict get $result valid]} {
    puts "Email format is valid"
} else {
    puts "Email format is invalid: [dict get $result error]"
}
```

## Supported Claim Formats

The validation functions support the following claim formats:

### Email Validation
- Must contain `@` symbol
- Must have valid domain part
- Must have TLD (at least 2 characters after last dot)

**Examples:**
- ✅ `john.doe@example.com`
- ✅ `user+tag@domain.org`
- ❌ `invalid-email-format`
- ❌ `user@domain`

### Phone Number Validation
- Must contain only digits, spaces, dashes, parentheses, and `+`
- Must have at least 7 digits

**Examples:**
- ✅ `+1-555-123-4567`
- ✅ `(555) 123-4567`
- ✅ `555 123 4567`
- ❌ `invalid-phone`
- ❌ `123`

### URL Validation
- Must start with `http://` or `https://`
- Must have valid domain part
- Must contain at least one dot

**Examples:**
- ✅ `https://example.com/photo.jpg`
- ✅ `http://api.example.org/data`
- ❌ `not-a-url`
- ❌ `ftp://example.com`

### Boolean Validation
- Accepts various boolean representations

**Examples:**
- ✅ `true`, `false`
- ✅ `1`, `0`
- ✅ `yes`, `no`
- ❌ `maybe`
- ❌ `invalid`

### Timestamp Validation
- Must be a valid integer
- Must be a reasonable timestamp (after 1970, before year 2100)

**Examples:**
- ✅ `1640995200`
- ✅ `1234567890`
- ❌ `not-a-timestamp`
- ❌ `9999999999999`

## Complete OIDC Flow Example

```tcl
# 1. Get claims from ID token or UserInfo
set claims {
    {
        "sub": "1234567890",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "email_verified": true,
        "phone_number": "+1-555-123-4567",
        "picture": "https://example.com/john.jpg",
        "updated_at": 1640995200
    }
}

# 2. Validate required claims
set validation [tossl::oidc::validate_claims \
    -claims $claims \
    -required_claims {sub name email email_verified}]

if {![dict get $validation valid]} {
    error "Required claims validation failed"
}

# 3. Check specific claim values
set email_check [tossl::oidc::check_claim \
    -claims $claims \
    -claim "email" \
    -value "john.doe@example.com"]

if {![dict get $email_check matches]} {
    error "Email does not match expected value"
}

# 4. Validate claim formats
set email_format [tossl::oidc::validate_claim_format \
    -claim "email" \
    -value "john.doe@example.com"]

if {![dict get $email_format valid]} {
    error "Email format is invalid"
}

puts "All claims validation passed!"
```

## Error Handling

The claims validation commands provide comprehensive error handling:

### Common Errors

- **"Invalid claims data"**: Malformed JSON in claims data
- **"Invalid required_claims format"**: Invalid list format for required claims
- **"Claim not found"**: Specified claim does not exist in claims data
- **"Invalid email format"**: Email does not meet format requirements
- **"Invalid phone number format"**: Phone number does not meet format requirements
- **"Invalid URL format"**: URL does not meet format requirements
- **"Invalid boolean format"**: Boolean value is not recognized
- **"Invalid timestamp format"**: Timestamp is not a valid integer or out of range

### Best Practices

1. **Always validate required claims** before processing user data
2. **Check specific claim values** for authorization decisions
3. **Validate claim formats** to ensure data quality
4. **Handle validation errors gracefully** with appropriate user feedback
5. **Use consistent claim names** across your application
6. **Validate claims from trusted sources only** (OIDC providers)

## Integration with Existing OIDC Commands

The claims validation commands integrate seamlessly with other OIDC commands:

```tcl
# Complete OIDC flow with claims validation
set id_token_validation [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "your_client_id"]

if {[dict get $id_token_validation valid]} {
    # Extract claims from ID token
    set claims [dict get $id_token_validation claims]
    
    # Validate required claims
    set claims_validation [tossl::oidc::validate_claims \
        -claims $claims \
        -required_claims {sub name email}]
    
    if {[dict get $claims_validation valid]} {
        puts "User authenticated and claims validated"
    }
}
``` 