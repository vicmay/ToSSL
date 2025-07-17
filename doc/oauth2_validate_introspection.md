# ::tossl::oauth2::validate_introspection

Validate an OAuth2 token introspection result for activity, audience, and issuer.

## Syntax

    tossl::oauth2::validate_introspection -active <0|1> -scope <scopes> -audience <aud> -issuer <iss>

- `-active <0|1>`: Whether the token is active (1) or not (0)
- `-scope <scopes>`: (Optional) Space-separated scopes string
- `-audience <aud>`: The expected audience (required)
- `-issuer <iss>`: The expected issuer (required)

## Description

Checks if the token is active and required fields are present. Returns "valid" if active and all required fields are present, "invalid" otherwise. Errors if required arguments are missing.

## Output

Returns "valid" or "invalid".

## Examples

```tcl
set result [tossl::oauth2::validate_introspection -active 1 -scope "openid profile" -audience "client1" -issuer "https://issuer.example.com"]
puts $result
# Output: valid

set result [tossl::oauth2::validate_introspection -active 0 -scope "openid profile" -audience "client1" -issuer "https://issuer.example.com"]
puts $result
# Output: invalid
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::validate_introspection -active 1 -scope "openid profile"
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::validate_introspection -foo bar
# Error: wrong # args: should be "-active <0|1> -scope <scopes> -audience <aud> -issuer <iss>"
```

## Security Notes

- Always validate both the audience and issuer for security.
- Only treat tokens as valid if active=1 and all required fields are present. 