# ::tossl::oauth2::is_token_expired

Check if an OAuth2 token is expired based on its metadata.

## Syntax

    tossl::oauth2::is_token_expired -token <token_json>

- `-token <token_json>`: The JSON string containing token metadata (must include `expires_at` or `expires_in`)

## Description

Checks if the provided OAuth2 token is expired. If `expires_at` is present, compares it to the current time. If only `expires_in` is present, assumes the token is valid (since the issue time is unknown). Returns 1 if expired, 0 if valid.

## Output

Returns 1 if the token is expired, 0 if valid.

## Examples

```tcl
set token_json "{\"expires_in\":3600,\"expires_at\":0}"
set expired [tossl::oauth2::is_token_expired -token $token_json]
puts $expired
# Output: 1

set token_json "{\"expires_in\":3600,\"expires_at\":[expr {[clock seconds] + 3600}]}"
set valid [tossl::oauth2::is_token_expired -token $token_json]
puts $valid
# Output: 0
```

## Error Handling

- If the token JSON is invalid, an error is returned:

```tcl
tossl::oauth2::is_token_expired -token not_json
# Error: Invalid token data JSON
```

## Security Notes

- Always check token expiration before using access tokens in security-sensitive operations. 