# ::tossl::oauth2::introspect_token

Perform OAuth2 token introspection (RFC 7662) to check token validity and metadata.

## Syntax

    tossl::oauth2::introspect_token -token <access_token> -introspection_url <url> -client_id <id> -client_secret <secret>

- `-token <access_token>`: The access token to introspect (required)
- `-introspection_url <url>`: The introspection endpoint URL (required)
- `-client_id <id>`: The OAuth2 client ID (required)
- `-client_secret <secret>`: The OAuth2 client secret (required)

## Description

Sends a POST request to the OAuth2 introspection endpoint to check if a token is active and retrieve its metadata. Returns a Tcl dict with fields such as `active`, `scope`, `client_id`, `username`, `exp`, `iat`, `token_type`, and `error` (if any).

## Output

Returns a Tcl dict with the introspection response fields.

## Examples

```tcl
set result [tossl::oauth2::introspect_token \
    -token $access_token \
    -introspection_url "https://provider.example.com/oauth/introspect" \
    -client_id "your_client_id" \
    -client_secret "your_client_secret"]
puts $result
# Output: active 1 scope "openid profile" client_id ...
```

## Error Handling

- If any required argument is missing, an error is returned:

```tcl
tossl::oauth2::introspect_token -token foo -introspection_url bar -client_id baz
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::introspect_token -foo bar
# Error: wrong # args: should be "-token <access_token> -introspection_url <url> -client_id <id> -client_secret <secret>"
```

## Security Notes

- Only send tokens to trusted introspection endpoints over HTTPS.
- Never expose client secrets in logs or error messages.
- The introspection response may contain sensitive information; handle it securely. 