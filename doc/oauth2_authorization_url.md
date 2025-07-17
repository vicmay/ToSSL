# ::tossl::oauth2::authorization_url

Generate an OAuth2 authorization URL for the Authorization Code flow.

## Syntax

    tossl::oauth2::authorization_url -client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url>

- `-client_id <id>`: The OAuth2 client ID (required)
- `-redirect_uri <uri>`: The redirect URI (required)
- `-scope <scope>`: The requested scopes (required)
- `-state <state>`: Opaque value to maintain state (recommended)
- `-authorization_url <url>`: The base authorization endpoint URL (required)

## Description

Builds a standards-compliant OAuth2 authorization URL with all required parameters, URL-encoded as needed. Used to initiate the Authorization Code flow.

## Output

Returns the full authorization URL as a string.

## Examples

```tcl
set url [tossl::oauth2::authorization_url \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile" \
    -state "test_state" \
    -authorization_url "https://auth.example.com/oauth/authorize"]
puts $url
# Output: https://auth.example.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20profile&state=test_state
```

## Error Handling

- If any required argument is missing, an error is returned:

```tcl
tossl::oauth2::authorization_url -client_id foo -redirect_uri bar -scope baz
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::authorization_url -foo bar
# Error: wrong # args: should be "-client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url>"
```

## Security Notes

- Always use HTTPS for the authorization URL and redirect URI.
- The state parameter should be a cryptographically random value to prevent CSRF attacks.
- Never expose client secrets in the authorization URL. 