# ::tossl::oauth2::authorization_url_pkce

Generate an OAuth2 authorization URL for the Authorization Code flow with PKCE (RFC 7636).

## Syntax

    tossl::oauth2::authorization_url_pkce -client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url> -code_challenge <challenge> -code_challenge_method S256

- `-client_id <id>`: The OAuth2 client ID (required)
- `-redirect_uri <uri>`: The redirect URI (required)
- `-scope <scope>`: The requested scopes (required)
- `-state <state>`: Opaque value to maintain state (recommended)
- `-authorization_url <url>`: The base authorization endpoint URL (required)
- `-code_challenge <challenge>`: The PKCE code challenge (required)
- `-code_challenge_method S256`: The PKCE challenge method (required)

## Description

Builds a standards-compliant OAuth2 authorization URL with PKCE parameters for enhanced security. Used to initiate the Authorization Code flow with Proof Key for Code Exchange (PKCE).

## Output

Returns the full authorization URL as a string.

## Examples

```tcl
set code_verifier [tossl::oauth2::generate_code_verifier -length 64]
set code_challenge [tossl::oauth2::create_code_challenge -verifier $code_verifier]
set url [tossl::oauth2::authorization_url_pkce \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile" \
    -state "test_state" \
    -authorization_url "https://auth.example.com/oauth/authorize" \
    -code_challenge $code_challenge \
    -code_challenge_method S256]
puts $url
# Output: https://auth.example.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=...&code_challenge=...&code_challenge_method=S256&scope=openid%20profile&state=test_state
```

## Error Handling

- If any required argument is missing, an error is returned:

```tcl
tossl::oauth2::authorization_url_pkce -client_id foo -redirect_uri bar -authorization_url baz
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::authorization_url_pkce -foo bar
# Error: wrong # args: should be "-client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url> -code_challenge <challenge> -code_challenge_method S256"
```

## Security Notes

- Always use HTTPS for the authorization URL and redirect URI.
- The state parameter should be a cryptographically random value to prevent CSRF attacks.
- The code challenge must be generated from a high-entropy code verifier.
- Never expose client secrets in the authorization URL. 