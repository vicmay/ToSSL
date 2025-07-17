# ::tossl::oauth2::exchange_code_pkce

Exchange an OAuth2 authorization code for access tokens using PKCE (RFC 7636).

## Syntax

    tossl::oauth2::exchange_code_pkce -client_id <id> -code_verifier <verifier> -code <code> -redirect_uri <uri> -token_url <url>

- `-client_id <id>`: The OAuth2 client ID (required)
- `-code_verifier <verifier>`: The PKCE code verifier used in the authorization request (required)
- `-code <code>`: The authorization code received from the authorization server (required)
- `-redirect_uri <uri>`: The redirect URI used in the authorization request (required)
- `-token_url <url>`: The token endpoint URL (required)

## Description

Sends a POST request to the OAuth2 token endpoint to exchange an authorization code for access tokens using PKCE (Proof Key for Code Exchange). This command is used in OAuth2 PKCE flows to securely exchange authorization codes without requiring a client secret, making it suitable for public clients like mobile apps and SPAs.

## Output

Returns a Tcl dict with the token response fields such as `access_token`, `refresh_token`, `token_type`, `expires_in`, `scope`, and `error` (if any).

## Examples

```tcl
# First, generate PKCE parameters for the authorization request
set code_verifier [tossl::oauth2::generate_code_verifier -length 64]
set code_challenge [tossl::oauth2::create_code_challenge -verifier $code_verifier]

# Create authorization URL with PKCE
set auth_url [tossl::oauth2::authorization_url_pkce \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -code_challenge $code_challenge \
    -code_challenge_method S256 \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url "https://provider.example.com/oauth/authorize"]

puts "Visit: $auth_url"

# After user authorization, exchange the code for tokens
set token_result [tossl::oauth2::exchange_code_pkce \
    -client_id "your_client_id" \
    -code_verifier $code_verifier \
    -code $auth_code \
    -redirect_uri "https://your-app.com/callback" \
    -token_url "https://provider.example.com/oauth/token"]

# Check for errors
if {[dict exists $token_result error]} {
    puts "Error: [dict get $token_result error]"
    if {[dict exists $token_result error_description]} {
        puts "Description: [dict get $token_result error_description]"
    }
} else {
    puts "Access token: [dict get $token_result access_token]"
    puts "Token type: [dict get $token_result token_type]"
    puts "Expires in: [dict get $token_result expires_in] seconds"
    if {[dict exists $token_result refresh_token]} {
        puts "Refresh token: [dict get $token_result refresh_token]"
    }
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::exchange_code_pkce -client_id foo -code_verifier bar -code baz -redirect_uri qux
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::exchange_code_pkce -foo bar
# Error: wrong # args: should be "-client_id <id> -code_verifier <verifier> -code <code> -redirect_uri <uri> -token_url <url>"
```

- If the server returns an error, the dict will include an `error` field:

```tcl
# Common error responses
# {"error": "invalid_grant"} - Authorization code is invalid or expired
# {"error": "invalid_client"} - Client ID is invalid
# {"error": "invalid_request"} - Missing required parameters
# {"error": "unauthorized_client"} - Client not authorized for this grant type
```

## Security Notes

- Only use trusted token endpoints over HTTPS.
- The code verifier must match the one used in the authorization request.
- Never expose authorization codes in logs or error messages.
- PKCE provides protection against authorization code interception attacks.
- This flow is suitable for public clients that cannot securely store client secrets.
- The code verifier should be stored securely until the token exchange is complete.

## Implementation Notes

- The command uses the `authorization_code` grant type with PKCE parameters.
- The code verifier is sent in the `code_verifier` parameter as specified in RFC 7636.
- The response format follows the standard OAuth2 token response structure.
- PKCE is recommended for all OAuth2 flows, especially for public clients.

## PKCE Flow Overview

1. **Generate PKCE parameters**: Use `tossl::oauth2::generate_code_verifier` and `tossl::oauth2::create_code_challenge`
2. **Authorization request**: Use `tossl::oauth2::authorization_url_pkce` with the code challenge
3. **User authorization**: User completes the authorization flow
4. **Token exchange**: Use this command with the authorization code and code verifier
5. **Token usage**: Use the received access token for API calls 