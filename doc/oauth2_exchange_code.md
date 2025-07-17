# ::tossl::oauth2::exchange_code

Exchange an OAuth2 authorization code for access and refresh tokens.

## Syntax

    tossl::oauth2::exchange_code -client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url>

- `-client_id <id>`: The OAuth2 client ID (required)
- `-client_secret <secret>`: The OAuth2 client secret (required)
- `-code <code>`: The authorization code received from the authorization server (required)
- `-redirect_uri <uri>`: The redirect URI used in the authorization request (required)
- `-token_url <url>`: The token endpoint URL (required)

## Description

Sends a POST request to the OAuth2 token endpoint to exchange an authorization code for access and refresh tokens. Returns a Tcl dict with fields such as `access_token`, `refresh_token`, `token_type`, `expires_in`, `scope`, and `error` (if any).

## Output

Returns a Tcl dict with the token response fields.

## Examples

```tcl
set result [tossl::oauth2::exchange_code \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -code $auth_code \
    -redirect_uri "https://your-app.com/callback" \
    -token_url "https://provider.example.com/oauth/token"]
puts $result
# Output: access_token ... refresh_token ... token_type ...
```

## Error Handling

- If any required argument is missing, an error is returned:

```tcl
tossl::oauth2::exchange_code -client_id foo -client_secret bar -code baz -redirect_uri qux
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::exchange_code -foo bar
# Error: wrong # args: should be "-client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url>"
```

## Security Notes

- Only send credentials to trusted token endpoints over HTTPS.
- Never expose client secrets or authorization codes in logs or error messages.
- Store access and refresh tokens securely. 