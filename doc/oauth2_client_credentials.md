# ::tossl::oauth2::client_credentials

Obtain an OAuth2 access token using the Client Credentials flow (RFC 6749).

## Syntax

    tossl::oauth2::client_credentials -client_id <id> -client_secret <secret> -token_url <url> ?-scope <scope>?

- `-client_id <id>`: The OAuth2 client ID (required)
- `-client_secret <secret>`: The OAuth2 client secret (required)
- `-token_url <url>`: The token endpoint URL (required)
- `-scope <scope>`: (Optional) The requested scopes

## Description

Sends a POST request to the OAuth2 token endpoint to obtain an access token using the client credentials grant. Returns a Tcl dict with fields such as `access_token`, `token_type`, `expires_in`, `scope`, and `error` (if any).

## Output

Returns a Tcl dict with the token response fields.

## Examples

```tcl
set result [tossl::oauth2::client_credentials \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -token_url "https://provider.example.com/oauth/token" \
    -scope "api:read"]
puts $result
# Output: access_token ... token_type ... expires_in ...
```

## Error Handling

- If any required argument is missing, an error is returned:

```tcl
tossl::oauth2::client_credentials -client_id foo -client_secret bar
# Error: Missing required parameters
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::client_credentials -foo bar
# Error: wrong # args: should be "-client_id <id> -client_secret <secret> -token_url <url> ?-scope <scope>?"
```

## Security Notes

- Only send credentials to trusted token endpoints over HTTPS.
- Never expose client secrets in logs or error messages.
- Store access tokens securely and use the minimum required scope. 