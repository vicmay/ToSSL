# ::tossl::oauth2::refresh_token

Refresh an OAuth2 access token using a refresh token and client credentials.

## Syntax

    tossl::oauth2::refresh_token -client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url>

- `-client_id <id>`: The OAuth2 client ID
- `-client_secret <secret>`: The OAuth2 client secret
- `-refresh_token <token>`: The refresh token to use
- `-token_url <url>`: The token endpoint URL

## Description

Attempts to refresh the OAuth2 access token using the provided refresh token and client credentials. Returns the new token response as a Tcl dict. If the refresh token is missing or invalid, or if required arguments are missing, an error is returned.

## Output

Returns a Tcl dict with the new token fields on success. If the HTTP request fails or the server returns an error, the dict will include error fields.

## Examples

```tcl
set client_id "myclient"
set client_secret "mysecret"
set refresh_token "test_refresh"
set token_url "https://auth.example.com/oauth/token"
set rc [catch {tossl::oauth2::refresh_token -client_id $client_id -client_secret $client_secret -refresh_token $refresh_token -token_url $token_url} result]
puts $result
# Output: (token dict or error)
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::refresh_token -client_id foo
# Error: wrong # args: should be "tossl::oauth2::refresh_token -client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url>"
```

- If the HTTP request fails (e.g., no server), an error is returned:

```tcl
tossl::oauth2::refresh_token -client_id foo -client_secret bar -refresh_token baz -token_url qux
# Error: HTTP request failed
```

## Security Notes

- Always validate the new token data after refresh.
- Never expose client secrets in logs or error messages. 