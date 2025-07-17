# ::tossl::oauth2::auto_refresh

Automatically refresh an OAuth2 access token using the refresh token.

## Syntax

    tossl::oauth2::auto_refresh -token_data <dict> -client_id <id> -client_secret <secret> -token_url <url>

- `-token_data <dict>`: The token data as a JSON string (must include `refresh_token`)
- `-client_id <id>`: The OAuth2 client ID
- `-client_secret <secret>`: The OAuth2 client secret
- `-token_url <url>`: The token endpoint URL

## Description

Attempts to refresh the OAuth2 access token using the provided refresh token and client credentials. Returns the new token response as a Tcl dict. If the refresh token is missing or invalid, or if required arguments are missing, an error is returned.

## Output

Returns a Tcl dict with the new token fields on success.

## Examples

```tcl
set token_data "{\"refresh_token\":\"test_refresh\"}"
set client_id "myclient"
set client_secret "mysecret"
set token_url "https://auth.example.com/oauth/token"
set rc [catch {tossl::oauth2::auto_refresh -token_data $token_data -client_id $client_id -client_secret $client_secret -token_url $token_url} result]
puts $result
# Output: (token dict or error)
```

## Error Handling

- If the refresh token is missing, an error is returned:

```tcl
tossl::oauth2::auto_refresh -token_data "{}" -client_id foo -client_secret bar -token_url baz
# Error: No refresh token available
```

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::auto_refresh -token_data "{}" -client_id foo
# Error: wrong # args: should be "tossl::oauth2::auto_refresh -token_data <dict> -client_id <id> -client_secret <secret> -token_url <url>"
```

## Security Notes

- Always validate the new token data after refresh.
- Never expose client secrets in logs or error messages. 