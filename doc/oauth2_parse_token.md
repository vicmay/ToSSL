# ::tossl::oauth2::parse_token

Parse an OAuth2 token response JSON into a Tcl dict.

## Syntax

    tossl::oauth2::parse_token <token_response>

- `<token_response>`: The JSON string returned by the OAuth2 server

## Description

Parses the OAuth2 token response JSON and returns a Tcl dict with fields such as `access_token`, `token_type`, `refresh_token`, `scope`, `expires_in`, and any error fields. This command is useful for extracting token data from the raw server response.

## Output

Returns a Tcl dict with the parsed token fields.

## Examples

```tcl
set response {"access_token":"abc123","token_type":"Bearer","refresh_token":"def456","scope":"read write","expires_in":3600}
set parsed [tossl::oauth2::parse_token $response]
puts $parsed
# Output: access_token abc123 token_type Bearer refresh_token def456 scope {read write} expires_in 3600
```

## Error Handling

- If the argument is missing, an error is returned:

```tcl
tossl::oauth2::parse_token
# Error: wrong # args: should be "tossl::oauth2::parse_token <token_response>"
```

## Security Notes

- Always validate and sanitize token data before use in security-sensitive contexts. 