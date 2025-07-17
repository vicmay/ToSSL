# ::tossl::oauth2::generate_state

Generate a cryptographically random OAuth2 state parameter.

## Syntax

    tossl::oauth2::generate_state

## Description

Generates a 64-character hexadecimal string suitable for use as the OAuth2 state parameter. The state value is used to prevent CSRF attacks in OAuth2 flows.

## Output

Returns a random 64-character string.

## Examples

```tcl
set state [tossl::oauth2::generate_state]
puts $state
# Output: (random 64-char hex string)
```

## Error Handling

- If any argument is provided, an error is returned:

```tcl
tossl::oauth2::generate_state foo
# Error: wrong # args: should be "tossl::oauth2::generate_state"
```

## Security Notes

- Always use a cryptographically random state value for each OAuth2 request.
- Never reuse state values between requests.
- Store the state value securely until the OAuth2 callback is received. 