# ::tossl::oauth2::create_code_challenge

Create a PKCE code challenge from a code verifier (RFC 7636, S256 method).

## Syntax

    tossl::oauth2::create_code_challenge -verifier <code_verifier>

- `-verifier <code_verifier>`: The code verifier string (43-128 chars, URL-safe)

## Description

Computes the PKCE code challenge (S256) for the given code verifier. This is used in OAuth2 PKCE flows to securely bind the authorization request to the token exchange.

## Output

Returns the code challenge string (base64url-encoded SHA-256 hash of the verifier).

## Examples

```tcl
set verifier [tossl::oauth2::generate_code_verifier -length 64]
set challenge [tossl::oauth2::create_code_challenge -verifier $verifier]
puts $challenge
# Output: (base64url-encoded string)
```

## Error Handling

- If the `-verifier` argument is missing or invalid, an error is returned:

```tcl
tossl::oauth2::create_code_challenge
# Error: wrong # args: should be "tossl::oauth2::create_code_challenge -verifier <code_verifier>"
```

## Security Notes

- The code verifier should be a high-entropy, random string (43-128 chars, URL-safe).
- The code challenge is used to prevent authorization code interception attacks in OAuth2 PKCE flows. 