# ::tossl::oauth2::generate_code_verifier

Generate a high-entropy PKCE code verifier string (RFC 7636).

## Syntax

    tossl::oauth2::generate_code_verifier ?-length N?

- `-length N`: (Optional) Length of the code verifier (43-128, default: 64)

## Description

Generates a random, URL-safe code verifier suitable for OAuth2 PKCE flows. The verifier is a high-entropy string between 43 and 128 characters, using the allowed PKCE character set.

## Output

Returns the code verifier string.

## Examples

```tcl
set verifier [tossl::oauth2::generate_code_verifier -length 64]
puts $verifier
# Output: (random 64-char string)

set verifier [tossl::oauth2::generate_code_verifier -length 128]
puts $verifier
# Output: (random 128-char string)
```

## Error Handling

- If the length is below 43 or above 128, an error is returned:

```tcl
tossl::oauth2::generate_code_verifier -length 10
# Error: Failed to generate code verifier
```

- If an unknown argument is provided, an error is returned:

```tcl
tossl::oauth2::generate_code_verifier -foo bar
# Error: wrong # args: should be "tossl::oauth2::generate_code_verifier ?-length N?"
```

## Security Notes

- The code verifier must be unpredictable and high-entropy.
- Use only the allowed PKCE character set (A-Z, a-z, 0-9, '-', '.', '_', '~').
- Never reuse code verifiers between authorization requests.
- Store the code verifier securely until the token exchange step. 