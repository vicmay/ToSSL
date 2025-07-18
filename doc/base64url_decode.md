# ::tossl::base64url::decode

Decode a base64url-encoded string (RFC 4648 URL-safe variant) to a Tcl byte array.

## Syntax

    tossl::base64url::decode <base64url_string>

- `<base64url_string>`: The base64url-encoded string to decode (may be padded or unpadded)

## Description

Decodes a base64url-encoded string (using `-` and `_` instead of `+` and `/`, and optional padding) to its original binary form. This is commonly used in web protocols (e.g., JWT, JWK, OAuth2, ACME).

- Accepts both padded and unpadded input.
- Returns a Tcl byte array with the decoded data.
- The empty string decodes to an empty byte array.

## Output

Returns the decoded data as a Tcl byte array.

## Examples

```tcl
set b64url "aGVsbG8gd29ybGQh"
set decoded [tossl::base64url::decode $b64url]
puts $decoded  ;# Output: hello world!

set b64url "SGVsbG8tX3dvcmxkIQ"
set decoded [tossl::base64url::decode $b64url]
puts $decoded  ;# Output: Hello-_world!

# Empty string
tossl::base64url::decode ""  ;# Returns empty byte array
```

## Error Handling

- Returns an error if the input is not valid base64url (e.g., contains invalid characters or incorrect length).
- Returns an error if the wrong number of arguments is provided.

## Security Notes

- Input is not validated as safe for all consumers; ensure you trust the input source.
- Only valid base64url input is accepted; invalid input will cause an error. 