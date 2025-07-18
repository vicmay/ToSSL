# ::tossl::base64url::encode

Encode data to a base64url-encoded string (RFC 4648 URL-safe variant, no padding).

## Syntax

    tossl::base64url::encode <data>

- `<data>`: The data to encode (string or byte array)

## Description

Encodes binary or string data to a base64url-encoded string:
- Uses `-` and `_` instead of `+` and `/`.
- Omits all trailing `=` padding (as per RFC 4648).
- Output is safe for use in URLs, JWT, JWK, OAuth2, ACME, etc.

## Output

Returns the base64url-encoded string (no padding).

## Examples

```tcl
set b64url [tossl::base64url::encode "hello world!"]
puts $b64url  ;# Output: aGVsbG8gd29ybGQh

set b64url [tossl::base64url::encode "Hello-_world!"]
puts $b64url  ;# Output: SGVsbG8tX3dvcmxkIQ

set b64url [tossl::base64url::encode [binary format H* "deadbeef"]]
puts $b64url  ;# Output: 3q2-7w

# Empty string
puts [tossl::base64url::encode ""]  ;# Output: (empty string)
```

## Error Handling

- Returns an error if the wrong number of arguments is provided.

## Security Notes

- Input is not validated as safe for all consumers; ensure you trust the input source.
- Output is URL-safe and contains only unreserved base64url characters. 