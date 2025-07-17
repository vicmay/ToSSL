# ::tossl::url::decode

Decode a percent-encoded (URL-encoded) string.

## Syntax

    tossl::url::decode <encoded_string>

- `<encoded_string>`: The percent-encoded string to decode

## Description

Decodes a percent-encoded (URL-encoded) string, converting all valid `%XX` sequences to their ASCII character equivalents. Reserved and unreserved characters are handled according to standard URL decoding rules. Incomplete or invalid percent sequences are left unchanged.

## Output

Returns the decoded string.

## Examples

```tcl
set encoded "hello%20world"
set decoded [tossl::url::decode $encoded]
puts $decoded
# Output: hello world

set encoded "%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D"
set decoded [tossl::url::decode $encoded]
puts $decoded
# Output: !*'();:@&=+$,/?#[]
```

## Error Handling

- Returns an error if the wrong number of arguments is provided.
- Incomplete or invalid percent-encoded sequences are left unchanged.

## Security Notes

- Only valid percent-encoded sequences are decoded; invalid sequences are not modified.
- Input is not validated as safe for all consumers; ensure you trust the input source. 