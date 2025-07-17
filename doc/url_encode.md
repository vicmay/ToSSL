# ::tossl::url::encode

Encode a string as percent-encoded (URL-encoded) data.

## Syntax

    tossl::url::encode <string>

- `<string>`: The string to encode

## Description

Encodes a string as percent-encoded (URL-encoded) data, converting all reserved and non-unreserved characters to `%XX` sequences. Unreserved characters (A-Z, a-z, 0-9, '-', '_', '.', '~') are left unchanged. Reserved and special characters are encoded according to standard URL encoding rules.

## Output

Returns the percent-encoded string.

## Examples

```tcl
set input "hello world"
set encoded [tossl::url::encode $input]
puts $encoded
# Output: hello%20world

set input "!*'();:@&=+$,/?#[]"
set encoded [tossl::url::encode $input]
puts $encoded
# Output: %21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D

set input "AZaz09-_.~"
set encoded [tossl::url::encode $input]
puts $encoded
# Output: AZaz09-_.~
```

## Error Handling

- Returns an error if the wrong number of arguments is provided.

## Security Notes

- Only valid UTF-8 input is supported; invalid input may produce unexpected results.
- Input is not validated as safe for all consumers; ensure you trust the input source. 