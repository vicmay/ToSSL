# ::tossl::base64::encode

Encode data to a base64-encoded string.

## Syntax

    tossl::base64::encode <data>

- `<data>`: The data to encode (string or byte array)

## Description

Encodes binary or string data to a base64-encoded string following RFC 4648 standard.

- Uses standard base64 alphabet (A-Z, a-z, 0-9, +, /).
- Includes padding with `=` characters as required by the standard.
- Output is compatible with standard base64 encoding used in HTTP, email, and other protocols.
- Handles both string and binary data input.

## Output

Returns the base64-encoded string with proper padding.

## Examples

```tcl
set data "hello world!"
set b64 [tossl::base64::encode $data]
puts $b64  ;# Output: aGVsbG8gd29ybGQh

# Roundtrip with decode
set decoded [tossl::base64::decode $b64]
puts $decoded  ;# Output: hello world!

# Binary data
set binary_data [binary format H* "deadbeef"]
set b64 [tossl::base64::encode $binary_data]
puts $b64  ;# Output: 3q2+7w==

# Special characters
set data_special "Hello+world/with=chars!"
set b64 [tossl::base64::encode $data_special]
puts $b64  ;# Output: SGVsbG8rd29ybGQvd2l0aD1jaGFycyE=

# Empty string
puts [tossl::base64::encode ""]  ;# Output: (empty string)

# Unicode data
set unicode_data "Hello, 世界!"
set b64 [tossl::base64::encode $unicode_data]
puts $b64  ;# Output: SGVsbG8sIOS4reWbvQ==
```

## Padding Behavior

The command follows RFC 4648 padding rules:
- 1 byte input: 2 padding characters (`==`)
- 2 bytes input: 1 padding character (`=`)
- 3 bytes input: no padding
- 4 bytes input: no padding (and so on)

## Error Handling

- Returns an error if the wrong number of arguments is provided.
- The command accepts any valid Tcl string or byte array input.

## Security Notes

- Input is not validated as safe for all consumers; ensure you trust the input source.
- Output contains only standard base64 characters and is safe for transmission in most contexts.
- The encoded output may be longer than the input (approximately 4/3 ratio).

## Implementation Details

- Uses OpenSSL's BIO_f_base64() for encoding.
- Uses `BIO_FLAGS_BASE64_NO_NL` flag to avoid newlines in output.
- Automatically handles padding according to RFC 4648.
- Compatible with standard base64 encoding as used in HTTP, email, and other protocols.
- Handles Unicode strings properly by treating input as string data.
- No size limitations - can handle arbitrarily large data.

## Related Commands

- `::tossl::base64::decode` - Decode base64 string
- `::tossl::base64url::encode` - Encode data to base64url (URL-safe variant)
- `::tossl::base64url::decode` - Decode base64url (URL-safe variant) 