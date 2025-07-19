# ::tossl::hex::encode

Encode binary or string data to a hexadecimal string.

## Syntax

    tossl::hex::encode <data>

- `<data>`: The data to encode (string or byte array)

## Description

Encodes binary or string data to a lowercase hexadecimal string. Each byte of input is represented by two hexadecimal digits (0-9, a-f). The output is always lowercase and contains no spaces or separators.

- Handles both string and binary data input.
- Output is always lowercase hexadecimal.
- The empty string encodes to an empty string.

## Output

Returns the hex-encoded string.

## Examples

```tcl
set data "hello world!"
set hex [tossl::hex::encode $data]
puts $hex  ;# Output: 68656c6c6f20776f726c6421

# Roundtrip with decode
set decoded [tossl::hex::decode $hex]
puts $decoded  ;# Output: hello world!

# Binary data
set binary_data [binary format H* "deadbeef"]
set hex [tossl::hex::encode $binary_data]
puts $hex  ;# Output: deadbeef

# Single byte
set hex_single [tossl::hex::encode "A"]
puts $hex_single  ;# Output: 41

# Two bytes
set hex_two [tossl::hex::encode "AB"]
puts $hex_two  ;# Output: 4142

# Unicode text
set unicode_data "Привет мир!"
set hex_unicode [tossl::hex::encode $unicode_data]
set decoded_unicode [tossl::hex::decode $hex_unicode]
puts $decoded_unicode  ;# Output: Привет мир!

# Empty string
tossl::hex::encode ""  ;# Returns empty string
```

## Error Handling

- Returns an error if the wrong number of arguments is provided.
- The command accepts any valid Tcl string or byte array input.

## Security Notes

- Output contains only hexadecimal characters (0-9, a-f) and is safe for transmission in most contexts.
- Input is not validated as safe for all consumers; ensure you trust the input source.

## Related Commands

- `::tossl::hex::decode` - Decode hexadecimal string to binary data
- `::tossl::base64::encode` - Encode data to base64 string
- `::tossl::base64::decode` - Decode base64 string to binary data

## Implementation Details

The command uses the following algorithm:
1. Accepts a string or byte array as input
2. Allocates a buffer for the output (2x input length + 1)
3. Converts each byte to two lowercase hex digits
4. Returns the resulting string

This implementation provides robust and efficient encoding for both small and large inputs. 