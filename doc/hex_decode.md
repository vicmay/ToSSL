# ::tossl::hex::decode

Decode a hexadecimal string to a Tcl byte array.

## Syntax

    tossl::hex::decode <hex_string>

- `<hex_string>`: The hexadecimal string to decode

## Description

Decodes a hexadecimal string to its original binary form. This command converts pairs of hexadecimal digits (0-9, a-f, A-F) into their corresponding byte values.

- Accepts both uppercase and lowercase hexadecimal digits.
- Requires an even number of hexadecimal digits (each byte is represented by two hex digits).
- Returns a Tcl byte array with the decoded data.
- The empty string decodes to an empty byte array.

## Output

Returns the decoded data as a Tcl byte array.

## Examples

```tcl
# Basic decoding
set hex "68656c6c6f20776f726c6421"
set decoded [tossl::hex::decode $hex]
puts $decoded  ;# Output: hello world!

# Roundtrip with encode
set data "Hello, World!"
set encoded [tossl::hex::encode $data]
set decoded [tossl::hex::decode $encoded]
puts $decoded  ;# Output: Hello, World!

# Uppercase hex
set hex_upper "68656C6C6F20776F726C6421"
set decoded [tossl::hex::decode $hex_upper]
puts $decoded  ;# Output: hello world!

# Mixed case hex
set hex_mixed "68656c6C6F20776F726C6421"
set decoded [tossl::hex::decode $hex_mixed]
puts $decoded  ;# Output: hello world!

# Binary data
set hex_binary "deadbeef"
set decoded [tossl::hex::decode $hex_binary]
set decoded_hex [binary encode hex $decoded]
puts $decoded_hex  ;# Output: deadbeef

# Single byte
set hex_single "41"
set decoded [tossl::hex::decode $hex_single]
puts $decoded  ;# Output: A

# Two bytes
set hex_two "4142"
set decoded [tossl::hex::decode $hex_two]
puts $decoded  ;# Output: AB

# Unicode text
set unicode_hex "d09fd180d0b8d0b2d0b5d18220d0bcd0b8d18021"
set decoded [tossl::hex::decode $unicode_hex]
puts $decoded  ;# Output: Привет мир!

# Empty string
tossl::hex::decode ""  ;# Returns empty byte array
```

## Error Handling

- Returns an error if the input has an odd number of characters (hex strings must have an even length).
- Returns an error if the input contains invalid hexadecimal characters (only 0-9, a-f, A-F are allowed).
- Returns an error if the wrong number of arguments is provided.

## Common Error Cases

```tcl
# Odd length (missing one hex digit)
tossl::hex::decode "123"  ;# Error: Invalid hex string length

# Invalid hex characters
tossl::hex::decode "12g3"  ;# Error: Invalid hex string
tossl::hex::decode "123g"  ;# Error: Invalid hex string

# Wrong number of arguments
tossl::hex::decode  ;# Error: wrong # args
tossl::hex::decode "1234" "5678"  ;# Error: wrong # args
```

## Performance Considerations

- The command efficiently processes hex strings of any reasonable size.
- For very large hex strings, consider processing in chunks if memory is a concern.
- The implementation uses `strtol()` for robust hex parsing with proper error detection.

## Security Notes

- Input validation ensures only valid hexadecimal characters are processed.
- The command safely handles large inputs without buffer overflow vulnerabilities.
- Invalid input is rejected rather than producing undefined output.

## Related Commands

- `::tossl::hex::encode` - Encode binary data to hexadecimal string
- `::tossl::base64::decode` - Decode base64-encoded data
- `::tossl::base64url::decode` - Decode base64url-encoded data

## Implementation Details

The command uses the following algorithm:
1. Validates that the input length is even
2. Allocates memory for the decoded data (half the length of the hex string)
3. Processes the hex string in pairs, converting each pair to a byte using `strtol()`
4. Validates that each conversion was successful
5. Returns the decoded data as a Tcl byte array

This implementation provides robust error handling and efficient processing for both small and large hex strings. 