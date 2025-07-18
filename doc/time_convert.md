# ::tossl::time::convert

## Overview

The `::tossl::time::convert` command converts time values between different formats and returns a Unix timestamp. This is useful for standardizing time representations across different systems and protocols, particularly in cryptographic operations and certificate validation.

## Syntax

```tcl
::tossl::time::convert <format> <time_str>
```

- `<format>`: The time format to convert from ("unix", "iso8601", "rfc2822")
- `<time_str>`: The time string to convert

## Supported Formats

### Unix Timestamp
- **Format**: `unix`
- **Input**: Unix timestamp (seconds since epoch)
- **Example**: `1640995200`

### ISO 8601
- **Format**: `iso8601`
- **Input**: ISO 8601 formatted string (YYYY-MM-DDTHH:MM:SSZ)
- **Example**: `2022-01-01T00:00:00Z`

### RFC 2822
- **Format**: `rfc2822`
- **Input**: RFC 2822 formatted string
- **Example**: `Sat, 01 Jan 2022 00:00:00 +0000`

## Return Value

Returns a Unix timestamp as a string representing seconds since January 1, 1970 UTC.

## Examples

### Convert Unix Timestamp

```tcl
set unix_time 1640995200
set result [tossl::time::convert unix $unix_time]
puts "Unix timestamp: $result"
# Output: Unix timestamp: 1640995200
```

### Convert ISO 8601 Time

```tcl
set iso_time "2022-01-01T00:00:00Z"
set result [tossl::time::convert iso8601 $iso_time]
puts "Unix timestamp: $result"
# Output: Unix timestamp: 1640995200
```

### Convert RFC 2822 Time

```tcl
set rfc_time "Sat, 01 Jan 2022 00:00:00 +0000"
set result [tossl::time::convert rfc2822 $rfc_time]
puts "Unix timestamp: $result"
# Output: Unix timestamp: 1640995200
```

### Certificate Time Validation

```tcl
# Convert certificate notBefore time
set cert_time "2022-01-01T00:00:00Z"
set unix_time [tossl::time::convert iso8601 $cert_time]
set current_time [clock seconds]

if {$unix_time <= $current_time} {
    puts "Certificate is valid (notBefore passed)"
} else {
    puts "Certificate is not yet valid"
}
```

### Multiple Format Conversion

```tcl
set times {
    "unix" "1640995200"
    "iso8601" "2022-01-01T00:00:00Z"
    "rfc2822" "Sat, 01 Jan 2022 00:00:00 +0000"
}

foreach {format time_str} $times {
    set result [tossl::time::convert $format $time_str]
    puts "$format: $time_str -> $result"
}
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **Unsupported format**: Format not recognized
- **Invalid time string**: Time string cannot be parsed
- **Malformed input**: Input does not match expected format

### Error Handling Example

```tcl
proc safe_time_convert {format time_str} {
    set rc [catch {
        set result [tossl::time::convert $format $time_str]
    } err]
    if {$rc != 0} {
        return [dict create error $err]
    }
    return [dict create success $result]
}

set result [safe_time_convert "iso8601" "invalid-time"]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Success: [dict get $result success]"
}
```

## Security Considerations

- **Time Zone Handling**: All times are converted to UTC
- **Input Validation**: Always validate time strings before conversion
- **Overflow Protection**: Large timestamps may cause issues on 32-bit systems
- **Format Consistency**: Ensure consistent time format usage across applications

## Best Practices

- Use ISO 8601 format for maximum compatibility
- Validate time strings before conversion
- Handle conversion errors gracefully
- Use UTC times for cryptographic operations
- Consider timezone implications in your application

## Related Commands

- `::tossl::time::compare` — Compare two timestamps
- `::tossl::x509::time_validate` — Validate certificate time validity
- `::tossl::x509::parse` — Parse certificate information including times

## Troubleshooting

- **"Unsupported time format"**: Check that the format is one of "unix", "iso8601", or "rfc2822"
- **"Invalid ISO 8601 format"**: Ensure the time string matches YYYY-MM-DDTHH:MM:SSZ format
- **"Invalid RFC 2822 format"**: Ensure the time string matches RFC 2822 format
- **"Invalid Unix timestamp"**: Ensure the input is a valid number

### Debugging Tips

```tcl
proc debug_time_convert {format time_str} {
    puts "Converting time:"
    puts "  Format: $format"
    puts "  Input: $time_str"
    
    set rc [catch {
        set result [tossl::time::convert $format $time_str]
    } err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    puts "Result: $result"
    
    # Show human-readable time
    set readable [clock format $result -format "%Y-%m-%d %H:%M:%S UTC"]
    puts "Readable: $readable"
}
```

## Performance Notes

- Time conversion is typically very fast
- ISO 8601 and RFC 2822 parsing may be slower than Unix timestamp conversion
- Consider caching converted timestamps for repeated operations

## Testing

### Test with Different Formats

```tcl
# Test all supported formats
set test_cases {
    {unix "1640995200"}
    {iso8601 "2022-01-01T00:00:00Z"}
    {rfc2822 "Sat, 01 Jan 2022 00:00:00 +0000"}
}

foreach {format time_str} $test_cases {
    set result [tossl::time::convert $format $time_str]
    puts "$format: $time_str -> $result"
}
``` 