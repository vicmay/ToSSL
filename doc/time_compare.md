# ::tossl::time::compare

## Overview

The `::tossl::time::compare` command calculates the difference between two Unix timestamps and returns the result in seconds. This command is useful for determining time intervals, validating certificate time constraints, and performing time-based calculations in cryptographic operations.

## Syntax

```tcl
::tossl::time::compare <time1> <time2>
```

- `<time1>`: First Unix timestamp (seconds since epoch)
- `<time2>`: Second Unix timestamp (seconds since epoch)

## Return Value

Returns the difference between `time1` and `time2` in seconds as a string:
- **Positive value**: `time1` is later than `time2`
- **Zero**: Both times are equal
- **Negative value**: `time1` is earlier than `time2`

## Examples

### Basic Time Comparison

```tcl
set time1 1640995200
set time2 1640995260
set diff [tossl::time::compare $time1 $time2]
puts "Time difference: $diff seconds"
# Output: Time difference: -60 seconds
```

### Certificate Time Validation

```tcl
# Check if current time is within certificate validity period
set cert_not_before 1640995200
set cert_not_after 1704067200
set current_time [clock seconds]

set before_check [tossl::time::compare $current_time $cert_not_before]
set after_check [tossl::time::compare $cert_not_after $current_time]

if {$before_check >= 0 && $after_check >= 0} {
    puts "Certificate is currently valid"
} else {
    puts "Certificate is not valid"
}
```

### Time Interval Calculation

```tcl
# Calculate time since a specific event
set event_time 1640995200
set current_time [clock seconds]
set elapsed [tossl::time::compare $current_time $event_time]

if {$elapsed > 0} {
    puts "Event occurred $elapsed seconds ago"
} else {
    puts "Event is in the future"
}
```

### Real-time Performance Measurement

```tcl
set start_time [clock seconds]
# ... perform some operation ...
set end_time [clock seconds]
set duration [tossl::time::compare $end_time $start_time]
puts "Operation took $duration seconds"
```

### Multiple Time Comparisons

```tcl
set times {1640995200 1640995260 1640995320 1640995380}
set base_time 1640995200

foreach time $times {
    set diff [tossl::time::compare $time $base_time]
    puts "Time $time: $diff seconds from base"
}
```

### Integration with Time Conversion

```tcl
# Compare ISO 8601 formatted times
set iso_time1 "2022-01-01T00:00:00Z"
set iso_time2 "2022-01-02T00:00:00Z"

set unix_time1 [tossl::time::convert iso8601 $iso_time1]
set unix_time2 [tossl::time::convert iso8601 $iso_time2]
set diff [tossl::time::compare $unix_time2 $unix_time1]

puts "Difference between $iso_time1 and $iso_time2: $diff seconds"
# Output: Difference between 2022-01-01T00:00:00Z and 2022-01-02T00:00:00Z: 86400 seconds
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **Wrong number of arguments**: Too many or too few parameters

### Error Handling Example

```tcl
proc safe_time_compare {time1 time2} {
    set rc [catch {
        set result [tossl::time::compare $time1 $time2]
    } err]
    if {$rc != 0} {
        return [dict create error $err]
    }
    return [dict create success $result]
}

set result [safe_time_compare "1000" "2000"]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Difference: [dict get $result success] seconds"
}
```

## Security Considerations

- **Input Validation**: Always validate timestamp inputs before comparison
- **Overflow Protection**: Large timestamp differences may cause integer overflow
- **Time Zone Awareness**: Ensure timestamps are in the same timezone for accurate comparison
- **Precision**: Unix timestamps have second-level precision

## Best Practices

### Use for Time-based Validation

```tcl
# Good: Use for certificate time validation
proc validate_certificate_time {not_before not_after} {
    set current_time [clock seconds]
    set before_valid [expr {[tossl::time::compare $current_time $not_before] >= 0}]
    set after_valid [expr {[tossl::time::compare $not_after $current_time] >= 0}]
    return [expr {$before_valid && $after_valid}]
}
```

### Handle Edge Cases

```tcl
# Handle edge cases gracefully
proc compare_times_safe {time1 time2} {
    # Validate inputs are numeric
    if {![string is integer $time1] || ![string is integer $time2]} {
        return [dict create error "Invalid timestamp format"]
    }
    
    # Check for reasonable time range
    if {$time1 < 0 || $time2 < 0} {
        return [dict create error "Negative timestamps not supported"]
    }
    
    set diff [tossl::time::compare $time1 $time2]
    return [dict create success $diff]
}
```

### Performance Optimization

```tcl
# For repeated comparisons, cache current time
set current_time [clock seconds]
set times {1640995200 1640995260 1640995320}

foreach time $times {
    set diff [tossl::time::compare $current_time $time]
    puts "Time $time: $diff seconds from now"
}
```

## Related Commands

- `::tossl::time::convert` — Convert between time formats
- `::tossl::x509::time_validate` — Validate certificate time validity
- `::tossl::x509::validate` — Comprehensive certificate validation

## Troubleshooting

### Common Issues

1. **Unexpected negative values**
   - Check the order of timestamps (time1 vs time2)
   - Verify timestamp formats are consistent

2. **Large time differences**
   - Ensure timestamps are in the same timezone
   - Check for timestamp format issues

3. **Zero differences when expected**
   - Verify both timestamps are different
   - Check for precision issues

### Debugging Tips

```tcl
proc debug_time_compare {time1 time2} {
    puts "Comparing times:"
    puts "  Time1: $time1"
    puts "  Time2: $time2"
    
    set rc [catch {
        set result [tossl::time::compare $time1 $time2]
    } err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    puts "Result: $result seconds"
    
    # Show human-readable interpretation
    if {$result > 0} {
        puts "Interpretation: Time1 is $result seconds later than Time2"
    } elseif {$result < 0} {
        puts "Interpretation: Time1 is [expr abs($result)] seconds earlier than Time2"
    } else {
        puts "Interpretation: Times are equal"
    }
}
```

## Performance Notes

- **Fast operation**: Time comparison is computationally inexpensive
- **Memory efficient**: No additional memory allocation required
- **Scalable**: Performance remains consistent regardless of timestamp size
- **Thread-safe**: Safe for concurrent access

### Performance Example

```tcl
# Performance test
set start_time [clock clicks -microseconds]
for {set i 0} {$i < 10000} {incr i} {
    tossl::time::compare $i [expr $i + 1]
}
set end_time [clock clicks -microseconds]
puts "10000 comparisons took: [expr $end_time - $start_time] microseconds"
```

## Testing

### Test with Different Scenarios

```tcl
# Test various time comparison scenarios
set test_cases {
    {1000 500 500}
    {500 1000 -500}
    {1000 1000 0}
    {0 31536000 -31536000}
    {31536000 0 31536000}
}

foreach {time1 time2 expected} $test_cases {
    set result [tossl::time::compare $time1 $time2]
    if {$result == $expected} {
        puts "✓ $time1 vs $time2: $result"
    } else {
        puts "✗ $time1 vs $time2: expected $expected, got $result"
    }
}
```

### Integration Testing

```tcl
# Test integration with time conversion
set iso_times {
    {"2022-01-01T00:00:00Z" "2022-01-02T00:00:00Z" 86400}
    {"2022-01-01T00:00:00Z" "2022-01-01T01:00:00Z" 3600}
}

foreach {time1_str time2_str expected} $iso_times {
    set unix_time1 [tossl::time::convert iso8601 $time1_str]
    set unix_time2 [tossl::time::convert iso8601 $time2_str]
    set result [tossl::time::compare $unix_time2 $unix_time1]
    
    if {$result == $expected} {
        puts "✓ $time1_str vs $time2_str: $result seconds"
    } else {
        puts "✗ $time1_str vs $time2_str: expected $expected, got $result"
    }
}
``` 