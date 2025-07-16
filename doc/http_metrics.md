# ::tossl::http::metrics

Retrieve HTTP request statistics and performance metrics.

## Overview

`::tossl::http::metrics` provides cumulative statistics about all HTTP requests made through the TOSSL HTTP commands. It tracks request counts, response times, and performance metrics across the entire application session. This is useful for monitoring, debugging, and performance analysis of HTTP operations.

## Syntax

```
tossl::http::metrics
```

**No parameters required.**

## Examples

```tcl
# Get current metrics
set metrics [tossl::http::metrics]
puts "Total requests: [dict get $metrics total_requests]"
puts "Average response time: [dict get $metrics avg_response_time] ms"
puts "Total request time: [dict get $metrics total_request_time] ms"

# Monitor performance during operations
puts "Before requests: [dict get [tossl::http::metrics] total_requests]"

# Make some HTTP requests
tossl::http::get "https://httpbin.org/get"
tossl::http::post "https://httpbin.org/post" "test data"

puts "After requests: [dict get [tossl::http::metrics] total_requests]"

# Calculate performance statistics
set metrics [tossl::http::metrics]
if {[dict get $metrics total_requests] > 0} {
    set avg_time [dict get $metrics avg_response_time]
    set total_time [dict get $metrics total_request_time]
    puts "Performance Summary:"
    puts "  Average response time: ${avg_time}ms"
    puts "  Total time spent: ${total_time}ms"
    puts "  Requests per second: [expr {[dict get $metrics total_requests] / ($total_time / 1000.0)}]"
}
```

## Return Value

Returns a Tcl dictionary with the following keys:

- `total_requests`: Total number of HTTP requests made since initialization
- `avg_response_time`: Average response time in milliseconds across all requests
- `total_request_time`: Total cumulative time spent on all requests in milliseconds

### Example Return Value

```tcl
{
    total_requests 5
    avg_response_time 125.5
    total_request_time 627.5
}
```

## How Metrics Are Collected

Metrics are automatically updated by all HTTP commands:
- `tossl::http::get`
- `tossl::http::post`
- `tossl::http::request`
- `tossl::http::upload`
- Session-based commands

Each successful HTTP request updates:
1. **total_requests**: Incremented by 1
2. **total_request_time**: Accumulated with the request duration
3. **avg_response_time**: Automatically calculated as `total_request_time / total_requests`

## Use Cases

### Performance Monitoring
```tcl
# Monitor application performance
set start_metrics [tossl::http::metrics]

# Perform operations
foreach url $urls {
    tossl::http::get $url
}

set end_metrics [tossl::http::metrics]
set new_requests [expr {[dict get $end_metrics total_requests] - [dict get $start_metrics total_requests]}]
puts "Processed $new_requests requests"
```

### Debugging and Troubleshooting
```tcl
# Check if requests are being made
set metrics [tossl::http::metrics]
if {[dict get $metrics total_requests] == 0} {
    puts "Warning: No HTTP requests have been made"
} else {
    puts "HTTP activity detected: [dict get $metrics total_requests] requests"
}
```

### Performance Analysis
```tcl
# Analyze response time patterns
set metrics [tossl::http::metrics]
set avg_time [dict get $metrics avg_response_time]

if {$avg_time > 1000} {
    puts "Warning: Average response time is high: ${avg_time}ms"
} elseif {$avg_time > 500} {
    puts "Notice: Response time is moderate: ${avg_time}ms"
} else {
    puts "Good: Response time is acceptable: ${avg_time}ms"
}
```

## Important Notes

- **Global Scope**: Metrics are global across the entire TOSSL session
- **Persistent**: Metrics accumulate until the application restarts
- **Real-time**: Metrics are updated immediately after each request
- **Thread Safety**: Metrics are not thread-safe in multi-threaded environments
- **Reset**: There is no built-in way to reset metrics; they persist for the session

## Best Practices

- **Monitor Regularly**: Check metrics periodically to identify performance issues
- **Baseline Comparison**: Compare metrics before and after operations
- **Threshold Monitoring**: Set up alerts for high response times
- **Session Tracking**: Use metrics to track performance across application sessions
- **Debugging**: Use metrics to verify that requests are being made as expected

## Limitations

- Metrics are not persisted across application restarts
- No per-request detailed metrics (use `-return_details` for individual requests)
- No breakdown by HTTP method or URL
- No error rate tracking
- No bandwidth usage statistics

## See Also
- `tossl::http::get`
- `tossl::http::post`
- `tossl::http::request`
- `tossl::http::debug` 