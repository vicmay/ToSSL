# HTTP Debug Command

## Overview

The `::tossl::http::debug` command controls debug logging for HTTP operations in the TOSSL library. This command allows developers to enable or disable debug output with different verbosity levels to help troubleshoot HTTP requests, responses, and errors.

## Syntax

```tcl
::tossl::http::debug enable|disable ?-level verbose|info|warning|error?
```

## Parameters

### Action
- **`enable`** - Enables debug logging
- **`disable`** - Disables debug logging

### Options
- **`-level`** - Specifies the debug verbosity level (optional)
  - **`verbose`** - Most detailed output (level 4)
  - **`info`** - Standard information output (level 3, default)
  - **`warning`** - Warning and error messages only (level 2)
  - **`error`** - Error messages only (level 1)

## Return Value

Returns a status message indicating the current debug state:
- `"Debug logging enabled"` - When debug is successfully enabled
- `"Debug logging disabled"` - When debug is successfully disabled

## Debug Levels

The debug system uses numeric levels internally:

| Level | Name | Description |
|-------|------|-------------|
| 0 | none | No debug output (disabled) |
| 1 | error | Only error messages |
| 2 | warning | Warning and error messages |
| 3 | info | Standard information, warnings, and errors |
| 4 | verbose | All debug information including detailed request/response data |

## Examples

### Basic Usage

```tcl
;# Enable debug logging with default info level
::tossl::http::debug enable

;# Disable debug logging
::tossl::http::debug disable
```

### Specifying Debug Levels

```tcl
;# Enable verbose debugging
::tossl::http::debug enable -level verbose

;# Enable warning-level debugging
::tossl::http::debug enable -level warning

;# Enable error-only debugging
::tossl::http::debug enable -level error
```

### Integration with HTTP Requests

```tcl
;# Enable debug before making requests
::tossl::http::debug enable -level info

;# Make HTTP requests (debug output will be shown)
set response [::tossl::http::get "https://httpbin.org/get"]

;# Disable debug when done
::tossl::http::debug disable
```

### Error Handling

```tcl
;# Enable error-level debugging
::tossl::http::debug enable -level error

;# Make a request that might fail
set response [::tossl::http::get "https://nonexistent-domain.com"]

;# Debug will show error messages if the request fails
::tossl::http::debug disable
```

### Multiple Operations

```tcl
;# Enable debug for a series of operations
::tossl::http::debug enable -level info

;# Multiple HTTP requests
set response1 [::tossl::http::get "https://httpbin.org/get"]
set response2 [::tossl::http::post "https://httpbin.org/post" "test data"]

;# Disable debug when finished
::tossl::http::debug disable
```

## Error Handling

### Invalid Actions

```tcl
;# This will return an error
catch {::tossl::http::debug invalid_action} error_msg
puts $error_msg
;# Output: Invalid action: use 'enable' or 'disable'
```

### Invalid Levels

```tcl
;# Invalid levels are ignored, enable still works
::tossl::http::debug enable -level invalid_level
;# This will still enable debug with default info level
```

### Wrong Number of Arguments

```tcl
;# No arguments
catch {::tossl::http::debug} error_msg
puts $error_msg
;# Output: wrong # args: should be "tossl::http::debug enable|disable ?-level verbose|info|warning|error?"

;# Only level without action
catch {::tossl::http::debug -level verbose} error_msg
puts $error_msg
;# Output: wrong # args: should be "tossl::http::debug enable|disable ?-level verbose|info|warning|error?"
```

## Debug Output

When debug is enabled, the following information may be logged to stdout:

### Error Level (1)
- HTTP request failures
- Connection errors
- SSL/TLS errors
- Timeout errors

### Warning Level (2)
- All error messages
- SSL certificate warnings
- Redirect warnings
- Performance warnings

### Info Level (3)
- All warning and error messages
- Request initiation
- Response completion
- Basic timing information

### Verbose Level (4)
- All info, warning, and error messages
- Detailed request headers
- Response headers
- SSL/TLS details
- Redirect information
- Detailed timing data

## Best Practices

### 1. Use Appropriate Debug Levels

```tcl
;# For production troubleshooting - use error level
::tossl::http::debug enable -level error

;# For development - use info level
::tossl::http::debug enable -level info

;# For detailed analysis - use verbose level
::tossl::http::debug enable -level verbose
```

### 2. Always Disable Debug in Production

```tcl
;# Enable debug for troubleshooting
::tossl::http::debug enable -level error

;# Make your requests
set response [::tossl::http::get "https://api.example.com/data"]

;# Always disable when done
::tossl::http::debug disable
```

### 3. Use Debug with Error Handling

```tcl
;# Enable debug
::tossl::http::debug enable -level warning

;# Make request with error handling
if {[catch {
    set response [::tossl::http::get "https://api.example.com/data"]
} error_msg]} {
    puts "Request failed: $error_msg"
    ;# Debug output will show additional details
}

;# Disable debug
::tossl::http::debug disable
```

### 4. Debug Session Management

```tcl
;# Enable debug for session operations
::tossl::http::debug enable -level info

;# Create session
::tossl::http::session::create "my_session"

;# Use session
::tossl::http::session::get "my_session" "https://httpbin.org/get"

;# Destroy session
::tossl::http::session::destroy "my_session"

;# Disable debug
::tossl::http::debug disable
```

## Performance Considerations

- Debug output is written to stdout and may impact performance
- Verbose level generates the most output and should be used sparingly
- Consider disabling debug in production environments
- Debug output is not captured by TCL commands - it goes directly to stdout

## Integration with Other HTTP Commands

The debug command affects all HTTP-related commands:

- `::tossl::http::get`
- `::tossl::http::post`
- `::tossl::http::request`
- `::tossl::http::upload`
- `::tossl::http::session::*` commands

## Troubleshooting

### Common Issues

1. **No debug output visible**
   - Ensure debug is enabled before making HTTP requests
   - Check that the debug level is appropriate for the information you need

2. **Too much debug output**
   - Use a lower debug level (error or warning)
   - Consider using info level for most debugging needs

3. **Debug not working with sessions**
   - Debug affects all HTTP operations including sessions
   - Enable debug before creating sessions

### Debug Level Selection Guide

| Use Case | Recommended Level |
|----------|-------------------|
| Production error monitoring | error |
| Development troubleshooting | info |
| Performance analysis | verbose |
| SSL/TLS debugging | verbose |
| Network connectivity issues | warning |

## Related Commands

- `::tossl::http::metrics` - Get HTTP request statistics
- `::tossl::http::get` - Make HTTP GET requests
- `::tossl::http::post` - Make HTTP POST requests
- `::tossl::http::request` - Make custom HTTP requests
- `::tossl::http::upload` - Upload files via HTTP 