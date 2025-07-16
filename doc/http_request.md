# ::tossl::http::request

Perform HTTP requests with full control over method, headers, and options.

## Overview

`::tossl::http::request` is a universal HTTP request command that supports all major HTTP methods (GET, POST, PUT, DELETE, PATCH) with comprehensive options for customization. It provides fine-grained control over headers, authentication, timeouts, and other HTTP parameters.

## Syntax

```
tossl::http::request -method <method> -url <url> ?-data <data>? ?-headers <headers>? ?-content_type <type>? ?-timeout <seconds>? ?-user_agent <string>? ?-follow_redirects <boolean>? ?-verify_ssl <boolean>? ?-proxy <url>? ?-auth <username:password>? ?-cookies <cookies>? ?-return_details <boolean>?
```

### Required Parameters
- `-method <method>`: HTTP method (GET, POST, PUT, DELETE, PATCH)
- `-url <url>`: The URL to request

### Optional Parameters
- `-data <data>`: Request body data
- `-headers <headers>`: Custom HTTP headers (newline-separated)
- `-content_type <type>`: Content-Type header
- `-timeout <seconds>`: Request timeout in seconds (default: 30)
- `-user_agent <string>`: Custom User-Agent string
- `-follow_redirects <boolean>`: Whether to follow redirects (default: true)
- `-verify_ssl <boolean>`: Whether to verify SSL certificates (default: true)
- `-proxy <url>`: Proxy URL
- `-auth <username:password>`: Authentication credentials
- `-cookies <cookies>`: Cookie string
- `-return_details <boolean>`: Whether to return detailed response info (default: false)

## Examples

```tcl
# Basic GET request
set response [tossl::http::request -method GET -url "https://httpbin.org/get"]

# POST request with JSON data
set response [tossl::http::request -method POST -url "https://httpbin.org/post" \
    -data '{"key": "value"}' \
    -content_type "application/json"]

# Request with custom headers and authentication
set response [tossl::http::request -method GET -url "https://api.example.com/data" \
    -headers "Authorization: Bearer token123\nX-Custom-Header: value" \
    -auth "username:password" \
    -timeout 60]

# Request with detailed response information
set response [tossl::http::request -method GET -url "https://httpbin.org/get" \
    -return_details 1]
puts "Request time: [dict get $response request_time] ms"
puts "Response size: [dict get $response response_size] bytes"
```

## Return Value

Returns a Tcl dictionary with the following keys:
- `status_code`: HTTP status code (e.g., 200, 404, 500)
- `body`: Response body as a string
- `headers`: Response headers as a string

### Additional fields when `-return_details` is true:
- `request_time`: Request time in milliseconds
- `response_size`: Size of response in bytes
- `error_message`: Error message if any
- `redirect_count`: Number of redirects followed
- `ssl_info`: SSL verification information (if available)

## Error Handling

- Returns an error if required parameters (`-method` or `-url`) are missing.
- Invalid URLs or network failures return status_code 0 in the response dictionary.
- Returns an error if curl initialization fails.
- Invalid HTTP methods may result in status_code 0.

## Security Considerations

- Always validate URLs before making requests.
- Use HTTPS for sensitive data transmission.
- Be careful with authentication credentials in logs.
- Validate response data before processing.
- Consider using `-verify_ssl 1` for production environments.

## Best Practices

- Always check the status code before processing the response.
- Use appropriate timeouts for different types of requests.
- Handle network errors and timeouts gracefully.
- Use `-return_details` for debugging and monitoring.
- Validate input data and URLs before sending requests.
- Use appropriate content types for different data formats.

## See Also
- `tossl::http::get`
- `tossl::http::post`
- `tossl::http::upload` 