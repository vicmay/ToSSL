# ::tossl::http::post

Perform HTTP POST requests with comprehensive options for data transmission.

## Overview

`::tossl::http::post` is an enhanced HTTP POST command that supports sending data to web servers with full control over headers, content types, authentication, and other HTTP parameters. It provides a simple yet powerful interface for making POST requests with various data formats.

## Syntax

```
tossl::http::post url data ?-headers {header1 value1}? ?-content_type type? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-return_details boolean?
```

### Required Parameters
- `url`: The URL to send the POST request to
- `data`: The data to send in the request body

### Optional Parameters
- `-headers <headers>`: Custom HTTP headers (newline-separated)
- `-content_type <type>`: Content-Type header (default: application/x-www-form-urlencoded)
- `-timeout <seconds>`: Request timeout in seconds (default: 30)
- `-user_agent <string>`: Custom User-Agent string
- `-follow_redirects <boolean>`: Whether to follow redirects (default: true)
- `-verify_ssl <boolean>`: Whether to verify SSL certificates (default: true)
- `-proxy <url>`: Proxy URL
- `-auth <username:password>`: Authentication credentials
- `-return_details <boolean>`: Whether to return detailed response info (default: false)

## Examples

```tcl
# Basic POST request
set response [tossl::http::post "https://httpbin.org/post" "name=test&value=123"]

# POST with JSON data
set response [tossl::http::post "https://api.example.com/data" \
    '{"key": "value", "number": 42}' \
    -content_type "application/json"]

# POST with custom headers and authentication
set response [tossl::http::post "https://api.example.com/submit" \
    "form data" \
    -headers "Authorization: Bearer token123\nX-Custom-Header: value" \
    -auth "username:password" \
    -timeout 60]

# POST with form data
set response [tossl::http::post "https://example.com/form" \
    "name=John&email=john@example.com" \
    -content_type "application/x-www-form-urlencoded"]

# POST with detailed response information
set response [tossl::http::post "https://httpbin.org/post" \
    "test data" \
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

- Returns an error if required parameters (`url` or `data`) are missing.
- Invalid URLs or network failures return status_code 0 in the response dictionary.
- Returns an error if curl initialization fails.
- Authentication failures result in appropriate HTTP status codes (401, 403).

## Security Considerations

- Always validate URLs before making requests.
- Use HTTPS for sensitive data transmission.
- Be careful with authentication credentials in logs.
- Validate response data before processing.
- Consider using `-verify_ssl 1` for production environments.
- Sanitize user input before sending in POST data.

## Best Practices

- Always check the status code before processing the response.
- Use appropriate content types for different data formats:
  - `application/json` for JSON data
  - `application/x-www-form-urlencoded` for form data
  - `text/plain` for plain text
  - `application/xml` for XML data
- Use appropriate timeouts for different types of requests.
- Handle network errors and timeouts gracefully.
- Use `-return_details` for debugging and monitoring.
- Validate input data and URLs before sending requests.
- Use authentication when required by the API.

## Common Use Cases

- **API Integration**: Sending JSON data to REST APIs
- **Form Submission**: Submitting HTML forms
- **File Upload**: Sending file data (use `tossl::http::upload` for multipart)
- **Data Synchronization**: Sending data to remote servers
- **Webhook Notifications**: Sending notifications to webhook endpoints

## See Also
- `tossl::http::get`
- `tossl::http::request`
- `tossl::http::upload` 