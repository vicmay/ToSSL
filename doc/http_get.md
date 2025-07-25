# ::tossl::http::get

Perform HTTP GET requests with comprehensive options for data retrieval.

## Overview

`::tossl::http::get` is an enhanced HTTP GET command that supports retrieving data from web servers with full control over headers, authentication, timeouts, and other HTTP parameters. It provides a simple yet powerful interface for making GET requests with various customization options.

## Syntax

```
tossl::http::get url ?-headers {header1 value1}? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-return_details boolean?
```

### Required Parameters
- `url`: The URL to send the GET request to

### Optional Parameters
- `-headers <headers>`: Custom HTTP headers (newline-separated)
- `-timeout <seconds>`: Request timeout in seconds (default: 30)
- `-user_agent <string>`: Custom User-Agent string
- `-follow_redirects <boolean>`: Whether to follow redirects (default: true)
- `-verify_ssl <boolean>`: Whether to verify SSL certificates (default: true)
- `-proxy <url>`: Proxy URL
- `-auth <username:password>`: Authentication credentials
- `-return_details <boolean>`: Whether to return detailed response info (default: false)

## Examples

```tcl
# Basic GET request
set response [tossl::http::get "https://httpbin.org/get"]

# GET with custom headers
set response [tossl::http::get "https://api.example.com/data" \
    -headers "Authorization: Bearer token123\nX-Custom-Header: value"]

# GET with authentication and timeout
set response [tossl::http::get "https://api.example.com/secure" \
    -auth "username:password" \
    -timeout 60]

# GET with custom user agent
set response [tossl::http::get "https://httpbin.org/user-agent" \
    -user_agent "MyApp/1.0"]

# GET with detailed response information
set response [tossl::http::get "https://httpbin.org/get" \
    -return_details 1]
puts "Request time: [dict get $response request_time] ms"
puts "Response size: [dict get $response response_size] bytes"

# GET with cookies
set response [tossl::http::get "https://httpbin.org/cookies" \
    -cookies "session=12345; user=test"]
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

- Returns an error if the URL is missing.
- Invalid URLs or network failures return status_code 0 in the response dictionary.
- Returns an error if curl initialization fails.
- Authentication failures result in appropriate HTTP status codes (401, 403).

## Security Considerations

- Always validate URLs before making requests.
- Use HTTPS for sensitive data transmission.
- Be careful with authentication credentials in logs.
- Validate response data before processing.
- Consider using `-verify_ssl 1` for production environments.
- Handle cookies and session data securely.

## Best Practices

- Always check the status code before processing the response.
- Use appropriate timeouts for different types of requests.
- Handle network errors and timeouts gracefully.
- Use `-return_details` for debugging and monitoring.
- Validate input data and URLs before sending requests.
- Use authentication when required by the API.
- Set appropriate user agent strings for your application.

## Common Use Cases

- **API Integration**: Retrieving data from REST APIs
- **Web Scraping**: Fetching web page content
- **Data Synchronization**: Downloading data from remote servers
- **Status Checking**: Monitoring service availability
- **Content Delivery**: Fetching static resources

## See Also
- `tossl::http::post`
- `tossl::http::request`
- `tossl::http::upload` 