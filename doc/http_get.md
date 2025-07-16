# ::tossl::http::get

Perform an HTTP GET request and return the response.

## Overview

`::tossl::http::get` performs a simple HTTP GET request to the specified URL using libcurl. It returns the response as a Tcl dictionary containing the status code, response body, and headers.

## Syntax

```
tossl::http::get <url>
```

- `<url>`: The URL to fetch (required).

## Example

```tcl
set response [tossl::http::get "https://httpbin.org/get"]
puts "Status: [dict get $response status_code]"
puts "Body: [dict get $response body]"
puts "Headers: [dict get $response headers]"
```

## Return Value

Returns a Tcl dictionary with the following keys:
- `status_code`: HTTP status code (e.g., 200, 404, 500)
- `body`: Response body as a string
- `headers`: Response headers as a string

## Error Handling

- Returns an error if the URL is missing.
- Invalid URLs or network failures return status_code 0 in the response dictionary.
- Returns an error if curl initialization fails.

## Security Considerations

- Always validate URLs before making requests.
- Be aware that HTTP requests may expose sensitive information in logs.
- Consider using HTTPS for sensitive data transmission.
- Handle response data securely and validate input.

## Best Practices

- Always check the status code before processing the response body.
- Handle network timeouts and connection errors gracefully.
- Validate response data before using it in your application.
- Use appropriate error handling for production applications.

## See Also
- `tossl::http::post`
- `tossl::http::get_enhanced` (for advanced options) 