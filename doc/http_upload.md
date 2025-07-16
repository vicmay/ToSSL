# ::tossl::http::upload

Upload a file using HTTP multipart form data.

## Overview

`::tossl::http::upload` performs an HTTP file upload using multipart/form-data encoding. It supports custom field names, additional form fields, and custom headers. The command uses libcurl's MIME API for efficient file handling.

## Syntax

```
tossl::http::upload <url> <file_path> ?-field_name <name>? ?-additional_fields <fields>? ?-headers <headers>?
```

- `<url>`: The URL to upload to (required).
- `<file_path>`: Path to the file to upload (required).
- `-field_name <name>`: Form field name for the file (default: "file").
- `-additional_fields <fields>`: Additional form fields in "field:value" format, separated by newlines.
- `-headers <headers>`: Custom HTTP headers, separated by newlines.

## Example

```tcl
# Basic file upload
set response [tossl::http::upload "https://httpbin.org/post" "myfile.txt"]

# Upload with custom field name and additional fields
set response [tossl::http::upload "https://httpbin.org/post" "myfile.txt" \
    -field_name "document" \
    -additional_fields "description:Important document\ncategory:work"]

# Upload with custom headers
set response [tossl::http::upload "https://httpbin.org/post" "myfile.txt" \
    -headers "Authorization: Bearer token123\nX-Custom-Header: value"]
```

## Return Value

Returns a Tcl dictionary with the following keys:
- `status_code`: HTTP status code (e.g., 200, 404, 500)
- `body`: Response body as a string
- `headers`: Response headers as a string
- `request_time`: Request time in milliseconds
- `response_size`: Size of response in bytes
- `error_message`: Error message if any

## Error Handling

- Returns an error if the URL or file path is missing.
- Invalid URLs or network failures return status_code 0 in the response dictionary.
- Non-existent files return status_code 0 in the response dictionary.
- Returns an error if curl initialization fails.

## Security Considerations

- Always validate file paths before uploading.
- Be aware that file uploads may expose sensitive information in logs.
- Consider using HTTPS for sensitive file uploads.
- Validate file types and sizes on the server side.
- Handle uploaded files securely and validate input.

## Best Practices

- Always check the status code before processing the response.
- Use appropriate file size limits for uploads.
- Validate file types and content before uploading.
- Handle network timeouts and connection errors gracefully.
- Clean up temporary files after upload.

## See Also
- `tossl::http::post`
- `tossl::http::request` 