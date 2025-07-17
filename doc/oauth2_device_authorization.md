# ::tossl::oauth2::device_authorization

Initiate an OAuth2 Device Authorization Grant (RFC 8628) request.

## Syntax

    tossl::oauth2::device_authorization -client_id <id> -device_authorization_url <url> ?-scope <scope>?

- `-client_id <id>`: The OAuth2 client ID
- `-device_authorization_url <url>`: The device authorization endpoint URL
- `-scope <scope>`: (Optional) The requested scopes

## Description

Sends a device authorization request to the specified OAuth2 server. Returns a dict with fields such as `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`, and `error` (if any). This command is used in device and IoT flows where the user must visit a verification URL and enter a code.

## Output

Returns a Tcl dict with the device authorization response fields.

## Examples

```tcl
set result [tossl::oauth2::device_authorization \
    -client_id "your_client_id" \
    -device_authorization_url "https://provider.example.com/oauth/device/code" \
    -scope "openid profile email"]
puts $result
# Output: device_code ... user_code ... verification_uri ...
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::device_authorization
# Error: wrong # args: should be "tossl::oauth2::device_authorization -client_id <id> -device_authorization_url <url> ?-scope <scope>?"
```

- If the server returns an error, the dict will include an `error` field.

## Security Notes

- Only use trusted device authorization endpoints.
- The device code and user code should be kept confidential until the user completes verification.
- This command does not perform polling or token retrieval; use `tossl::oauth2::poll_device_token` to complete the flow. 