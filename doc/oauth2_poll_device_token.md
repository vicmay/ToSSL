# ::tossl::oauth2::poll_device_token

Poll for device authorization completion and retrieve access tokens (RFC 8628).

## Syntax

    tossl::oauth2::poll_device_token -device_code <code> -token_url <url> -client_id <id> -client_secret <secret>

- `-device_code <code>`: The device code received from the device authorization request
- `-token_url <url>`: The OAuth2 token endpoint URL
- `-client_id <id>`: The OAuth2 client ID
- `-client_secret <secret>`: The OAuth2 client secret

## Description

Polls the OAuth2 token endpoint to check if the user has completed the device authorization flow. This command is used in conjunction with `tossl::oauth2::device_authorization` to complete the OAuth2 Device Authorization Grant flow (RFC 8628). The command sends a POST request with the device code and client credentials to retrieve access tokens once the user has authorized the device.

## Output

Returns a Tcl dict with the token response fields such as `access_token`, `token_type`, `refresh_token`, `scope`, `expires_in`, and any error fields.

## Examples

```tcl
# First, initiate device authorization
set device_auth [tossl::oauth2::device_authorization \
    -client_id "your_client_id" \
    -device_authorization_url "https://provider.example.com/oauth/device/code" \
    -scope "openid profile email"]

# Extract the device code
set device_code [dict get $device_auth device_code]
set user_code [dict get $device_auth user_code]
set verification_uri [dict get $device_auth verification_uri]

# Display instructions to user
puts "Please visit: $verification_uri"
puts "Enter code: $user_code"

# Poll for completion (in practice, you would do this in a loop with delays)
set token_result [tossl::oauth2::poll_device_token \
    -device_code $device_code \
    -token_url "https://provider.example.com/oauth/token" \
    -client_id "your_client_id" \
    -client_secret "your_client_secret"]

# Check for errors
if {[dict exists $token_result error]} {
    puts "Error: [dict get $token_result error]"
} else {
    puts "Access token: [dict get $token_result access_token]"
    puts "Token type: [dict get $token_result token_type]"
    puts "Expires in: [dict get $token_result expires_in] seconds"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::poll_device_token
# Error: wrong # args: should be "tossl::oauth2::poll_device_token -device_code <code> -token_url <url> -client_id <id> -client_secret <secret>"
```

- If any required parameter is missing, an error is returned:

```tcl
tossl::oauth2::poll_device_token -device_code foo -token_url bar -client_id baz
# Error: Missing required parameters
```

- If the server returns an error, the dict will include an `error` field:

```tcl
# Common error responses
# {"error": "authorization_pending"} - User hasn't completed authorization yet
# {"error": "slow_down"} - Polling too frequently, increase interval
# {"error": "expired_token"} - Device code has expired
# {"error": "access_denied"} - User denied the authorization
```

## Security Notes

- Only use trusted token endpoints over HTTPS.
- Never expose client secrets in logs or error messages.
- The device code should be kept confidential until the user completes verification.
- Implement proper polling intervals (typically 5-10 seconds) to avoid overwhelming the server.
- The device code has a limited lifetime (usually 15-20 minutes); handle expiration gracefully.
- This command is part of the OAuth2 Device Authorization Grant flow and should be used with appropriate user interaction.

## Implementation Notes

- The command uses the `urn:ietf:params:oauth:grant-type:device_code` grant type as specified in RFC 8628.
- The response format follows the standard OAuth2 token response structure.
- In production applications, implement proper retry logic with exponential backoff for failed requests. 