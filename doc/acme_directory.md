# ::tossl::acme::directory

## Overview

The `::tossl::acme::directory` command fetches and parses the ACME directory from the specified URL. The ACME directory provides endpoint URLs for account creation, order creation, nonce retrieval, and other ACME operations. This command is essential for initializing ACME workflows and discovering the correct endpoints for further protocol steps.

## Syntax

```tcl
::tossl::acme::directory <directory_url>
```

- `<directory_url>`: ACME server directory URL (e.g., Let's Encrypt staging)

## Return Value

Returns a Tcl dict containing ACME endpoint URLs, such as:
- `newAccount`: URL for account creation
- `newOrder`: URL for order creation
- `newNonce`: URL for nonce retrieval
- `revokeCert`: URL for certificate revocation
- `keyChange`: URL for key rollover

## Examples

### Fetching the ACME Directory

```tcl
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set directory [tossl::acme::directory $directory_url]
puts "New account URL: [dict get $directory newAccount]"
puts "New order URL: [dict get $directory newOrder]"
```

### Using Directory in ACME Workflow

```tcl
set directory [tossl::acme::directory $directory_url]
set account_key [tossl::key::generate -type rsa -bits 2048]
set result [tossl::acme::create_account $directory_url [dict get $account_key private] "admin@example.com"]
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **Invalid directory URL**: Cannot fetch ACME directory
- **Network errors**: HTTP request fails
- **Malformed JSON**: Directory response is not valid JSON

### Error Handling Example

```tcl
set rc [catch {set directory [tossl::acme::directory $directory_url]} err]
if {$rc != 0} {
    puts "Error fetching directory: $err"
} else {
    puts "Directory keys: [dict keys $directory]"
}
```

## Security Considerations

- **Directory URL Validation**: Always verify the ACME server URL before use
- **Network Security**: Ensure HTTPS is used for all ACME directory requests
- **Endpoint Trust**: Only use endpoints from trusted ACME directories

## Best Practices

- Use Let's Encrypt staging for testing to avoid production rate limits
- Cache the directory dict for repeated use in workflows
- Validate the presence of required endpoints in the returned dict
- Handle network and parsing errors gracefully

## Related Commands

- `::tossl::acme::create_account` — Create a new ACME account
- `::tossl::acme::create_order` — Create a certificate order
- `::tossl::acme::dns01_challenge` — Prepare DNS-01 challenge
- `::tossl::acme::cleanup_dns` — Clean up DNS challenge records
- `::tossl::http::get` — HTTP client for API communication

## Troubleshooting

- **"Failed to get response body"**: Check directory URL and network connectivity
- **"Failed to parse directory JSON"**: Directory response is not valid JSON
- **"HTTP request failed"**: Check network and ACME server status

### Debugging Tips

```tcl
proc debug_acme_directory {directory_url} {
    puts "Fetching ACME directory: $directory_url"
    set rc [catch {set directory [tossl::acme::directory $directory_url]} err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    puts "Directory keys: [dict keys $directory]"
    foreach {key value} $directory {
        puts "$key: $value"
    }
}
```

## Performance Notes

- Directory fetch is typically fast but depends on network latency
- Consider caching the directory dict for multiple operations

## Testing

### Test with Let's Encrypt Staging

```tcl
set staging_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set directory [tossl::acme::directory $staging_url]
puts "Staging directory keys: [dict keys $directory]"
``` 