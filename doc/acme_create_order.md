# ::tossl::acme::create_order

## Overview

The `::tossl::acme::create_order` command creates a new certificate order for the specified domains. This is a key step in the ACME certificate issuance process, where you request a certificate for one or more domain names from the certificate authority.

## Syntax

```tcl
::tossl::acme::create_order <directory_url> <account_key> <domains>
```

- `<directory_url>`: ACME server directory URL (e.g., Let's Encrypt staging)
- `<account_key>`: PEM-encoded private key for the ACME account
- `<domains>`: Space-separated list of domain names

## Return Value

Returns a status message indicating whether the order was successfully created:
- `"Order created successfully"` on success
- Error message on failure

## Examples

### Basic Order Creation

```tcl
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set account_key "-----BEGIN PRIVATE KEY-----\n..."
set domains "example.com"

set result [tossl::acme::create_order $directory_url $account_key $domains]
puts "Order creation: $result"
```

### Multiple Domain Order

```tcl
set domains "example.com www.example.com api.example.com"
set result [tossl::acme::create_order $directory_url $account_key $domains]
```

### Complete ACME Workflow

```tcl
# Step 1: Generate account key
set account_keys [tossl::key::generate -type rsa -bits 2048]
set account_private [dict get $account_keys private]

# Step 2: Create ACME account
set result [tossl::acme::create_account $directory_url $account_private $email]
puts "Account creation: $result"

# Step 3: Create certificate order
set domains "example.com www.example.com"
set order_result [tossl::acme::create_order $directory_url $account_private $domains]
puts "Order creation: $order_result"

# Step 4: Prepare DNS-01 challenge
set challenge [tossl::acme::dns01_challenge "example.com" $token $account_private "cloudflare" $api_key $zone_id]
```

### Wildcard Domain Order

```tcl
set domains "example.com *.example.com"
set result [tossl::acme::create_order $directory_url $account_key $domains]
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **Invalid domain list**: Cannot parse the domains parameter
- **Empty domains**: No valid domains provided
- **Server errors**: ACME server communication failures

### Error Handling Example

```tcl
proc safe_create_order {directory_url account_key domains} {
    set rc [catch {
        set result [tossl::acme::create_order $directory_url $account_key $domains]
    } err]
    if {$rc != 0} {
        return [dict create error $err]
    }
    return [dict create success $result]
}

set result [safe_create_order $directory_url $account_key $domains]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Success: [dict get $result success]"
}
```

## Security Considerations

- **Domain Validation**: Ensure you control all domains in the order
- **Account Key Security**: Store account keys securely
- **Directory URL Validation**: Verify the ACME server URL before use
- **Rate Limits**: Be aware of ACME server rate limits

## Best Practices

- Use Let's Encrypt staging for testing to avoid production rate limits
- Validate domain ownership before creating orders
- Use strong account keys (RSA 2048+ or EC P-256+)
- Handle rate limits gracefully
- Monitor order status and handle failures

## Related Commands

- `::tossl::acme::directory` — Get ACME server directory
- `::tossl::acme::create_account` — Create a new ACME account
- `::tossl::acme::dns01_challenge` — Prepare DNS-01 challenge
- `::tossl::acme::cleanup_dns` — Clean up DNS challenge records
- `::tossl::key::generate` — Generate account keys
- `::tossl::http::get` — HTTP client for API communication

## Troubleshooting

- **"Failed to parse domains"**: Check domain list format
- **"Order creation failed"**: Verify account and server status
- **"Invalid key format"**: Ensure account key is valid PEM format
- **"Server communication error"**: Check network and ACME server status

### Debugging Tips

```tcl
proc debug_create_order {directory_url account_key domains} {
    puts "Creating ACME order"
    puts "  Directory: $directory_url"
    puts "  Domains: $domains"
    
    set rc [catch {
        set result [tossl::acme::create_order $directory_url $account_key $domains]
    } err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    puts "Result: $result"
}
```

## Performance Notes

- Order creation is typically fast but depends on network latency
- Use staging servers for testing to avoid production rate limits
- Consider caching directory information for multiple operations

## Testing

### Test with Let's Encrypt Staging

```tcl
set staging_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set test_domains "test.example.com"
set result [tossl::acme::create_order $staging_url $account_key $test_domains]
puts "Staging order creation: $result"
``` 