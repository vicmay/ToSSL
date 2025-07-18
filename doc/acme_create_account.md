# ::tossl::acme::create_account

## Overview

The `::tossl::acme::create_account` command creates a new ACME account with the specified email address. This is the first step in the ACME certificate issuance process, establishing your identity with the certificate authority.

## Syntax

```tcl
::tossl::acme::create_account <directory_url> <account_key> <email> ?<contact>?
```

- `<directory_url>`: ACME server directory URL (e.g., Let's Encrypt staging)
- `<account_key>`: PEM-encoded private key for the ACME account
- `<email>`: Email address for account notifications and contact
- `<contact>`: Additional contact information (optional)

## Return Value

Returns a status message indicating whether the account was successfully created:
- `"Account created successfully"` on success
- Error message on failure

## Examples

### Basic Account Creation

```tcl
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set account_key "-----BEGIN PRIVATE KEY-----\n..."
set email "admin@example.com"

set result [tossl::acme::create_account $directory_url $account_key $email]
puts "Account creation: $result"
```

### Account Creation with Additional Contact

```tcl
set contact "https://example.com/contact"
set result [tossl::acme::create_account $directory_url $account_key $email $contact]
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
set order_result [tossl::acme::create_order $directory_url $account_private "example.com"]
```

### Multiple Email Formats

```tcl
set emails {admin@example.com user@test.org contact@domain.co.uk}
foreach email $emails {
    set result [tossl::acme::create_account $directory_url $account_key $email]
    puts "Account for $email: $result"
}
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **Invalid directory URL**: Cannot fetch ACME directory
- **Account key issues**: Invalid or unsupported key format
- **Email validation**: Invalid email format
- **Server errors**: ACME server communication failures

### Error Handling Example

```tcl
proc safe_create_account {directory_url account_key email contact} {
    set rc [catch {
        set result [tossl::acme::create_account $directory_url $account_key $email $contact]
    } err]
    if {$rc != 0} {
        return [dict create error $err]
    }
    return [dict create success $result]
}

set result [safe_create_account $directory_url $account_key $email $contact]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Success: [dict get $result success]"
}
```

## Security Considerations

- **Account Key Security**: Store account keys securely - they are critical for ACME operations
- **Email Privacy**: Use a dedicated email for ACME notifications
- **Directory URL Validation**: Verify the ACME server URL before use
- **Contact Information**: Be careful with additional contact information

## Best Practices

- Use Let's Encrypt staging for testing to avoid rate limits
- Generate strong account keys (RSA 2048+ or EC P-256+)
- Store account keys securely and backup appropriately
- Use dedicated email addresses for ACME notifications
- Monitor account status and handle notifications properly

## Related Commands

- `::tossl::acme::directory` — Get ACME server directory
- `::tossl::acme::create_order` — Create certificate order
- `::tossl::acme::dns01_challenge` — Prepare DNS-01 challenge
- `::tossl::acme::cleanup_dns` — Clean up DNS challenge records
- `::tossl::key::generate` — Generate account keys
- `::tossl::http::get` — HTTP client for API communication

## Troubleshooting

- **"Failed to get newAccount URL"**: Check directory URL and network connectivity
- **"Account creation failed"**: Verify email format and server status
- **"Invalid key format"**: Ensure account key is valid PEM format
- **"Server communication error"**: Check network and ACME server status

### Debugging Tips

```tcl
proc debug_create_account {directory_url account_key email contact} {
    puts "Creating ACME account"
    puts "  Directory: $directory_url"
    puts "  Email: $email"
    puts "  Contact: $contact"
    
    set rc [catch {
        set result [tossl::acme::create_account $directory_url $account_key $email $contact]
    } err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    puts "Result: $result"
}
```

## Performance Notes

- Account creation is typically fast but depends on network latency
- Use staging servers for testing to avoid production rate limits
- Consider caching directory information for multiple operations

## Testing

### Test with Let's Encrypt Staging

```tcl
set staging_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set test_email "test@example.com"
set result [tossl::acme::create_account $staging_url $account_key $test_email]
puts "Staging account creation: $result"
``` 