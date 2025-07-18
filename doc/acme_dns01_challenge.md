# ::tossl::acme::dns01_challenge

## Overview

The `::tossl::acme::dns01_challenge` command prepares a DNS-01 challenge for ACME certificate validation by creating the required DNS TXT record for a given domain. This is a key step in automated certificate issuance with Let's Encrypt and other ACME-compliant CAs.

## Syntax

```tcl
::tossl::acme::dns01_challenge <domain> <token> <account_key> <provider> <api_key> ?<zone_id>?
```

- `<domain>`: Domain name for the certificate (e.g., `example.com`)
- `<token>`: ACME challenge token (provided by the ACME server)
- `<account_key>`: PEM-encoded private key for the ACME account
- `<provider>`: DNS provider ("cloudflare", "route53", "generic")
- `<api_key>`: DNS provider API key
- `<zone_id>`: DNS zone ID (optional, required for Cloudflare)

## Return Value

Returns a Tcl dict with the following fields:
- `type`: Always `dns-01`
- `token`: The challenge token
- `key_authorization`: The key authorization string
- `dns_record_name`: The DNS TXT record name to create (e.g., `_acme-challenge.example.com`)
- `dns_record_value`: The value to set for the TXT record

## Examples

### Basic DNS-01 Challenge Preparation

```tcl
set domain "example.com"
set token "challenge-token-12345"
set account_key "-----BEGIN PRIVATE KEY-----\n..."
set provider "cloudflare"
set api_key "your-cloudflare-api-key"
set zone_id "your-zone-id"

set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key $zone_id]
puts "DNS record name: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"
```

### Minimal Parameters (No Zone ID)

```tcl
set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key]
```

### Complete ACME Workflow

```tcl
# Step 1: Prepare DNS-01 challenge
set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key $zone_id]
puts "DNS record: [dict get $challenge dns_record_name]"
puts "Value: [dict get $challenge dns_record_value]"

# Step 2: Wait for DNS propagation (in real usage)
after 30000  ; # Wait 30 seconds

# Step 3: Notify ACME server (not shown here)

# Step 4: Clean up DNS record
set cleanup_result [tossl::acme::cleanup_dns $domain [dict get $challenge dns_record_name] $provider $api_key $zone_id]
puts "Cleanup: $cleanup_result"
```

### Multiple Providers

```tcl
set providers {cloudflare route53 generic}
foreach provider $providers {
    set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key]
    puts "$provider: [dict get $challenge dns_record_name] => [dict get $challenge dns_record_value]"
}
```

## Error Handling

The command will return an error in the following cases:
- **Missing arguments**: Not enough parameters provided
- **API errors**: DNS provider API communication failures
- **DNS propagation timeout**: TXT record not visible after waiting
- **Provider errors**: Unsupported or misconfigured provider

### Error Handling Example

```tcl
proc safe_dns01_challenge {domain token account_key provider api_key zone_id} {
    set rc [catch {
        set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key $zone_id]
    } err]
    if {$rc != 0} {
        return [dict create error $err]
    }
    return $challenge
}

set result [safe_dns01_challenge $domain $token $account_key $provider $api_key $zone_id]
if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Challenge prepared: $result"
}
```

## Security Considerations

- **API Key Security**: Store API keys securely, use least privilege, and rotate regularly
- **Temporary Records**: Remove DNS challenge records after validation using `::tossl::acme::cleanup_dns`
- **Input Validation**: Validate all inputs to avoid injection or misconfiguration
- **Provider Permissions**: Ensure API keys have only the permissions needed for TXT record management

## Best Practices

- Always clean up DNS challenge records after validation
- Use Let's Encrypt staging for testing to avoid rate limits
- Monitor DNS changes for unauthorized modifications
- Handle errors and retries gracefully in automation scripts

## Related Commands

- `::tossl::acme::cleanup_dns` — Remove DNS-01 challenge records
- `::tossl::acme::directory` — Get ACME server directory
- `::tossl::acme::create_account` — Create ACME account
- `::tossl::acme::create_order` — Create certificate order
- `::tossl::http::get` — HTTP client for API communication
- `::tossl::http::post` — HTTP client for API communication

## Troubleshooting

- **"Failed to create DNS record"**: Check API credentials and permissions
- **"DNS propagation timeout"**: Wait longer or check DNS provider status
- **"Provider not supported"**: Ensure provider is one of the supported types
- **"Missing required argument"**: Check command syntax and parameters

### Debugging Tips

```tcl
proc debug_dns01_challenge {domain token account_key provider api_key zone_id} {
    puts "Preparing DNS-01 challenge for $domain"
    set rc [catch {
        set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key $zone_id]
    } err]
    if {$rc != 0} {
        puts "Error: $err"
        return
    }
    dict for {k v} $challenge {
        puts "$k: $v"
    }
}
```

## Performance Notes

- DNS-01 challenge creation is fast, but DNS propagation may take time
- For high-throughput automation, parallelize challenge creation and polling
- Use provider-specific options for optimal performance 