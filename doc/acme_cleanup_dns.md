# ::tossl::acme::cleanup_dns

## Overview

The `::tossl::acme::cleanup_dns` command removes DNS TXT records that were created for ACME DNS-01 challenges. This command is essential for cleaning up temporary DNS records after certificate validation is complete, ensuring proper resource management and security.

## Syntax

```tcl
::tossl::acme::cleanup_dns <domain> <record_name> <provider> <api_key> ?<zone_id>?
```

- `<domain>`: Domain name (currently not used but kept for future implementation)
- `<record_name>`: DNS record name to delete (e.g., "_acme-challenge.example.com")
- `<provider>`: DNS provider ("cloudflare", "route53", "generic")
- `<api_key>`: DNS provider API key
- `<zone_id>`: DNS zone ID (optional, required for Cloudflare)

## Return Value

Returns a status message indicating whether the DNS record was successfully deleted:
- `"DNS record deleted successfully"` on success
- Error message on failure

## Examples

### Basic DNS Record Cleanup

```tcl
;# Clean up a DNS TXT record created for ACME challenge
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-cloudflare-api-key"]

if {[string match "*deleted successfully*" $result]} {
    puts "DNS record cleaned up successfully"
} else {
    puts "Cleanup failed: $result"
}
```

### Cleanup with Zone ID (Cloudflare)

```tcl
;# Clean up DNS record with zone ID for Cloudflare
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]

puts "Cleanup result: $result"
```

### Complete ACME Workflow with Cleanup

```tcl
;# Complete ACME certificate issuance workflow
set domain "example.com"
set token "challenge-token-12345"
set account_key "-----BEGIN PRIVATE KEY-----\n..."
set provider "cloudflare"
set api_key "your-cloudflare-api-key"
set zone_id "your-zone-id"

# Step 1: Create DNS-01 challenge
set challenge [tossl::acme::dns01_challenge \
    $domain $token $account_key $provider $api_key $zone_id]

puts "DNS record created: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"

# Step 2: Wait for DNS propagation (in real usage)
puts "Waiting for DNS propagation..."
after 30000  ; # Wait 30 seconds

# Step 3: Notify ACME server (not shown here)
# tossl::acme::notify_challenge $challenge_url $key_authorization

# Step 4: Clean up DNS record
puts "Cleaning up DNS record..."
set cleanup_result [tossl::acme::cleanup_dns \
    $domain \
    [dict get $challenge dns_record_name] \
    $provider \
    $api_key \
    $zone_id]

puts "Cleanup result: $cleanup_result"
```

### Multiple Domain Cleanup

```tcl
;# Clean up DNS records for multiple domains
set domains {example.com www.example.com api.example.com}
set provider "cloudflare"
set api_key "your-cloudflare-api-key"
set zone_id "your-zone-id"

foreach domain $domains {
    set record_name "_acme-challenge.$domain"
    set result [tossl::acme::cleanup_dns \
        $domain $record_name $provider $api_key $zone_id]
    
    if {[string match "*deleted successfully*" $result]} {
        puts "Cleaned up DNS record for $domain"
    } else {
        puts "Failed to clean up DNS record for $domain: $result"
    }
}
```

### Error Handling with Retry Logic

```tcl
proc cleanup_dns_with_retry {domain record_name provider api_key zone_id max_retries} {
    for {set attempt 1} {$attempt <= $max_retries} {incr attempt} {
        set cleanup_rc [catch {
            set result [tossl::acme::cleanup_dns \
                $domain $record_name $provider $api_key $zone_id]
        } cleanup_err]
        
        if {$cleanup_rc == 0 && [string match "*deleted successfully*" $result]} {
            puts "DNS cleanup successful on attempt $attempt"
            return $result
        } else {
            puts "DNS cleanup attempt $attempt failed: $cleanup_err"
            if {$attempt < $max_retries} {
                puts "Retrying in 5 seconds..."
                after 5000
            }
        }
    }
    
    error "DNS cleanup failed after $max_retries attempts"
}

;# Usage
set result [cleanup_dns_with_retry \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-api-key" \
    "your-zone-id" \
    3]
```

## DNS Provider Support

### Cloudflare

**Required Parameters:**
- `provider`: "cloudflare"
- `api_key`: Cloudflare API key
- `zone_id`: Cloudflare zone ID

**Setup:**
1. Get API key from Cloudflare dashboard
2. Get zone ID for your domain
3. Ensure domain is managed by Cloudflare

**Example:**
```tcl
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]
```

### Route53

**Required Parameters:**
- `provider`: "route53"
- `api_key`: AWS access key
- `api_secret`: AWS secret key (not currently used in cleanup)

**Setup:**
1. Configure AWS credentials
2. Ensure domain is managed by Route53
3. Set up IAM permissions for DNS management

**Example:**
```tcl
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "route53" \
    "your-aws-access-key"]
```

### Generic DNS Provider

**Required Parameters:**
- `provider`: "generic"
- `api_key`: DNS provider API key
- `endpoint`: DNS API endpoint (not currently used in cleanup)

**Setup:**
1. Configure DNS API endpoint
2. Set up authentication credentials
3. Ensure API supports TXT record management

**Example:**
```tcl
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "generic" \
    "your-api-key"]
```

## Error Handling

The command will return an error in the following cases:

- **Missing arguments**: Insufficient number of parameters
- **API errors**: DNS provider API communication failures
- **Authentication failures**: Invalid API keys or credentials
- **Record not found**: DNS record doesn't exist or has already been deleted

### Error Handling Example

```tcl
proc safe_cleanup_dns {domain record_name provider api_key zone_id} {
    if {[string length $domain] == 0 || [string length $record_name] == 0} {
        return [dict create error "Domain and record_name are required"]
    }
    
    set cleanup_rc [catch {
        set result [tossl::acme::cleanup_dns \
            $domain $record_name $provider $api_key $zone_id]
    } cleanup_err]
    
    if {$cleanup_rc != 0} {
        return [dict create error "Cleanup failed: $cleanup_err"]
    }
    
    if {[string match "*deleted successfully*" $result]} {
        return [dict create success $result]
    } else {
        return [dict create error "Unexpected result: $result"]
    }
}

;# Usage
set result [safe_cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-api-key" \
    "your-zone-id"]

if {[dict exists $result error]} {
    puts "Error: [dict get $result error]"
} else {
    puts "Success: [dict get $result success]"
}
```

## Security Considerations

### API Key Security

- **Secure storage**: Store API keys securely, not in plain text files
- **Access control**: Use API keys with minimal required permissions
- **Rotation**: Regularly rotate API keys
- **Environment variables**: Use environment variables for sensitive data

```tcl
;# Secure API key usage
set api_key [exec env | grep CLOUDFLARE_API_KEY | cut -d= -f2]
if {[string length $api_key] == 0} {
    error "CLOUDFLARE_API_KEY environment variable not set"
}

set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    $api_key \
    "your-zone-id"]
```

### DNS Record Security

- **Temporary records**: DNS records created for ACME challenges are temporary
- **Cleanup timing**: Clean up records immediately after validation
- **Record validation**: Verify record deletion was successful
- **Monitoring**: Monitor DNS changes for unauthorized modifications

### Best Practices

```tcl
proc secure_acme_cleanup {domain record_name provider api_key zone_id} {
    # Input validation
    if {![regexp {^[a-zA-Z0-9.-]+$} $domain]} {
        error "Invalid domain name: $domain"
    }
    
    if {![regexp {^_acme-challenge\.[a-zA-Z0-9.-]+$} $record_name]} {
        error "Invalid ACME challenge record name: $record_name"
    }
    
    # Perform cleanup
    set cleanup_rc [catch {
        set result [tossl::acme::cleanup_dns \
            $domain $record_name $provider $api_key $zone_id]
    } cleanup_err]
    
    if {$cleanup_rc != 0} {
        error "DNS cleanup failed: $cleanup_err"
    }
    
    # Verify cleanup was successful
    if {![string match "*deleted successfully*" $result]} {
        error "DNS cleanup verification failed: $result"
    }
    
    return $result
}
```

## Performance Notes

- **API rate limits**: Be aware of DNS provider API rate limits
- **Batch operations**: For multiple domains, consider batch cleanup operations
- **Caching**: Cache DNS provider credentials to avoid repeated lookups
- **Timeout handling**: Implement appropriate timeouts for API calls

## Related Commands

- `::tossl::acme::dns01_challenge` — Create DNS-01 challenge records
- `::tossl::acme::directory` — Get ACME server directory
- `::tossl::acme::create_account` — Create ACME account
- `::tossl::acme::create_order` — Create certificate order
- `::tossl::http::get` — HTTP client for API communication
- `::tossl::http::post` — HTTP client for API communication

## Troubleshooting

### Common Issues

- **"Failed to delete DNS record"**: Check API credentials and permissions
- **"DNS record not found"**: Record may have already been deleted
- **"Authentication failed"**: Verify API key and zone ID
- **"Rate limit exceeded"**: Wait before retrying

### Debugging Tips

```tcl
;# Enable detailed error reporting
proc debug_cleanup_dns {domain record_name provider api_key zone_id} {
    puts "Debug: Cleaning up DNS record"
    puts "  Domain: $domain"
    puts "  Record: $record_name"
    puts "  Provider: $provider"
    puts "  Zone ID: $zone_id"
    
    set cleanup_rc [catch {
        set result [tossl::acme::cleanup_dns \
            $domain $record_name $provider $api_key $zone_id]
    } cleanup_err]
    
    if {$cleanup_rc != 0} {
        puts "Error: $cleanup_err"
        return
    }
    
    puts "Result: $result"
}
```

### Testing with Staging Environment

For testing, use Let's Encrypt's staging environment:

```tcl
;# Test cleanup with staging environment
set test_domain "test.example.com"
set test_record "_acme-challenge.test.example.com"
set test_provider "cloudflare"
set test_api_key "your-test-api-key"
set test_zone_id "your-test-zone-id"

set result [tossl::acme::cleanup_dns \
    $test_domain $test_record $test_provider $test_api_key $test_zone_id]

puts "Test cleanup result: $result"
``` 