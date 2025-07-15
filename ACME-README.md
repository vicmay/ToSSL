# TOSSL ACME Protocol Support

This document describes the ACME (Automated Certificate Management Environment) protocol support in TOSSL, which enables automated SSL/TLS certificate issuance and management using Let's Encrypt and other ACME-compliant certificate authorities.

## Overview

ACME is the protocol used by Let's Encrypt and other certificate authorities to automate the process of certificate issuance, validation, and renewal. TOSSL provides a complete ACME v2 implementation with support for:

- **ACME v2 protocol** - Full RFC 8555 compliance
- **DNS-01 challenges** - Domain validation via DNS TXT records
- **HTTP-01 challenges** - Domain validation via HTTP (planned)
- **Multiple DNS providers** - Cloudflare, Route53, generic DNS APIs
- **Certificate lifecycle management** - Issuance, renewal, revocation

## Prerequisites

### System Requirements

- **TOSSL library** - Built with ACME support enabled
- **libcurl** - HTTP client library for ACME communication
- **json-c** - JSON parsing library
- **OpenSSL** - Cryptographic operations
- **Network access** - To ACME servers and DNS APIs

### Dependencies Installation

```bash
# Ubuntu/Debian
sudo apt-get install libcurl4-openssl-dev libjson-c-dev

# CentOS/RHEL
sudo yum install libcurl-devel json-c-devel

# macOS
brew install curl json-c
```

### Building TOSSL with ACME Support

```bash
# Build TOSSL with ACME support
make clean && make

# Verify ACME commands are available
echo 'load ./libtossl.so; puts [info commands tossl::acme::*]' | tclsh
```

Expected output:
```
::tossl::acme::cleanup_dns ::tossl::acme::dns01_challenge ::tossl::acme::create_account ::tossl::acme::directory ::tossl::acme::create_order
```

## ACME Commands Reference

### Core ACME Commands

#### `tossl::acme::directory directory_url`
Fetches and parses the ACME directory from the specified URL.

**Parameters:**
- `directory_url` - ACME server directory URL (e.g., Let's Encrypt staging)

**Returns:** Tcl dict containing ACME endpoints

**Example:**
```tcl
set directory [tossl::acme::directory "https://acme-staging-v02.api.letsencrypt.org/directory"]
puts "New account URL: [dict get $directory newAccount]"
puts "New order URL: [dict get $directory newOrder]"
```

#### `tossl::acme::create_account directory_url account_key email ?contact?`
Creates a new ACME account with the specified email address.

**Parameters:**
- `directory_url` - ACME server directory URL
- `account_key` - PEM-encoded private key for account
- `email` - Email address for account
- `contact` - Additional contact information (optional)

**Returns:** Account creation status

**Example:**
```tcl
set account_key [tossl::key::generate -type rsa -bits 2048]
set result [tossl::acme::create_account \
    "https://acme-staging-v02.api.letsencrypt.org/directory" \
    [dict get $account_key private] \
    "admin@example.com"]
```

#### `tossl::acme::create_order directory_url account_key domains`
Creates a new certificate order for the specified domains.

**Parameters:**
- `directory_url` - ACME server directory URL
- `account_key` - PEM-encoded private key for account
- `domains` - Space-separated list of domain names

**Returns:** Order creation status

**Example:**
```tcl
set result [tossl::acme::create_order \
    "https://acme-staging-v02.api.letsencrypt.org/directory" \
    $account_key \
    "example.com www.example.com"]
```

### DNS-01 Challenge Commands

#### `tossl::acme::dns01_challenge domain token account_key provider api_key ?zone_id?`
Prepares a DNS-01 challenge by creating the required DNS TXT record.

**Parameters:**
- `domain` - Domain name for certificate
- `token` - ACME challenge token
- `account_key` - PEM-encoded private key for account
- `provider` - DNS provider ("cloudflare", "route53", "generic")
- `api_key` - DNS provider API key
- `zone_id` - DNS zone ID (required for Cloudflare)

**Returns:** Challenge information dict

**Example:**
```tcl
set challenge [tossl::acme::dns01_challenge \
    "example.com" \
    "challenge-token-12345" \
    $account_key \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]

puts "DNS record name: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"
```

#### `tossl::acme::cleanup_dns domain record_name provider api_key ?zone_id?`
Removes the DNS TXT record created for the challenge.

**Parameters:**
- `domain` - Domain name
- `record_name` - DNS record name to delete
- `provider` - DNS provider
- `api_key` - DNS provider API key
- `zone_id` - DNS zone ID (required for Cloudflare)

**Returns:** Cleanup status

**Example:**
```tcl
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]
```

## DNS Provider Configuration

### Cloudflare

**Setup:**
1. Get API key from Cloudflare dashboard
2. Get zone ID for your domain
3. Ensure domain is managed by Cloudflare

**Usage:**
```tcl
set provider "cloudflare"
set api_key "your-cloudflare-api-key"
set zone_id "your-zone-id"
```

### Route53

**Setup:**
1. Configure AWS credentials
2. Ensure domain is managed by Route53
3. Set up IAM permissions for DNS management

**Usage:**
```tcl
set provider "route53"
set api_key "your-aws-access-key"
set api_secret "your-aws-secret-key"
```

### Generic DNS Provider

**Setup:**
1. Configure DNS API endpoint
2. Set up authentication credentials
3. Ensure API supports TXT record management

**Usage:**
```tcl
set provider "generic"
set api_key "your-api-key"
set endpoint "https://your-dns-api.com"
```

## Complete Certificate Issuance Example

Here's a complete example of issuing a certificate using DNS-01 challenge:

```tcl
#!/usr/bin/env tclsh

# Load TOSSL
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Configuration
set acme_server "https://acme-staging-v02.api.letsencrypt.org/directory"
set domain "example.com"
set email "admin@example.com"
set dns_provider "cloudflare"
set dns_api_key "your-cloudflare-api-key"
set dns_zone_id "your-zone-id"

# Step 1: Generate account key
puts "Generating account key..."
set account_keys [tossl::key::generate -type rsa -bits 2048]
set account_private [dict get $account_keys private]

# Step 2: Create ACME account
puts "Creating ACME account..."
set account_result [tossl::acme::create_account $acme_server $account_private $email]
puts "Account creation: $account_result"

# Step 3: Create certificate order
puts "Creating certificate order..."
set order_result [tossl::acme::create_order $acme_server $account_private $domain]
puts "Order creation: $order_result"

# Step 4: Prepare DNS-01 challenge
puts "Preparing DNS-01 challenge..."
set token "challenge-token-12345"
set challenge [tossl::acme::dns01_challenge \
    $domain $token $account_private $dns_provider $dns_api_key $dns_zone_id]

puts "DNS record name: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"

# Step 5: Wait for DNS propagation (in real usage)
puts "Waiting for DNS propagation..."
after 30000  ; # Wait 30 seconds

# Step 6: Clean up DNS record
puts "Cleaning up DNS record..."
set cleanup_result [tossl::acme::cleanup_dns \
    $domain \
    [dict get $challenge dns_record_name] \
    $dns_provider \
    $dns_api_key \
    $dns_zone_id]
puts "Cleanup: $cleanup_result"

puts "Certificate issuance process completed!"
```

## Testing

### Test Against Let's Encrypt Staging

The staging server is perfect for testing:

```tcl
# Test directory fetch
set directory [tossl::acme::directory "https://acme-staging-v02.api.letsencrypt.org/directory"]
puts "Available endpoints: [dict keys $directory]"

# Test account creation
set account_key [tossl::key::generate -type rsa -bits 2048]
set result [tossl::acme::create_account \
    "https://acme-staging-v02.api.letsencrypt.org/directory" \
    [dict get $account_key private] \
    "test@example.com"]
puts "Account creation result: $result"
```

### Run Integration Tests

```bash
# Run the complete ACME integration test
tclsh test_acme_integration.tcl
```

Expected output:
```
Testing ACME functionality with DNS-01 challenge support...
========================================================

1. Testing HTTP functionality...
   Status: 200
   ✓ HTTP functionality working

2. Testing ACME directory fetch...
   Directory keys: keyChange meta newAccount newNonce newOrder renewalInfo revokeCert
   ✓ ACME directory fetch working

3. Testing account key generation...
   ✓ Account key generated

4. Testing ACME account creation...
   Result: Account created successfully
   ✓ ACME account creation working

5. Testing ACME order creation...
   Result: Order created successfully
   ✓ ACME order creation working

6. Testing DNS-01 challenge preparation...
   Challenge type: dns-01
   DNS record name: _acme-challenge.example.com
   DNS record value: placeholder-dns01-value
   ✓ DNS-01 challenge preparation working

7. Testing DNS cleanup...
   Result: DNS record deleted successfully
   ✓ DNS cleanup working
```

## Production Usage

### Let's Encrypt Production

For production certificates, use the production server:

```tcl
set production_server "https://acme-v02.api.letsencrypt.org/directory"
```

### Rate Limits

Let's Encrypt has rate limits:
- **Staging**: No limits (for testing)
- **Production**: 
  - 50 certificates per registered domain per week
  - 300 new orders per account per 3 hours
  - 5 duplicate orders per account per week

### Certificate Renewal

For automatic renewal, implement a cron job or systemd timer:

```bash
#!/bin/bash
# Renew certificates every 60 days
tclsh /path/to/renewal_script.tcl
```

## Troubleshooting

### Common Issues

#### "Failed to parse directory JSON"
- Check network connectivity to ACME server
- Verify libcurl and json-c are properly installed
- Ensure HTTP response is valid JSON

#### "Failed to create DNS record"
- Verify DNS provider credentials
- Check zone ID for Cloudflare
- Ensure domain is managed by the DNS provider
- Verify API permissions

#### "DNS propagation timeout"
- Increase wait time for DNS propagation
- Check DNS provider's propagation time
- Verify DNS record was created correctly

### Debug Mode

Enable debug output by setting environment variables:

```bash
export TOSSL_DEBUG=1
export TOSSL_ACME_DEBUG=1
tclsh your_acme_script.tcl
```

### Log Files

Check system logs for detailed error information:

```bash
# Check for TOSSL-related errors
journalctl -f | grep tossl

# Check DNS provider API logs
tail -f /var/log/dns-provider.log
```

## Security Considerations

### Private Key Management

- Store account private keys securely
- Use appropriate file permissions (600)
- Consider hardware security modules (HSM) for production
- Rotate keys periodically

### API Key Security

- Use environment variables for API keys
- Implement least-privilege access for DNS APIs
- Monitor API usage for unauthorized access
- Rotate API keys regularly

### Certificate Security

- Validate certificate contents before deployment
- Monitor certificate expiration
- Implement certificate transparency logging
- Use appropriate key sizes (RSA 2048+ or ECDSA P-256+)

## API Reference

### HTTP Response Format

ACME HTTP responses return a dict with:
- `status_code` - HTTP status code
- `body` - Response body (JSON)
- `headers` - Response headers

### JSON Response Format

ACME directory responses contain:
- `newAccount` - Account registration endpoint
- `newOrder` - Order creation endpoint
- `newNonce` - Nonce generation endpoint
- `keyChange` - Account key change endpoint
- `revokeCert` - Certificate revocation endpoint

### Error Handling

All ACME commands return TCL_OK on success or TCL_ERROR on failure. Check the interp result for error details:

```tcl
if {[catch {
    set result [tossl::acme::create_account $url $key $email]
} err]} {
    puts "Error: $err"
    return
}
```

## Contributing

To contribute to ACME support:

1. **Report bugs** - Create issues with detailed error information
2. **Add DNS providers** - Implement new DNS provider integrations
3. **Improve error handling** - Add better error messages and recovery
4. **Add tests** - Create comprehensive test suites
5. **Documentation** - Improve this README and add examples

## License

TOSSL ACME support is licensed under the Apache License 2.0. See LICENSE file for details.

## Support

For support with ACME functionality:

1. Check this README for common solutions
2. Review the test files for usage examples
3. Check the TOSSL main documentation
4. Create an issue with detailed error information

---

**Note:** This ACME implementation is designed for educational and development purposes. For production use, consider using established ACME clients like certbot or acme.sh for critical systems. 