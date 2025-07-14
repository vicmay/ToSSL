# ACME Certificate Requests with TOSSL

This directory contains tools for requesting free SSL/TLS certificates from Let's Encrypt and other ACME-compliant certificate authorities using the TOSSL library.

## What is ACME?

ACME (Automated Certificate Management Environment) is a protocol that allows automated certificate issuance and renewal. Let's Encrypt uses this protocol to provide free SSL/TLS certificates.

## Files Overview

- **`acme_client.tcl`** - Full ACME client implementation (work in progress)
- **`acme_challenge_server.tcl`** - HTTP server for serving ACME challenges
- **`acme_example.tcl`** - Demonstration of the ACME workflow
- **`ACME_README.md`** - This documentation

## Prerequisites

1. **TOSSL Library**: Make sure TOSSL is built and available
2. **Tcl HTTP Package**: Available in most Tcl installations
3. **Domain Control**: You must control the domain(s) you want certificates for
4. **Public Web Server**: Your domain must be accessible via HTTP on port 80

## Quick Start

### 1. Run the ACME Workflow Demonstration

```bash
# Demonstrate the ACME workflow (doesn't make actual requests)
tclsh acme_example.tcl "example.com www.example.com" user@example.com
```

This will show you the step-by-step process of requesting a certificate.

### 2. Start the Challenge Server

```bash
# Start on port 80 (requires root privileges)
sudo tclsh acme_challenge_server.tcl start 80

# Or start on a non-privileged port for testing
tclsh acme_challenge_server.tcl start 8080
```

### 3. Interactive Challenge Server

```bash
# Start interactive mode
tclsh acme_challenge_server.tcl interactive
```

In interactive mode, you can:
- `set <token> <response>` - Set a challenge response
- `remove <token>` - Remove a challenge response
- `list` - List all active challenges
- `start ?port?` - Start the server
- `stop` - Stop the server
- `quit` - Exit

## ACME Workflow Overview

The ACME protocol follows this general workflow:

1. **Generate Account Key**: Create a key pair for your ACME account
2. **Create Account**: Register with the ACME server
3. **Create Order**: Request a certificate for specific domains
4. **Domain Validation**: Prove you control the domains (HTTP-01 challenge)
5. **Generate Certificate Key**: Create the key pair for the certificate
6. **Create CSR**: Generate a Certificate Signing Request
7. **Finalize Order**: Submit the CSR to the ACME server
8. **Download Certificate**: Retrieve the issued certificate

## HTTP-01 Challenge

The HTTP-01 challenge is the most common validation method:

1. ACME server provides a token and expects a specific response
2. You serve the response at: `http://yourdomain/.well-known/acme-challenge/<token>`
3. ACME server verifies the response matches expectations
4. If valid, you can proceed with certificate issuance

### Example Challenge

```
Token: abc123
Expected Response: abc123.def456
URL: http://example.com/.well-known/acme-challenge/abc123
Response Content: abc123.def456
```

## Using TOSSL for ACME

The TOSSL library provides all the cryptographic functions needed for ACME:

### Key Generation
```tcl
# Generate account key
set account_keys [tossl::key::generate -type rsa -bits 2048]
set account_private [dict get $account_keys private]

# Generate certificate key
set cert_keys [tossl::key::generate -type rsa -bits 2048]
set cert_private [dict get $cert_keys private]
```

### Signing and Verification
```tcl
# Sign data for JWS (JSON Web Signature)
set signature [tossl::rsa::sign -privkey $private_key -alg sha256 $data]

# Verify signatures
set valid [tossl::rsa::verify -pubkey $public_key -alg sha256 $data $signature]
```

### Certificate Operations
```tcl
# Create self-signed certificate (for testing)
set cert [tossl::x509::create -subject "example.com" -issuer "example.com" \
    -pubkey $public_key -privkey $private_key -days 365]

# Parse certificate
set cert_info [tossl::x509::parse $cert]
puts "Subject: [dict get $cert_info subject]"
```

### Encoding/Decoding
```tcl
# Base64URL encoding (required for ACME)
set b64url [string map {+ - / _ = ""} [tossl::base64::encode $data]]

# Base64URL decoding
set data [tossl::base64::decode [string map {- + _ /} $b64url]]
```

## Implementation Status

### Completed
- ✅ Key generation (RSA, DSA, EC)
- ✅ Digital signatures (RSA, DSA, EC)
- ✅ Certificate creation and parsing
- ✅ Base64 encoding/decoding
- ✅ HTTP client capabilities
- ✅ Challenge server implementation

### Work in Progress
- 🔄 JWS (JSON Web Signature) implementation
- 🔄 CSR (Certificate Signing Request) generation
- 🔄 Full ACME client implementation
- 🔄 Error handling and retry logic

### Planned
- 📋 DNS-01 challenge support
- 📋 Certificate renewal automation
- 📋 Multiple CA support
- 📋 Certificate chain validation

## Security Considerations

1. **Account Key Security**: Your ACME account key is critical - keep it secure
2. **Certificate Key Security**: Certificate private keys should be protected
3. **Challenge Response**: Only serve challenge responses temporarily
4. **HTTPS Only**: Once you have a certificate, redirect HTTP to HTTPS

## Testing

### Test with Let's Encrypt Staging

For testing, use Let's Encrypt's staging environment:
- URL: `https://acme-staging-v02.api.letsencrypt.org/directory`
- Certificates are not trusted by browsers
- No rate limits
- Perfect for development and testing

### Local Testing

1. Set up a local web server
2. Use the challenge server on port 8080
3. Configure your web server to proxy ACME challenges
4. Test the workflow locally before going live

## Troubleshooting

### Common Issues

1. **Permission Denied**: Port 80 requires root privileges
   ```bash
   sudo tclsh acme_challenge_server.tcl start 80
   ```

2. **Domain Not Accessible**: Ensure your domain resolves and is accessible
   ```bash
   curl http://yourdomain.com/.well-known/acme-challenge/test
   ```

3. **Challenge Validation Fails**: Check that the challenge response is correct
   - Verify the token matches
   - Ensure the response is served exactly as expected
   - Check for extra whitespace or encoding issues

4. **Rate Limits**: Let's Encrypt has rate limits
   - Production: 50 certificates per registered domain per week
   - Staging: No limits (use for testing)

### Debug Mode

Enable debug output by setting the `DEBUG` environment variable:
```bash
export DEBUG=1
tclsh acme_example.tcl "example.com" user@example.com
```

## Integration with Web Servers

### Apache Configuration
```apache
# Proxy ACME challenges to the challenge server
ProxyPass /.well-known/acme-challenge/ http://localhost:8080/.well-known/acme-challenge/
ProxyPassReverse /.well-known/acme-challenge/ http://localhost:8080/.well-known/acme-challenge/
```

### Nginx Configuration
```nginx
# Proxy ACME challenges to the challenge server
location /.well-known/acme-challenge/ {
    proxy_pass http://localhost:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Next Steps

1. **Complete JWS Implementation**: Add proper JSON Web Signature support
2. **CSR Generation**: Implement Certificate Signing Request creation
3. **Full ACME Client**: Complete the full ACME client implementation
4. **Automation**: Add automatic certificate renewal
5. **DNS Challenges**: Support DNS-01 challenges for wildcard certificates

## Resources

- [RFC 8555 - ACME Protocol](https://tools.ietf.org/html/rfc8555)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [ACME Client Implementations](https://letsencrypt.org/docs/client-options/)
- [TOSSL Documentation](README.md)

## License

This ACME implementation is part of the TOSSL project and is licensed under the Apache License, Version 2.0. 