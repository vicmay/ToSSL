# ::tossl::ocsp::create_request

Create an OCSP (Online Certificate Status Protocol) request to check certificate revocation status.

## Syntax

    tossl::ocsp::create_request <cert_pem> <issuer_pem>

- `<cert_pem>`: PEM-encoded certificate to check (required)
- `<issuer_pem>`: PEM-encoded issuer certificate (required)

## Description

Creates an OCSP request to check the revocation status of a certificate. The request contains the certificate ID derived from the certificate and its issuer, which is used by OCSP responders to determine if the certificate has been revoked.

## Output

Returns the OCSP request as binary data (Tcl byte array) suitable for sending to an OCSP responder.

## Examples

### Basic OCSP Request Creation

```tcl
# Generate CA and certificate for testing
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private_key [dict get $ca_keypair private]
set ca_cert [tossl::x509::create $ca_private_key "CN=Test CA" 3650]

set server_keypair [tossl::key::generate -type rsa -bits 2048]
set server_private_key [dict get $server_keypair private]
set server_cert [tossl::x509::create $server_private_key "CN=test.example.com" 365]

# Create OCSP request
set ocsp_request [tossl::ocsp::create_request $server_cert $ca_cert]
puts "OCSP request created: [string length $ocsp_request] bytes"

# Send to OCSP responder (example)
set response [tossl::http::post \
    -url "http://ocsp.example.com" \
    -data $ocsp_request \
    -content_type "application/ocsp-request"]
```

### OCSP Request for Self-Signed Certificate

```tcl
# Create self-signed certificate
set keypair [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $keypair private]
set cert [tossl::x509::create $private_key "CN=self.example.com" 365]

# Create OCSP request (issuer is the same as certificate)
set ocsp_request [tossl::ocsp::create_request $cert $cert]
puts "Self-signed OCSP request created: [string length $ocsp_request] bytes"
```

### OCSP Request with Different Issuer

```tcl
# Create two different CA certificates
set ca1_keypair [tossl::key::generate -type rsa -bits 2048]
set ca1_cert [tossl::x509::create [dict get $ca1_keypair private] "CN=CA1" 3650]

set ca2_keypair [tossl::key::generate -type rsa -bits 2048]
set ca2_cert [tossl::x509::create [dict get $ca2_keypair private] "CN=CA2" 3650]

# Create certificate signed by CA1
set server_keypair [tossl::key::generate -type rsa -bits 2048]
set server_cert [tossl::x509::create [dict get $server_keypair private] "CN=server.example.com" 365]

# Create OCSP request with different issuer (this is valid for testing)
set ocsp_request [tossl::ocsp::create_request $server_cert $ca2_cert]
puts "OCSP request with different issuer created: [string length $ocsp_request] bytes"
```

### Complete OCSP Workflow

```tcl
# 1. Generate CA and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_cert [tossl::x509::create [dict get $ca_keypair private] "CN=My CA" 3650]

set server_keypair [tossl::key::generate -type rsa -bits 2048]
set server_cert [tossl::x509::create [dict get $server_keypair private] "CN=server.example.com" 365]

# 2. Create OCSP request
set ocsp_request [tossl::ocsp::create_request $server_cert $ca_cert]

# 3. Send to OCSP responder (example with Let's Encrypt)
set response [tossl::http::post \
    -url "http://ocsp.int-x3.letsencrypt.org" \
    -data $ocsp_request \
    -content_type "application/ocsp-request"]

# 4. Parse the response (if available)
if {[string length $response] > 0} {
    set parsed [tossl::ocsp::parse_response $response]
    puts "Certificate status: [dict get $parsed cert_status]"
    puts "Response status: [dict get $parsed status]"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::ocsp::create_request
# Error: wrong # args: should be "tossl::ocsp::create_request cert_pem issuer_pem"

tossl::ocsp::create_request "cert"
# Error: wrong # args: should be "tossl::ocsp::create_request cert_pem issuer_pem"
```

- If the certificates are invalid or cannot be parsed, an error is returned:

```tcl
tossl::ocsp::create_request "invalid_cert" "invalid_issuer"
# Error: Failed to parse certificate
```

- If the OCSP request creation fails, an error is returned:

```tcl
# This might fail if there are memory issues or OpenSSL problems
tossl::ocsp::create_request $cert $issuer
# Error: Failed to create OCSP request
```

## Security Notes

- OCSP requests contain certificate identifiers but do not include sensitive information.
- The request is typically sent over HTTP (not HTTPS) to OCSP responders.
- OCSP requests are used to check if a certificate has been revoked by the CA.
- The certificate ID in the request is derived from the certificate's serial number, issuer name, and issuer public key.
- OCSP requests are commonly used in certificate validation workflows.
- Consider implementing OCSP stapling in TLS connections for better performance.
- The request format follows RFC 6960 (OCSP) specification.

## Protocol Details

OCSP requests contain:
- Certificate ID (derived from serial number, issuer name, and issuer public key)
- Requestor name (optional)
- Request extensions (optional)

The certificate ID is created using SHA-1 hash by default in this implementation.

## Common OCSP Responder URLs

Some common OCSP responder URLs:
- Let's Encrypt: `http://ocsp.int-x3.letsencrypt.org`
- DigiCert: `http://ocsp.digicert.com`
- GlobalSign: `http://ocsp.globalsign.com`

## Notes

- The OCSP request is returned as binary data suitable for HTTP POST requests.
- The Content-Type for OCSP requests is typically `application/ocsp-request`.
- OCSP responses are typically returned with Content-Type `application/ocsp-response`.
- The command supports any valid X.509 certificate pair, regardless of whether they are actually related.
- OCSP requests are stateless and can be cached by responders. 