# ::tossl::ocsp::parse_response

Parse an OCSP (Online Certificate Status Protocol) response to extract certificate status information.

## Syntax

    tossl::ocsp::parse_response <ocsp_response>

- `<ocsp_response>`: OCSP response binary data (Tcl byte array)

## Description

Parses an OCSP response to extract certificate revocation status information. The response contains the status of the certificate that was queried in the OCSP request, including whether the certificate is good, revoked, or unknown.

## Output

Returns a Tcl list with key-value pairs containing:
- `status`: Response status (`successful`, `malformed_request`, `internal_error`, `try_later`, `sig_required`, `unauthorized`, or `unknown`)
- `cert_status`: Certificate status (`good`, `revoked`, or `unknown`) - only present if response status is `successful`

## Examples

### Basic OCSP Response Parsing

```tcl
# Read OCSP response from file
set f [open "ocsp_response.bin" rb]
set ocsp_response [read $f]
close $f

# Parse the OCSP response
set parsed [tossl::ocsp::parse_response $ocsp_response]

# Extract status information
set status_found 0
set cert_status_found 0
set status_value ""
set cert_status_value ""

for {set i 0} {$i < [llength $parsed]} {incr i 2} {
    set key [lindex $parsed $i]
    set value [lindex $parsed [expr {$i + 1}]]
    
    if {$key eq "status"} {
        set status_found 1
        set status_value $value
    } elseif {$key eq "cert_status"} {
        set cert_status_found 1
        set cert_status_value $value
    }
}

if {$status_found} {
    puts "Response status: $status_value"
    
    if {$status_value eq "successful" && $cert_status_found} {
        puts "Certificate status: $cert_status_value"
        
        switch $cert_status_value {
            "good" {
                puts "Certificate is valid and not revoked"
            }
            "revoked" {
                puts "Certificate has been revoked"
            }
            "unknown" {
                puts "Certificate status is unknown"
            }
        }
    }
}
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

# 3. Send to OCSP responder (example)
set response [tossl::http::post \
    -url "http://ocsp.example.com" \
    -data $ocsp_request \
    -content_type "application/ocsp-request"]

# 4. Parse the response
if {[string length $response] > 0} {
    set parsed [tossl::ocsp::parse_response $response]
    
    # Extract status
    set status_found 0
    set cert_status_found 0
    set status_value ""
    set cert_status_value ""
    
    for {set i 0} {$i < [llength $parsed]} {incr i 2} {
        set key [lindex $parsed $i]
        set value [lindex $parsed [expr {$i + 1}]]
        
        if {$key eq "status"} {
            set status_found 1
            set status_value $value
        } elseif {$key eq "cert_status"} {
            set cert_status_found 1
            set cert_status_value $value
        }
    }
    
    puts "OCSP Response Status: $status_value"
    if {$cert_status_found} {
        puts "Certificate Status: $cert_status_value"
    }
}
```

### Error Handling

```tcl
# Handle missing response
set rc [catch {tossl::ocsp::parse_response} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle invalid response
set rc [catch {tossl::ocsp::parse_response "invalid_data"} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle empty response
set rc [catch {tossl::ocsp::parse_response ""} result]
if {$rc != 0} {
    puts "Error: $result"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::ocsp::parse_response
# Error: wrong # args: should be "tossl::ocsp::parse_response ocsp_response"
```

- If the OCSP response is invalid or corrupted, an error is returned:

```tcl
tossl::ocsp::parse_response "invalid_data"
# Error: Failed to parse OCSP response
```

- If the response cannot be parsed as a basic response, an error is returned:

```tcl
tossl::ocsp::parse_response $response
# Error: Failed to get basic response
```

## Response Status Values

The response status indicates the overall status of the OCSP response:

- `successful`: The response contains valid certificate status information
- `malformed_request`: The OCSP request was malformed
- `internal_error`: The OCSP responder encountered an internal error
- `try_later`: The OCSP responder is temporarily unavailable
- `sig_required`: The OCSP request requires a signature
- `unauthorized`: The OCSP responder is not authorized to provide status for the requested certificate
- `unknown`: Unknown response status

## Certificate Status Values

When the response status is `successful`, the certificate status indicates the revocation status:

- `good`: The certificate is valid and not revoked
- `revoked`: The certificate has been revoked
- `unknown`: The certificate status is unknown to the OCSP responder

## Security Notes

- OCSP responses are typically signed by the CA or OCSP responder.
- The response contains certificate status information but no sensitive data.
- OCSP responses are commonly used in certificate validation workflows.
- The response format follows RFC 6960 (OCSP) specification.
- Consider implementing OCSP stapling in TLS connections for better performance.
- Always verify the signature on OCSP responses in production environments.
- OCSP responses may be cached by responders and clients.

## Protocol Details

OCSP responses contain:
- Response status (overall response status)
- Certificate status (if response is successful)
- This update time (when the status was last updated)
- Next update time (when the status will be updated next)
- Response extensions (optional)

## Notes

- The command returns a list with key-value pairs rather than a dict for compatibility with the underlying implementation.
- The OCSP response should be binary data received from an OCSP responder.
- The Content-Type for OCSP responses is typically `application/ocsp-response`.
- The command supports standard OCSP responses as defined in RFC 6960.
- OCSP responses are stateless and can be cached by clients and responders. 