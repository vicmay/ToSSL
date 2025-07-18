# tossl::ssl::verify_peer

## Synopsis

```tcl
tossl::ssl::verify_peer -conn connection_handle
```

## Description

The `tossl::ssl::verify_peer` command verifies the peer certificate of an established SSL/TLS connection. It returns the verification result code and description from OpenSSL's certificate verification process.

This command is used to check whether the peer's certificate chain is valid according to the verification settings that were configured when the SSL context was created.

## Parameters

- **-conn** `connection_handle` - The SSL connection handle returned by `tossl::ssl::connect` or `tossl::ssl::accept`

## Return Value

Returns a string in the format `"code:description"` where:
- `code` is a numeric verification result code from OpenSSL
- `description` is a human-readable description of the verification result

Common verification result codes include:
- `0:ok` - Certificate verification succeeded
- `2:unable to get issuer certificate` - The issuer certificate could not be found
- `9:certificate is not yet valid` - The certificate is not yet valid (notBefore date is in the future)
- `10:certificate has expired` - The certificate has expired (notAfter date is in the past)
- `18:self signed certificate` - The certificate is self-signed
- `19:self signed certificate in certificate chain` - A self-signed certificate was found in the certificate chain
- `20:unable to get local issuer certificate` - The issuer certificate of a locally looked up certificate could not be found
- `21:unable to verify the first certificate` - No signatures could be verified because the chain contains only one certificate and it is not self-signed

## Examples

### Basic Certificate Verification

```tcl
# Create SSL context with peer verification
set ctx [tossl::ssl::context create -verify peer -ca /path/to/ca-bundle.pem]

# Connect to a server
set conn [tossl::ssl::connect -ctx $ctx -host example.com -port 443]

# Verify the peer certificate
set result [tossl::ssl::verify_peer -conn $conn]
puts "Verification result: $result"

# Parse the result
set parts [split $result ":"]
set code [lindex $parts 0]
set message [join [lrange $parts 1 end] ":"]

if {$code == 0} {
    puts "Certificate verification successful"
} else {
    puts "Certificate verification failed: $message"
}

# Clean up
tossl::ssl::close -conn $conn
```

### Handling Different Verification Results

```tcl
set ctx [tossl::ssl::context create -verify peer]
set conn [tossl::ssl::connect -ctx $ctx -host test.example.com -port 443]

set result [tossl::ssl::verify_peer -conn $conn]
set code [lindex [split $result ":"] 0]

switch $code {
    0 {
        puts "Certificate is valid"
    }
    18 {
        puts "Warning: Self-signed certificate detected"
        # Decide whether to proceed or not
    }
    10 {
        puts "Error: Certificate has expired"
        # Handle expired certificate
    }
    default {
        puts "Certificate verification failed with code $code"
        puts "Full result: $result"
    }
}

tossl::ssl::close -conn $conn
```

### Server Certificate Validation

```tcl
proc validate_server_certificate {hostname port} {
    # Create context with peer verification enabled
    set ctx [tossl::ssl::context create -verify peer]
    
    # Load system CA certificates (platform-specific)
    # On Linux: -ca /etc/ssl/certs/ca-certificates.crt
    # On macOS: -ca /System/Library/OpenSSL/certs/cert.pem
    
    if {[catch {
        set conn [tossl::ssl::connect -ctx $ctx -host $hostname -port $port -sni $hostname]
        set verify_result [tossl::ssl::verify_peer -conn $conn]
        tossl::ssl::close -conn $conn
        
        set code [lindex [split $verify_result ":"] 0]
        return [list $code $verify_result]
    } error]} {
        return [list -1 "Connection failed: $error"]
    }
}

# Test certificate validation
set result [validate_server_certificate "google.com" 443]
set code [lindex $result 0]
set message [lindex $result 1]

if {$code == 0} {
    puts "google.com certificate is valid"
} else {
    puts "google.com certificate validation failed: $message"
}
```

## Error Conditions

The command will return a Tcl error in the following cases:

1. **Wrong number of arguments** - If called without the required `-conn` parameter
2. **Invalid connection handle** - If the specified connection handle does not exist
3. **Connection not found** - If the connection handle is not in the active connections list

## Notes

- The verification result depends on the verification mode set when creating the SSL context:
  - `SSL_VERIFY_NONE` - No verification is performed
  - `SSL_VERIFY_PEER` - Verify the peer certificate if present
  - `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` - Require and verify peer certificate

- Certificate verification is performed during the SSL handshake, but this command allows you to check the result after the connection is established

- The verification result is cached from the handshake, so calling this command multiple times on the same connection will return the same result

- For client connections, this verifies the server's certificate
- For server connections (from `tossl::ssl::accept`), this verifies the client's certificate (if client certificates are required)

## Testing

The test suite for this command includes:
- Parameter validation tests
- Error handling for invalid connections
- SSL context configuration testing
- Optional network connectivity tests (enabled with `TOSSL_TEST_NETWORK=1`)

To run tests with network connectivity:
```bash
TOSSL_TEST_NETWORK=1 tclsh tests/test_ssl_verify_peer.tcl
```

## See Also

- [`tossl::ssl::connect`](ssl_connect.md) - Establish SSL client connection
- [`tossl::ssl::accept`](ssl_accept.md) - Accept SSL server connection  
- [`tossl::ssl::context`](ssl_context.md) - Create and configure SSL context
- [`tossl::ssl::close`](ssl_close.md) - Close SSL connection
- [`tossl::x509::verify`](x509_verify.md) - Verify X.509 certificates directly
