# ::tossl::pkcs12::create

Create a PKCS#12 (PFX) bundle from certificate, private key, and optional CA chain.

## Syntax

    tossl::pkcs12::create -cert <cert> -key <key> -password <password> ?-name <friendly_name>?

- `-cert <cert>`: PEM-encoded certificate (required)
- `-key <key>`: PEM-encoded private key (required)
- `-password <password>`: Password to protect the PKCS#12 bundle (required)
- `-name <friendly_name>`: Friendly name for the PKCS#12 bundle (optional, default: "TOSSL PKCS#12")

## Description

Creates a PKCS#12 (PFX) bundle containing a certificate and private key. The bundle is encrypted with the provided password and returned as binary data suitable for writing to a file.

## Output

Returns the PKCS#12 bundle as binary data (Tcl byte array).

## Examples

### Basic PKCS#12 Creation

```tcl
# Generate a key pair
set keypair [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $keypair private]
set public_key [dict get $keypair public]

# Create a self-signed certificate
set cert [tossl::x509::create \
    -subject "CN=example.com" \
    -issuer "CN=example.com" \
    -pubkey $public_key \
    -privkey $private_key \
    -days 365]

# Create PKCS#12 bundle
set password "my_secure_password"
set p12_data [tossl::pkcs12::create \
    -cert $cert \
    -key $private_key \
    -password $password]

# Write to file
set f [open "certificate.p12" wb]
puts -nonewline $f $p12_data
close $f
puts "PKCS#12 bundle created successfully"
```

### PKCS#12 with Custom Friendly Name

```tcl
# Create PKCS#12 with custom friendly name
set p12_data [tossl::pkcs12::create \
    -cert $cert \
    -key $private_key \
    -password "secure_password" \
    -name "My Application Certificate"]

# Write to file
set f [open "my_app_cert.p12" wb]
puts -nonewline $f $p12_data
close $f
puts "PKCS#12 bundle with custom name created successfully"
```

### Round-trip Verification

```tcl
# Create PKCS#12 bundle
set p12_data [tossl::pkcs12::create \
    -cert $cert \
    -key $private_key \
    -password "test_password"]

# Parse it back
set parsed [tossl::pkcs12::parse $p12_data]

# Verify the data matches
if {[dict get $parsed cert] eq $cert} {
    puts "Certificate round-trip: OK"
} else {
    puts "Certificate round-trip: FAILED"
}

if {[dict get $parsed key] eq $private_key} {
    puts "Private key round-trip: OK"
} else {
    puts "Private key round-trip: FAILED"
}
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::pkcs12::create -cert $cert
# Error: Certificate, key, and password are required
```

- If the certificate or private key is invalid PEM, an error is returned:

```tcl
tossl::pkcs12::create -cert "invalid" -key "invalid" -password "test"
# Error: Failed to parse certificate
```

- If the PKCS#12 creation fails, an error is returned:

```tcl
# This might fail if the certificate and key don't match
tossl::pkcs12::create -cert $cert1 -key $key2 -password "test"
# Error: Failed to create PKCS12
```

## Security Notes

- Use a strong, random password to protect the PKCS#12 bundle.
- The private key should be kept secure and never exposed in logs or error messages.
- PKCS#12 bundles are commonly used for importing certificates into web servers, email clients, and other applications.
- The friendly name is optional and defaults to "TOSSL PKCS#12".
- Store the PKCS#12 file securely and limit access to authorized users only.
- Consider using hardware security modules (HSMs) for production environments.

## File Format

PKCS#12 bundles are typically saved with the following file extensions:
- `.p12` - Most common extension
- `.pfx` - Alternative extension (Microsoft)
- `.pem` - When encoded in PEM format (less common)

## Compatibility

PKCS#12 bundles created with this command are compatible with:
- Web servers (Apache, Nginx, IIS)
- Email clients (Outlook, Thunderbird)
- Java applications (keytool)
- OpenSSL command-line tools
- Most modern browsers and operating systems

## Implementation Notes

- The command uses OpenSSL's PKCS12_create function with default encryption settings.
- The bundle is encrypted using the provided password.
- The friendly name is set to "TOSSL PKCS#12" by default.
- The output is in DER format (binary) suitable for direct file writing.
- The friendly name is used to identify the certificate in applications that support it. 