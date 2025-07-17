# ::tossl::pkcs12::parse

Parse a PKCS#12 (PFX) bundle and extract certificate, private key, and CA chain.

## Syntax

    tossl::pkcs12::parse <pkcs12_data> <password>

- `<pkcs12_data>`: PKCS#12 binary data (Tcl byte array)
- `<password>`: Password used to protect the PKCS#12 bundle

## Description

Parses a PKCS#12 (PFX) bundle and extracts the contained certificate, private key, and optionally CA certificate chain. The bundle must be decrypted using the correct password.

## Output

Returns a Tcl list with key-value pairs containing:
- `certificate`: PEM-encoded certificate
- `private_key`: PEM-encoded private key
- `ca_certificates`: List of PEM-encoded CA certificates (if present)

## Examples

### Basic PKCS#12 Parsing

```tcl
# Read PKCS#12 file
set f [open "certificate.p12" rb]
set p12_data [read $f]
close $f

# Parse the PKCS#12 bundle
set parsed [tossl::pkcs12::parse $p12_data "my_password"]

# Extract certificate and private key
set cert_found 0
set key_found 0
set cert_value ""
set key_value ""

for {set i 0} {$i < [llength $parsed]} {incr i 2} {
    set key [lindex $parsed $i]
    set value [lindex $parsed [expr {$i + 1}]]
    
    if {$key eq "certificate"} {
        set cert_found 1
        set cert_value $value
    } elseif {$key eq "private_key"} {
        set key_found 1
        set key_value $value
    }
}

if {$cert_found} {
    puts "Certificate extracted successfully"
    # Write certificate to file
    set f [open "extracted_cert.pem" w]
    puts $f $cert_value
    close $f
}

if {$key_found} {
    puts "Private key extracted successfully"
    # Write private key to file
    set f [open "extracted_key.pem" w]
    puts $f $key_value
    close $f
}
```

### Round-trip Verification

```tcl
# Generate test certificate and key
set keypair [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $keypair private]
set cert [tossl::x509::create $private_key "CN=example.com" 365]

# Create PKCS#12 bundle
set password "secure_password"
set p12_data [tossl::pkcs12::create -cert $cert -key $private_key -password $password]

# Parse it back
set parsed [tossl::pkcs12::parse $p12_data $password]

# Verify round-trip
set cert_found 0
set key_found 0
set cert_value ""
set key_value ""

for {set i 0} {$i < [llength $parsed]} {incr i 2} {
    set key [lindex $parsed $i]
    set value [lindex $parsed [expr {$i + 1}]]
    
    if {$key eq "certificate"} {
        set cert_found 1
        set cert_value $value
    } elseif {$key eq "private_key"} {
        set key_found 1
        set key_value $value
    }
}

if {$cert_found && [string trim $cert] eq [string trim $cert_value]} {
    puts "Certificate round-trip: OK"
} else {
    puts "Certificate round-trip: FAILED"
}

if {$key_found && [string trim $private_key] eq [string trim $key_value]} {
    puts "Private key round-trip: OK"
} else {
    puts "Private key round-trip: FAILED"
}
```

### Error Handling

```tcl
# Handle missing password
set rc [catch {tossl::pkcs12::parse $p12_data} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle wrong password
set rc [catch {tossl::pkcs12::parse $p12_data "wrong_password"} result]
if {$rc != 0} {
    puts "Error: $result"
}

# Handle invalid PKCS#12 data
set rc [catch {tossl::pkcs12::parse "invalid_data" "password"} result]
if {$rc != 0} {
    puts "Error: $result"
}
```

## Error Handling

- If the PKCS#12 data is invalid or corrupted, an error is returned:

```tcl
tossl::pkcs12::parse "invalid_data" "password"
# Error: Failed to parse PKCS12
```

- If the password is incorrect, an error is returned:

```tcl
tossl::pkcs12::parse $p12_data "wrong_password"
# Error: Failed to parse PKCS12 contents
```

- If required arguments are missing, an error is returned:

```tcl
tossl::pkcs12::parse $p12_data
# Error: wrong # args: should be "tossl::pkcs12::parse pkcs12_data password"
```

## Security Notes

- The password is required and must match the one used to create the PKCS#12 bundle.
- Private keys extracted from PKCS#12 bundles should be handled securely.
- Never log or display private key material.
- PKCS#12 bundles are commonly used for importing certificates into web servers, email clients, and other applications.
- The parsed data is returned as PEM-encoded strings, which can be written to files or used directly.
- Consider using hardware security modules (HSMs) for production environments.

## File Format

PKCS#12 bundles are typically saved with the following file extensions:
- `.p12` - Most common extension
- `.pfx` - Alternative extension (Microsoft)

## Compatibility

PKCS#12 bundles parsed with this command are compatible with:
- Web servers (Apache, Nginx, IIS)
- Email clients (Outlook, Thunderbird)
- Java applications (keytool)
- Windows Certificate Store
- macOS Keychain
- Linux certificate stores

## Notes

- The command returns a list with key-value pairs rather than a dict for compatibility with the underlying implementation.
- Certificate and private key data is returned in PEM format.
- CA certificates (if present) are returned as a list of PEM-encoded certificates.
- The command supports standard PKCS#12 bundles created by OpenSSL and other tools. 