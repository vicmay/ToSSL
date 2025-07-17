# ::tossl::crl::parse

## Overview

The `::tossl::crl::parse` command parses a PEM-encoded Certificate Revocation List (CRL) and extracts key information such as version, issuer, update times, and the number of revoked certificates. This is useful for auditing, monitoring, and validating CRLs in PKI environments.

## Syntax

```tcl
::tossl::crl::parse <crl_pem>
```

- `<crl_pem>`: The PEM-encoded CRL string to parse.

## Returns

A Tcl dict (key-value pairs) with the following fields:
- `version`: CRL version (integer)
- `issuer`: Issuer distinguished name (string)
- `last_update`: Last update time (string)
- `next_update`: Next update time (string)
- `num_revoked`: Number of revoked certificates (integer)

## Examples

### Basic Usage

```tcl
# Generate CA key and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keypair private]
set ca_cert [tossl::x509::create $ca_private "CN=Test CA" 365]

# Create a CRL
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]

# Parse the CRL
set info [tossl::crl::parse $crl]
puts "CRL Version: [dict get $info version]"
puts "Issuer: [dict get $info issuer]"
puts "Last Update: [dict get $info last_update]"
puts "Next Update: [dict get $info next_update]"
puts "Number of Revoked Certs: [dict get $info num_revoked]"
```

### Error Handling

```tcl
# Parsing an invalid CRL
if {[catch {tossl::crl::parse "not a crl"} err]} {
    puts "Error: $err"
}

# Parsing with wrong number of arguments
if {[catch {tossl::crl::parse} err]} {
    puts "Error: $err"
}
```

## Error Handling

- Returns an error if the CRL cannot be parsed (invalid format, empty string, etc.).
- Returns an error if the wrong number of arguments is provided.

## Security Considerations

- Always validate CRLs before trusting their contents.
- Ensure CRLs are obtained from trusted sources.
- Use in conjunction with `::tossl::crl::create` and certificate validation commands for full PKI workflows.

## Best Practices

- Check the `issuer` field to ensure the CRL is from the expected CA.
- Monitor `last_update` and `next_update` to ensure CRLs are current.
- Use `num_revoked` to audit certificate revocation activity.

## Related Commands

- `::tossl::crl::create` — Create a new CRL
- `::tossl::x509::parse` — Parse X.509 certificates
- `::tossl::key::generate` — Generate cryptographic key pairs

## Standards Compliance

- RFC 5280 — X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

## Troubleshooting

- **Error: Failed to parse CRL**: Ensure the input is a valid PEM-encoded CRL.
- **Missing fields**: Only standard fields are extracted; extensions and revoked certificate details are not currently parsed. 