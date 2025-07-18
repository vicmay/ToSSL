# ::tossl::pkcs7::info

## Overview

The `::tossl::pkcs7::info` command extracts and returns structural information about a PKCS#7 (CMS) data structure. This command is useful for analyzing PKCS#7 messages without performing cryptographic operations, allowing you to inspect the type, signers, recipients, and encryption algorithms used in the structure.

PKCS#7 (Public-Key Cryptography Standards #7) is a standard for cryptographic message syntax that supports digital signatures, encryption, and certificate management. The info command provides a safe way to examine PKCS#7 structures without requiring access to private keys or performing verification.

## Syntax

```tcl
::tossl::pkcs7::info pkcs7_data
```

## Parameters

- **pkcs7_data** (required): The PKCS#7 data structure to analyze. This can be:
  - PEM-encoded PKCS#7 data (default)
  - DER-encoded PKCS#7 data (binary)

## Returns

Returns a Tcl dictionary containing information about the PKCS#7 structure. The dictionary may contain the following keys depending on the PKCS#7 type:

### Common Fields
- **type**: The PKCS#7 content type (e.g., "pkcs7-signedData", "pkcs7-envelopedData")

### For Signed Data (pkcs7-signedData)
- **num_signers**: Number of signers in the PKCS#7 structure

### For Encrypted Data (pkcs7-envelopedData)
- **num_recipients**: Number of recipients in the PKCS#7 structure
- **cipher**: The encryption algorithm used (e.g., "aes-256-cbc", "aes-128-cbc")

## Examples

### Basic Usage

```tcl
# Analyze a PKCS#7 signature
set signature [tossl::pkcs7::sign -cert $cert -key $key "Hello, World!"]
set info [tossl::pkcs7::info $signature]
puts "Type: [dict get $info type]"
puts "Signers: [dict get $info num_signers]"

# Analyze an encrypted PKCS#7 message
set encrypted [tossl::pkcs7::encrypt -cert $cert "Secret message"]
set info [tossl::pkcs7::info $encrypted]
puts "Type: [dict get $info type]"
puts "Recipients: [dict get $info num_recipients]"
puts "Cipher: [dict get $info cipher]"
```

### Analyzing Different PKCS#7 Types

```tcl
# Create test certificate and key
set cert [tossl::x509::create -subject "/CN=Test Cert" -days 365]
set key [tossl::key::generate -type rsa -bits 2048]

# Analyze signed data
set data "Important document content"
set signed [tossl::pkcs7::sign -cert $cert -key $key $data]
set signed_info [tossl::pkcs7::info $signed]

if {[dict get $signed_info type] eq "pkcs7-signedData"} {
    puts "This is a signed PKCS#7 message"
    puts "Number of signers: [dict get $signed_info num_signers]"
}

# Analyze encrypted data
set encrypted [tossl::pkcs7::encrypt -cert $cert $data]
set encrypted_info [tossl::pkcs7::info $encrypted]

if {[dict get $encrypted_info type] eq "pkcs7-envelopedData"} {
    puts "This is an encrypted PKCS#7 message"
    puts "Number of recipients: [dict get $encrypted_info num_recipients]"
    puts "Encryption algorithm: [dict get $encrypted_info cipher]"
}
```

### Multiple Recipients Analysis

```tcl
# Create multiple certificates
set cert1 [tossl::x509::create -subject "/CN=Recipient 1" -days 365]
set cert2 [tossl::x509::create -subject "/CN=Recipient 2" -days 365]
set cert3 [tossl::x509::create -subject "/CN=Recipient 3" -days 365]

# Encrypt for multiple recipients
set data "Confidential message for multiple recipients"
set multi_encrypted [tossl::pkcs7::encrypt -cert $cert1 -cert $cert2 -cert $cert3 $data]

# Analyze the structure
set info [tossl::pkcs7::info $multi_encrypted]
puts "Message type: [dict get $info type]"
puts "Number of recipients: [dict get $info num_recipients]"
puts "Encryption algorithm: [dict get $info cipher]"
```

### Error Handling

```tcl
# Handle invalid PKCS#7 data
set result [catch {
    set info [tossl::pkcs7::info "invalid data"]
} error_msg]

if {$result != 0} {
    puts "Error analyzing PKCS#7: $error_msg"
} else {
    puts "PKCS#7 analysis successful"
}

# Handle empty data
set result [catch {
    set info [tossl::pkcs7::info ""]
} error_msg]

if {$result != 0} {
    puts "Error with empty data: $error_msg"
}
```

### Performance Testing

```tcl
# Test performance with large PKCS#7 structures
set large_data [string repeat "A" 10000]
set large_signed [tossl::pkcs7::sign -cert $cert -key $key $large_data]

set start_time [clock milliseconds]
for {set i 0} {$i < 100} {incr i} {
    set info [tossl::pkcs7::info $large_signed]
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "Analyzed 100 PKCS#7 structures in ${duration}ms"
puts "Average time per analysis: [expr {$duration / 100.0}]ms"
```

## Error Handling

The command will return an error in the following cases:

- **Invalid PKCS#7 data**: The input data is not a valid PKCS#7 structure
- **Empty data**: The input is empty or null
- **Corrupted data**: The PKCS#7 structure is corrupted or incomplete
- **Unsupported format**: The PKCS#7 format is not supported

### Common Error Messages

- `"Failed to parse PKCS7"`: The input data could not be parsed as a valid PKCS#7 structure
- `"wrong # args"`: Incorrect number of arguments provided

## Security Considerations

### Safe Analysis
The `::tossl::pkcs7::info` command is designed to be safe for analyzing PKCS#7 structures without performing cryptographic operations. It only extracts metadata and does not:
- Verify signatures
- Decrypt data
- Access private keys
- Execute any embedded content

### Information Disclosure
Be aware that the info command reveals structural information about PKCS#7 messages, including:
- The type of PKCS#7 structure
- Number of signers or recipients
- Encryption algorithms used

This information could potentially be used for fingerprinting or reconnaissance purposes.

### Input Validation
Always validate the source of PKCS#7 data before analysis, especially when dealing with data from untrusted sources. While the command itself is safe, the input data should be from a trusted source.

## Best Practices

### 1. Validate Input Sources
```tcl
# Only analyze PKCS#7 data from trusted sources
if {[is_trusted_source $pkcs7_data]} {
    set info [tossl::pkcs7::info $pkcs7_data]
} else {
    puts "Warning: Analyzing untrusted PKCS#7 data"
}
```

### 2. Handle Errors Gracefully
```tcl
set result [catch {
    set info [tossl::pkcs7::info $pkcs7_data]
} error_msg]

if {$result != 0} {
    puts "Failed to analyze PKCS#7: $error_msg"
    # Handle the error appropriately
    return
}
```

### 3. Check for Required Fields
```tcl
set info [tossl::pkcs7::info $pkcs7_data]

# Check if required fields exist before accessing
if {![dict exists $info type]} {
    puts "Error: PKCS#7 structure missing type information"
    return
}

# Use the information safely
switch [dict get $info type] {
    "pkcs7-signedData" {
        if {[dict exists $info num_signers]} {
            puts "Signed by [dict get $info num_signers] signer(s)"
        }
    }
    "pkcs7-envelopedData" {
        if {[dict exists $info num_recipients]} {
            puts "Encrypted for [dict get $info num_recipients] recipient(s)"
        }
        if {[dict exists $info cipher]} {
            puts "Using [dict get $info cipher] encryption"
        }
    }
    default {
        puts "Unknown PKCS#7 type: [dict get $info type]"
    }
}
```

### 4. Performance Considerations
For applications that need to analyze many PKCS#7 structures, consider caching the results when appropriate:

```tcl
# Cache info results for repeated analysis
if {![info exists ::pkcs7_cache($pkcs7_data)]} {
    set ::pkcs7_cache($pkcs7_data) [tossl::pkcs7::info $pkcs7_data]
}
set info $::pkcs7_cache($pkcs7_data)
```

## Related Commands

- `::tossl::pkcs7::sign` - Create PKCS#7 signatures
- `::tossl::pkcs7::verify` - Verify PKCS#7 signatures
- `::tossl::pkcs7::encrypt` - Encrypt data using PKCS#7
- `::tossl::pkcs7::decrypt` - Decrypt PKCS#7 encrypted data
- `::tossl::x509::parse` - Parse X.509 certificates
- `::tossl::key::parse` - Parse cryptographic keys

## See Also

- [RFC 2315](https://tools.ietf.org/html/rfc2315) - PKCS#7: Cryptographic Message Syntax
- [RFC 5652](https://tools.ietf.org/html/rfc5652) - Cryptographic Message Syntax (CMS)
- [S/MIME](https://tools.ietf.org/html/rfc8551) - Secure/Multipurpose Internet Mail Extensions 