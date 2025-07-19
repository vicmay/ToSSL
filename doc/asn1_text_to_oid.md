# ::tossl::asn1::text_to_oid

Convert text representation to Object Identifier (OID).

## Overview

`::tossl::asn1::text_to_oid` converts text representations of Object Identifiers (OIDs) to their canonical dot notation format. The command can handle both OID dot notation (e.g., "2.5.4.3") and text names (e.g., "commonName") that are recognized by OpenSSL. When given an OID in dot notation, it returns the corresponding text name if available, otherwise returns the original OID. When given a text name, it returns the corresponding OID in dot notation.

## Syntax

```
tossl::asn1::text_to_oid text
```

### Parameters

- **text**: The text representation to convert. Can be:
  - An OID in dot notation (e.g., "2.5.4.3")
  - A recognized text name (e.g., "commonName")
  - Any valid OID format recognized by OpenSSL

### Return Value

Returns a string containing the converted OID or text name.

## Example

```tcl
# Convert OID to text name
set text_name [tossl::asn1::text_to_oid "2.5.4.3"]
puts "Text name: $text_name"  ;# Output: commonName

# Convert text name to OID
set oid [tossl::asn1::text_to_oid "commonName"]
puts "OID: $oid"  ;# Output: 2.5.4.3

# Convert unknown OID (returns original)
set result [tossl::asn1::text_to_oid "1.2.3.4.5"]
puts "Result: $result"  ;# Output: 1.2.3.4.5

# Round-trip conversion
set original "2.5.4.3"
set converted [tossl::asn1::text_to_oid $original]
set back [tossl::asn1::oid_to_text $converted]
puts "Round-trip: $original -> $converted -> $back"
```

## Common OID Conversions

The command recognizes many standard OIDs and their text names:

| OID | Text Name | Description |
|-----|-----------|-------------|
| 2.5.4.3 | commonName | Common Name |
| 2.5.4.6 | countryName | Country Name |
| 2.5.4.7 | localityName | Locality Name |
| 2.5.4.8 | stateOrProvinceName | State or Province Name |
| 2.5.4.10 | organizationName | Organization Name |
| 2.5.4.11 | organizationalUnitName | Organizational Unit Name |
| 1.3.6.1.5.5.7.1.1 | Authority Information Access | Authority Information Access |
| 1.2.840.113549.1.1.1 | rsaEncryption | RSA Encryption |
| 1.2.840.113549.1.1.11 | sha256WithRSAEncryption | SHA-256 with RSA Encryption |

## Error Handling

- Returns an error if no text is provided
- Returns an error if the text is not a valid OID format
- Returns an error if the text contains invalid characters
- Returns an error if memory allocation fails

## Advanced Usage

### Batch OID Conversion

```tcl
# Convert multiple OIDs efficiently
proc convert_multiple_oids {oid_list} {
    set results {}
    foreach oid $oid_list {
        if {[catch {
            set result [tossl::asn1::text_to_oid $oid]
            lappend results [dict create oid $oid result $result]
        } err]} {
            lappend results [dict create oid $oid error $err]
        }
    }
    return $results
}

# Usage
set oids {"2.5.4.3" "2.5.4.6" "1.2.3.4.5"}
set conversions [convert_multiple_oids $oids]
foreach conv $conversions {
    if {[dict exists $conv error]} {
        puts "[dict get $conv oid]: ERROR - [dict get $conv error]"
    } else {
        puts "[dict get $conv oid]: [dict get $conv result]"
    }
}
```

### OID Validation and Normalization

```tcl
# Validate and normalize OID format
proc validate_and_normalize_oid {input} {
    if {[catch {
        set result [tossl::asn1::text_to_oid $input]
        
        # Check if result is a valid OID format
        if {[regexp {^\d+(\.\d+)*$} $result]} {
            return [dict create valid 1 oid $result type "oid"]
        } else {
            return [dict create valid 1 oid $result type "text_name"]
        }
    } err]} {
        return [dict create valid 0 error $err]
    }
}

# Usage
set test_inputs {"2.5.4.3" "commonName" "invalid_oid" "1.2.3.4.5"}
foreach input $test_inputs {
    set validation [validate_and_normalize_oid $input]
    if {[dict get $validation valid]} {
        puts "$input -> [dict get $validation oid] ([dict get $validation type])"
    } else {
        puts "$input -> ERROR: [dict get $validation error]"
    }
}
```

### Certificate Extension OID Handling

```tcl
# Handle certificate extension OIDs
proc get_extension_oid {extension_name} {
    set extension_oids {
        basicConstraints "2.5.29.19"
        keyUsage "2.5.29.15"
        extendedKeyUsage "2.5.29.37"
        subjectAltName "2.5.29.17"
        authorityKeyIdentifier "2.5.29.35"
        subjectKeyIdentifier "2.5.29.14"
    }
    
    if {[dict exists $extension_oids $extension_name]} {
        return [dict get $extension_oids $extension_name]
    } else {
        # Try to convert using the command
        if {[catch {
            return [tossl::asn1::text_to_oid $extension_name]
        } err]} {
            error "Unknown extension: $extension_name"
        }
    }
}

# Usage
set extensions {"basicConstraints" "keyUsage" "subjectAltName"}
foreach ext $extensions {
    set oid [get_extension_oid $ext]
    puts "$ext: $oid"
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized OID lookup functions
- **Memory Management**: Proper memory allocation and cleanup
- **Caching**: OpenSSL maintains internal OID tables for fast lookups

### Performance Monitoring

```tcl
# Monitor OID conversion performance
proc benchmark_oid_conversion {iterations oid_list} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach oid $oid_list {
            set result [tossl::asn1::text_to_oid $oid]
            if {[string length $result] == 0} {
                error "Empty result for OID: $oid"
            }
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set total_operations [expr {$iterations * [llength $oid_list]}]
    set avg_time [expr {double($total_time) / $total_operations}]
    
    return [dict create \
        total_time $total_time \
        total_operations $total_operations \
        average_time $avg_time \
        operations_per_second [expr {double($total_operations) * 1000 / $total_time}]]
}

# Usage
set test_oids {"2.5.4.3" "2.5.4.6" "1.2.840.113549.1.1.1"}
set benchmark [benchmark_oid_conversion 100 $test_oids]
puts "Average conversion time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Convert OIDs for certificate extensions
proc create_extension_oid_list {extension_names} {
    set oids {}
    foreach name $extension_names {
        if {[catch {
            set oid [tossl::asn1::text_to_oid $name]
            lappend oids $oid
        } err]} {
            puts "Warning: Could not convert '$name' to OID: $err"
        }
    }
    return $oids
}

# Usage
set extensions {"basicConstraints" "keyUsage" "subjectAltName"}
set oid_list [create_extension_oid_list $extensions]
puts "Extension OIDs: $oid_list"
```

### Cryptographic Algorithm OID Handling

```tcl
# Handle cryptographic algorithm OIDs
proc get_algorithm_oid {algorithm_name} {
    set algorithm_oids {
        "RSA" "1.2.840.113549.1.1.1"
        "DSA" "1.2.840.10040.4.1"
        "ECDSA" "1.2.840.10045.2.1"
        "SHA-256" "2.16.840.1.101.3.4.2.1"
        "SHA-384" "2.16.840.1.101.3.4.2.2"
        "SHA-512" "2.16.840.1.101.3.4.2.3"
    }
    
    if {[dict exists $algorithm_oids $algorithm_name]} {
        return [dict get $algorithm_oids $algorithm_name]
    } else {
        # Try to convert using the command
        if {[catch {
            return [tossl::asn1::text_to_oid $algorithm_name]
        } err]} {
            error "Unknown algorithm: $algorithm_name"
        }
    }
}

# Usage
set algorithms {"RSA" "DSA" "SHA-256"}
foreach alg $algorithms {
    set oid [get_algorithm_oid $alg]
    puts "$alg: $oid"
}
```

### ASN.1 Structure Creation

```tcl
# Create ASN.1 structures with OID conversion
proc create_oid_sequence {oid_list} {
    set converted_oids {}
    foreach oid $oid_list {
        set converted [tossl::asn1::text_to_oid $oid]
        lappend converted_oids $converted
    }
    
    return [tossl::asn1::sequence_create {*}$converted_oids]
}

# Usage
set oids {"2.5.4.3" "2.5.4.6" "2.5.4.7"}
set sequence [create_oid_sequence $oids]
puts "ASN.1 sequence length: [string length $sequence] bytes"
```

## Troubleshooting

### Common Issues

1. **"Invalid OID text" error**
   - Check that the input is a valid OID format
   - Ensure the text is recognized by OpenSSL
   - Verify no special characters are present

2. **"wrong # args" error**
   - Ensure exactly one argument is provided
   - Check argument syntax

3. **Empty result**
   - Verify the input OID is valid
   - Check that OpenSSL recognizes the OID

### Debug Information

```tcl
# Debug OID conversion process
proc debug_oid_conversion {input} {
    puts "Debug: Converting '$input' to OID"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::asn1::text_to_oid $input]
        set end_time [clock milliseconds]
        
        puts "Debug: Conversion successful"
        puts "Debug: Conversion time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Result: '$result'"
        puts "Debug: Result length: [string length $result]"
        
        # Validate result format
        if {[regexp {^\d+(\.\d+)*$} $result]} {
            puts "Debug: Result is valid OID format"
        } else {
            puts "Debug: Result is text name format"
        }
        
        return $result
    } err]} {
        puts "Debug: Conversion failed: $err"
        return ""
    }
}

# Usage
set test_inputs {"2.5.4.3" "commonName" "invalid_oid"}
foreach input $test_inputs {
    set result [debug_oid_conversion $input]
    puts "Final result for '$input': '$result'"
    puts "---"
}
```

## OID Standards and Formats

### Supported Formats

- **Dot Notation**: Standard OID format (e.g., "2.5.4.3")
- **Text Names**: Recognized text names (e.g., "commonName")
- **Mixed Format**: Some OIDs may have both formats available

### OID Structure

OIDs follow the ASN.1 Object Identifier structure:
- Hierarchical tree structure
- Each node identified by a number
- Dots separate node numbers
- Example: 2.5.4.3 (ISO → ITU-T → X.500 → Attributes → Common Name)

### OpenSSL OID Database

The command uses OpenSSL's built-in OID database which includes:
- Standard X.500/X.509 OIDs
- Cryptographic algorithm OIDs
- Certificate extension OIDs
- PKCS OIDs
- Many other standard OIDs

## See Also

- `::tossl::asn1::oid_to_text` - Convert OID to text representation
- `::tossl::asn1::parse` - Parse ASN.1 structures
- `::tossl::asn1::encode` - Encode ASN.1 types
- `::tossl::asn1::sequence_create` - Create ASN.1 SEQUENCE structures
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::csr::create` - Create certificate signing requests

## Technical Notes

### Conversion Behavior

1. **OID Input**: When given an OID in dot notation, returns the corresponding text name if available
2. **Text Input**: When given a text name, returns the corresponding OID in dot notation
3. **Unknown Input**: When given an unrecognized input, returns an error
4. **Round-trip**: The function supports round-trip conversion with `::tossl::asn1::oid_to_text`

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient string handling

### Performance Characteristics

- **Time Complexity**: O(1) for known OIDs, O(n) for lookups
- **Space Complexity**: O(1) for the result string
- **Memory Usage**: Minimal overhead beyond the result string 