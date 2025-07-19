# ::tossl::asn1::oid_to_text

Convert Object Identifier (OID) to text representation.

## Overview

`::tossl::asn1::oid_to_text` converts Object Identifiers (OIDs) in dot notation to their text name representations when available. The command takes an OID in standard dot notation format and returns the corresponding text name if OpenSSL recognizes it, otherwise returns the original OID. This is the complementary function to `::tossl::asn1::text_to_oid` and supports round-trip conversions.

## Syntax

```
tossl::asn1::oid_to_text oid
```

### Parameters

- **oid**: The Object Identifier in dot notation format (e.g., "2.5.4.3")

### Return Value

Returns a string containing either:
- The text name if OpenSSL recognizes the OID (e.g., "commonName")
- The original OID if no text name is available (e.g., "1.2.3.4.5")

## Example

```tcl
# Convert OID to text name (when available)
set text_name [tossl::asn1::oid_to_text "2.5.4.3"]
puts "Text name: $text_name"  ;# Output: commonName (if available)

# Convert OID with no text name (returns original OID)
set result [tossl::asn1::oid_to_text "1.2.3.4.5"]
puts "Result: $result"  ;# Output: 1.2.3.4.5

# Round-trip conversion
set original "2.5.4.3"
set converted [tossl::asn1::oid_to_text $original]
set back [tossl::asn1::text_to_oid $converted]
puts "Round-trip: $original -> $converted -> $back"

# Test multiple OIDs
set oids {"2.5.4.3" "2.5.4.6" "1.2.3.4.5"}
foreach oid $oids {
    set text [tossl::asn1::oid_to_text $oid]
    puts "$oid -> $text"
}
```

## Common OID to Text Conversions

The command can convert many standard OIDs to their text names:

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

**Note**: The actual text names returned depend on the OpenSSL installation and version.

## Error Handling

- Returns an error if no OID is provided
- Returns an error if the OID is not in valid dot notation format
- Returns an error if the OID contains invalid characters
- Returns an error if memory allocation fails

## Advanced Usage

### Batch OID Conversion

```tcl
# Convert multiple OIDs efficiently
proc convert_multiple_oids_to_text {oid_list} {
    set results {}
    foreach oid $oid_list {
        if {[catch {
            set result [tossl::asn1::oid_to_text $oid]
            lappend results [dict create oid $oid result $result]
        } err]} {
            lappend results [dict create oid $oid error $err]
        }
    }
    return $results
}

# Usage
set oids {"2.5.4.3" "2.5.4.6" "1.2.3.4.5"}
set conversions [convert_multiple_oids_to_text $oids]
foreach conv $conversions {
    if {[dict exists $conv error]} {
        puts "[dict get $conv oid]: ERROR - [dict get $conv error]"
    } else {
        puts "[dict get $conv oid]: [dict get $conv result]"
    }
}
```

### OID Validation and Text Name Detection

```tcl
# Validate OID and detect if text name is available
proc validate_oid_and_get_text {oid} {
    if {[catch {
        set result [tossl::asn1::oid_to_text $oid]
        
        # Check if result is a valid OID format (no text name available)
        if {[regexp {^\d+(\.\d+)*$} $result]} {
            if {$result eq $oid} {
                return [dict create valid 1 oid $result type "oid_no_text"]
            } else {
                return [dict create valid 1 oid $result type "oid_converted"]
            }
        } else {
            return [dict create valid 1 oid $result type "text_name"]
        }
    } err]} {
        return [dict create valid 0 error $err]
    }
}

# Usage
set test_inputs {"2.5.4.3" "1.2.3.4.5" "invalid_oid"}
foreach input $test_inputs {
    set validation [validate_oid_and_get_text $input]
    if {[dict get $validation valid]} {
        puts "$input -> [dict get $validation oid] ([dict get $validation type])"
    } else {
        puts "$input -> ERROR: [dict get $validation error]"
    }
}
```

### Certificate Extension OID Analysis

```tcl
# Analyze certificate extension OIDs
proc analyze_extension_oids {extension_oids} {
    set analysis {}
    foreach oid $extension_oids {
        if {[catch {
            set text [tossl::asn1::oid_to_text $oid]
            
            # Determine if we got a text name or OID
            if {[regexp {^\d+(\.\d+)*$} $text]} {
                set type "unknown_extension"
                set description "Unknown extension OID"
            } else {
                set type "known_extension"
                set description "Known extension with text name"
            }
            
            lappend analysis [dict create \
                oid $oid \
                text $text \
                type $type \
                description $description]
        } err]} {
            lappend analysis [dict create \
                oid $oid \
                text "" \
                type "error" \
                description "Error: $err"]
        }
    }
    return $analysis
}

# Usage
set extensions {"2.5.29.19" "2.5.29.15" "2.5.29.17" "1.2.3.4.5"}
set analysis [analyze_extension_oids $extensions]
foreach ext $analysis {
    puts "[dict get $ext oid]: [dict get $ext text] ([dict get $ext type])"
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized OID lookup functions
- **Memory Management**: Proper memory allocation and cleanup
- **Caching**: OpenSSL maintains internal OID tables for fast lookups

### Performance Monitoring

```tcl
# Monitor OID to text conversion performance
proc benchmark_oid_to_text_conversion {iterations oid_list} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach oid $oid_list {
            set result [tossl::asn1::oid_to_text $oid]
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
set benchmark [benchmark_oid_to_text_conversion 100 $test_oids]
puts "Average conversion time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Convert OIDs for certificate extensions
proc get_extension_text_names {extension_oids} {
    set text_names {}
    foreach oid $extension_oids {
        if {[catch {
            set text [tossl::asn1::oid_to_text $oid]
            lappend text_names $text
        } err]} {
            puts "Warning: Could not convert '$oid' to text: $err"
            lappend text_names $oid  ;# Use OID as fallback
        }
    }
    return $text_names
}

# Usage
set extensions {"2.5.29.19" "2.5.29.15" "2.5.29.17"}
set text_names [get_extension_text_names $extensions]
puts "Extension text names: $text_names"
```

### Cryptographic Algorithm OID Handling

```tcl
# Handle cryptographic algorithm OIDs
proc get_algorithm_text_name {algorithm_oid} {
    if {[catch {
        set text [tossl::asn1::oid_to_text $algorithm_oid]
        
        # Check if we got a text name or OID
        if {[regexp {^\d+(\.\d+)*$} $text]} {
            return "Unknown Algorithm ($algorithm_oid)"
        } else {
            return $text
        }
    } err]} {
        return "Error: $err"
    }
}

# Usage
set algorithms {"1.2.840.113549.1.1.1" "1.2.840.10040.4.1" "1.2.840.10045.2.1"}
foreach alg $algorithms {
    set name [get_algorithm_text_name $alg]
    puts "$alg: $name"
}
```

### ASN.1 Structure Analysis

```tcl
# Analyze ASN.1 structures with OID conversion
proc analyze_asn1_oids {oid_list} {
    set analysis {}
    foreach oid $oid_list {
        if {[catch {
            set text [tossl::asn1::oid_to_text $oid]
            
            # Determine the type of result
            if {[regexp {^\d+(\.\d+)*$} $text]} {
                if {$text eq $oid} {
                    set result_type "oid_no_text"
                } else {
                    set result_type "oid_converted"
                }
            } else {
                set result_type "text_name"
            }
            
            lappend analysis [dict create \
                original_oid $oid \
                result $text \
                type $result_type]
        } err]} {
            lappend analysis [dict create \
                original_oid $oid \
                result "" \
                type "error" \
                error $err]
        }
    }
    return $analysis
}

# Usage
set oids {"2.5.4.3" "1.2.3.4.5" "1.2.840.113549.1.1.1"}
set analysis [analyze_asn1_oids $oids]
foreach item $analysis {
    puts "[dict get $item original_oid] -> [dict get $item result] ([dict get $item type])"
}
```

## Troubleshooting

### Common Issues

1. **"Invalid OID" error**
   - Check that the input is a valid OID format
   - Ensure the OID uses dot notation (e.g., "2.5.4.3")
   - Verify no special characters are present

2. **"wrong # args" error**
   - Ensure exactly one argument is provided
   - Check argument syntax

3. **OID returned instead of text name**
   - This is normal behavior when OpenSSL doesn't have a text name for the OID
   - The function returns the original OID when no text name is available

### Debug Information

```tcl
# Debug OID to text conversion process
proc debug_oid_to_text_conversion {input} {
    puts "Debug: Converting '$input' to text"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::asn1::oid_to_text $input]
        set end_time [clock milliseconds]
        
        puts "Debug: Conversion successful"
        puts "Debug: Conversion time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Result: '$result'"
        puts "Debug: Result length: [string length $result]"
        
        # Validate result format
        if {[regexp {^\d+(\.\d+)*$} $result]} {
            if {$result eq $input} {
                puts "Debug: Result is original OID (no text name available)"
            } else {
                puts "Debug: Result is converted OID"
            }
        } else {
            puts "Debug: Result is text name"
        }
        
        return $result
    } err]} {
        puts "Debug: Conversion failed: $err"
        return ""
    }
}

# Usage
set test_inputs {"2.5.4.3" "1.2.3.4.5" "invalid_oid"}
foreach input $test_inputs {
    set result [debug_oid_to_text_conversion $input]
    puts "Final result for '$input': '$result'"
    puts "---"
}
```

## OID Standards and Formats

### Supported Formats

- **Dot Notation**: Standard OID format (e.g., "2.5.4.3")
- **Text Names**: Recognized text names returned when available
- **Fallback Behavior**: Returns original OID when no text name is available

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

- `::tossl::asn1::text_to_oid` - Convert text representation to OID
- `::tossl::asn1::parse` - Parse ASN.1 structures
- `::tossl::asn1::encode` - Encode ASN.1 types
- `::tossl::asn1::sequence_create` - Create ASN.1 SEQUENCE structures
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::csr::create` - Create certificate signing requests

## Technical Notes

### Conversion Behavior

1. **Text Name Available**: When OpenSSL has a text name for the OID, returns the text name
2. **No Text Name**: When no text name is available, returns the original OID
3. **Invalid OID**: When given an invalid OID, returns an error
4. **Round-trip**: The function supports round-trip conversion with `::tossl::asn1::text_to_oid`

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient string handling

### Performance Characteristics

- **Time Complexity**: O(1) for known OIDs, O(n) for lookups
- **Space Complexity**: O(1) for the result string
- **Memory Usage**: Minimal overhead beyond the result string

### OpenSSL Integration

The command leverages OpenSSL's comprehensive OID database:
- **Built-in Tables**: Uses OpenSSL's internal OID tables
- **Version Dependent**: Available text names depend on OpenSSL version
- **Standards Compliant**: Follows ASN.1 and X.500 standards
- **Extensible**: Supports custom OID additions through OpenSSL configuration 