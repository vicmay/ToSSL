# ::tossl::asn1::encode

Encode ASN.1 types to DER format.

## Overview

`::tossl::asn1::encode` converts ASN.1 data types to their DER (Distinguished Encoding Rules) binary representation. The command supports encoding integers, octet strings, UTF8 strings, and object identifiers into standard ASN.1 DER format. This is useful for creating ASN.1 structures, certificate components, and other cryptographic data that requires ASN.1 encoding.

## Syntax

```
tossl::asn1::encode type value
```

### Parameters

- **type**: The ASN.1 type to encode. Supported types:
  - `integer` - ASN.1 INTEGER type
  - `octetstring` - ASN.1 OCTET STRING type
  - `utf8string` - ASN.1 UTF8String type
  - `objectidentifier` - ASN.1 OBJECT IDENTIFIER type

- **value**: The value to encode according to the specified type

### Return Value

Returns a binary string containing the DER-encoded ASN.1 data.

## Example

```tcl
# Encode an integer
set int_der [tossl::asn1::encode integer 123]
puts "Integer DER length: [string length $int_der] bytes"

# Encode an octet string
set octet_der [tossl::asn1::encode octetstring "hello"]
puts "OctetString DER length: [string length $octet_der] bytes"

# Encode a UTF8 string
set utf8_der [tossl::asn1::encode utf8string "Hello, World!"]
puts "UTF8String DER length: [string length $utf8_der] bytes"

# Encode an object identifier
set oid_der [tossl::asn1::encode objectidentifier "1.2.3"]
puts "OID DER length: [string length $oid_der] bytes"

# Encode negative integers
set neg_int_der [tossl::asn1::encode integer -456]
puts "Negative integer DER length: [string length $neg_int_der] bytes"

# Encode empty strings
set empty_octet_der [tossl::asn1::encode octetstring ""]
puts "Empty octet string DER length: [string length $empty_octet_der] bytes"
```

## Supported ASN.1 Types

### INTEGER

Encodes integer values to ASN.1 INTEGER type.

```tcl
# Positive integers
set pos_int [tossl::asn1::encode integer 123]
puts "Positive integer: [string length $pos_int] bytes"

# Negative integers
set neg_int [tossl::asn1::encode integer -456]
puts "Negative integer: [string length $neg_int] bytes"

# Large integers
set large_int [tossl::asn1::encode integer 999999]
puts "Large integer: [string length $large_int] bytes"

# Zero
set zero_int [tossl::asn1::encode integer 0]
puts "Zero: [string length $zero_int] bytes"
```

### OCTET STRING

Encodes binary data or strings to ASN.1 OCTET STRING type.

```tcl
# Regular strings
set str_octet [tossl::asn1::encode octetstring "hello"]
puts "String octet: [string length $str_octet] bytes"

# Empty strings
set empty_octet [tossl::asn1::encode octetstring ""]
puts "Empty octet: [string length $empty_octet] bytes"

# Long strings
set long_octet [tossl::asn1::encode octetstring "Hello, World!"]
puts "Long octet: [string length $long_octet] bytes"

# Binary data (with null bytes)
set binary_octet [tossl::asn1::encode octetstring "binary\0data"]
puts "Binary octet: [string length $binary_octet] bytes"
```

### UTF8String

Encodes Unicode strings to ASN.1 UTF8String type.

```tcl
# ASCII strings
set ascii_utf8 [tossl::asn1::encode utf8string "hello"]
puts "ASCII UTF8: [string length $ascii_utf8] bytes"

# Unicode strings
set unicode_utf8 [tossl::asn1::encode utf8string "Hello 世界"]
puts "Unicode UTF8: [string length $unicode_utf8] bytes"

# Empty strings
set empty_utf8 [tossl::asn1::encode utf8string ""]
puts "Empty UTF8: [string length $empty_utf8] bytes"

# Special characters
set special_utf8 [tossl::asn1::encode utf8string "Hello\nWorld\tTest"]
puts "Special UTF8: [string length $special_utf8] bytes"
```

### OBJECT IDENTIFIER

Encodes object identifiers to ASN.1 OBJECT IDENTIFIER type.

```tcl
# Simple OIDs
set simple_oid [tossl::asn1::encode objectidentifier "1.2.3"]
puts "Simple OID: [string length $simple_oid] bytes"

# Standard OIDs
set standard_oid [tossl::asn1::encode objectidentifier "2.5.4.3"]
puts "Standard OID: [string length $standard_oid] bytes"

# Complex OIDs
set complex_oid [tossl::asn1::encode objectidentifier "1.3.6.1.5.5.7.1.1"]
puts "Complex OID: [string length $complex_oid] bytes"

# Cryptographic OIDs
set crypto_oid [tossl::asn1::encode objectidentifier "1.2.840.113549.1.1.1"]
puts "Crypto OID: [string length $crypto_oid] bytes"
```

## Error Handling

- Returns an error if no type is provided
- Returns an error if no value is provided
- Returns an error if the type is not supported
- Returns an error if the value is invalid for the specified type
- Returns an error if memory allocation fails

## Advanced Usage

### Batch Encoding

```tcl
# Encode multiple values efficiently
proc encode_multiple_values {type_value_pairs} {
    set results {}
    foreach pair $type_value_pairs {
        set type [lindex $pair 0]
        set value [lindex $pair 1]
        if {[catch {
            set result [tossl::asn1::encode $type $value]
            lappend results [dict create type $type value $value result $result]
        } err]} {
            lappend results [dict create type $type value $value error $err]
        }
    }
    return $results
}

# Usage
set pairs {
    {integer 123}
    {octetstring "hello"}
    {utf8string "world"}
    {objectidentifier "1.2.3"}
}
set encodings [encode_multiple_values $pairs]
foreach enc $encodings {
    if {[dict exists $enc error]} {
        puts "[dict get $enc type] [dict get $enc value]: ERROR - [dict get $enc error]"
    } else {
        puts "[dict get $enc type] [dict get $enc value]: [string length [dict get $enc result]] bytes"
    }
}
```

### DER Length Analysis

```tcl
# Analyze DER encoding lengths
proc analyze_der_lengths {type_value_pairs} {
    set analysis {}
    foreach pair $type_value_pairs {
        set type [lindex $pair 0]
        set value [lindex $pair 1]
        if {[catch {
            set result [tossl::asn1::encode $type $value]
            set der_length [string length $result]
            
            # Calculate expected minimum length
            set value_length [string length $value]
            set min_length 2  ;# Tag (1) + Length (1)
            if {$value_length > 0} {
                incr min_length $value_length
            }
            
            lappend analysis [dict create \
                type $type \
                value $value \
                der_length $der_length \
                min_length $min_length \
                efficiency [expr {double($der_length) / $min_length}]]
        } err]} {
            lappend analysis [dict create \
                type $type \
                value $value \
                error $err]
        }
    }
    return $analysis
}

# Usage
set test_pairs {
    {integer 123}
    {integer 999999}
    {octetstring "hello"}
    {utf8string "Hello, World!"}
    {objectidentifier "1.2.3"}
}
set analysis [analyze_der_lengths $test_pairs]
foreach item $analysis {
    if {[dict exists $item error]} {
        puts "[dict get $item type] [dict get $item value]: ERROR"
    } else {
        puts "[dict get $item type] [dict get $item value]: [dict get $item der_length] bytes (efficiency: [format %.2f [dict get $item efficiency]])"
    }
}
```

### Certificate Component Encoding

```tcl
# Encode certificate components
proc encode_certificate_components {components} {
    set encoded {}
    foreach component $components {
        set type [dict get $component type]
        set value [dict get $component value]
        if {[catch {
            set der [tossl::asn1::encode $type $value]
            dict set component der $der
            dict set component der_length [string length $der]
            lappend encoded $component
        } err]} {
            puts "Warning: Failed to encode $type $value: $err"
        }
    }
    return $encoded
}

# Usage
set cert_components {
    {type integer value 2}  ;# Version
    {type objectidentifier value "1.2.840.113549.1.1.1"}  ;# Algorithm
    {type octetstring value "subject"}  ;# Subject
    {type utf8string value "Hello, World!"}  ;# Common Name
}
set encoded_components [encode_certificate_components $cert_components]
foreach comp $encoded_components {
    puts "[dict get $comp type] [dict get $comp value]: [dict get $comp der_length] bytes"
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized ASN.1 encoding functions
- **Memory Management**: Proper memory allocation and cleanup
- **DER Compliance**: Produces standard DER-encoded output

### Performance Monitoring

```tcl
# Monitor ASN.1 encoding performance
proc benchmark_asn1_encoding {iterations type_value_pairs} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach pair $type_value_pairs {
            set type [lindex $pair 0]
            set value [lindex $pair 1]
            set result [tossl::asn1::encode $type $value]
            if {[string length $result] == 0} {
                error "Empty result for $type $value"
            }
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set total_operations [expr {$iterations * [llength $type_value_pairs]}]
    set avg_time [expr {double($total_time) / $total_operations}]
    
    return [dict create \
        total_time $total_time \
        total_operations $total_operations \
        average_time $avg_time \
        operations_per_second [expr {double($total_operations) * 1000 / $total_time}]]
}

# Usage
set test_pairs {
    {integer 123}
    {octetstring "hello"}
    {utf8string "world"}
    {objectidentifier "1.2.3"}
}
set benchmark [benchmark_asn1_encoding 100 $test_pairs]
puts "Average encoding time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Encode certificate extensions
proc encode_certificate_extensions {extensions} {
    set encoded_extensions {}
    foreach ext $extensions {
        set oid [dict get $ext oid]
        set value [dict get $ext value]
        set critical [dict get $ext critical]
        
        # Encode OID
        set oid_der [tossl::asn1::encode objectidentifier $oid]
        
        # Encode value based on type
        set value_type [dict get $ext value_type]
        set value_der [tossl::asn1::encode $value_type $value]
        
        puts "Extension $oid: [string length $oid_der] + [string length $value_der] bytes"
        lappend encoded_extensions [dict create \
            oid_der $oid_der \
            value_der $value_der \
            critical $critical]
    }
    return $encoded_extensions
}

# Usage
set extensions {
    {oid "2.5.29.19" value "CA:TRUE" value_type utf8string critical true}
    {oid "2.5.29.15" value "Digital Signature" value_type utf8string critical false}
    {oid "2.5.29.17" value "DNS:example.com" value_type utf8string critical false}
}
set encoded [encode_certificate_extensions $extensions]
puts "Encoded [llength $encoded] extensions"
```

### Cryptographic Algorithm Encoding

```tcl
# Encode cryptographic algorithm identifiers
proc encode_algorithm_identifiers {algorithms} {
    set encoded_algorithms {}
    foreach alg $algorithms {
        set oid [dict get $alg oid]
        set parameters [dict get $alg parameters]
        
        # Encode algorithm OID
        set oid_der [tossl::asn1::encode objectidentifier $oid]
        
        # Encode parameters if present
        if {$parameters ne ""} {
            set param_der [tossl::asn1::encode [dict get $alg param_type] $parameters]
        } else {
            set param_der ""
        }
        
        lappend encoded_algorithms [dict create \
            oid_der $oid_der \
            param_der $param_der \
            name [dict get $alg name]]
    }
    return $encoded_algorithms
}

# Usage
set algorithms {
    {oid "1.2.840.113549.1.1.1" parameters "" param_type octetstring name "RSA"}
    {oid "1.2.840.113549.1.1.11" parameters "" param_type octetstring name "SHA-256 with RSA"}
    {oid "1.2.840.10045.2.1" parameters "1.2.840.10045.3.1.7" param_type objectidentifier name "ECDSA with P-256"}
}
set encoded [encode_algorithm_identifiers $algorithms]
foreach alg $encoded {
    puts "[dict get $alg name]: [string length [dict get $alg oid_der]] + [string length [dict get $alg param_der]] bytes"
}
```

### ASN.1 Structure Creation

```tcl
# Create ASN.1 structures with encoded components
proc create_asn1_structure {structure_type components} {
    set encoded_components {}
    foreach comp $components {
        set type [dict get $comp type]
        set value [dict get $comp value]
        
        set der [tossl::asn1::encode $type $value]
        lappend encoded_components $der
    }
    
    # Use sequence_create to combine components
    return [tossl::asn1::sequence_create {*}$encoded_components]
}

# Usage
set components {
    {type integer value 1}
    {type utf8string value "Test Subject"}
    {type objectidentifier value "1.2.3.4.5"}
    {type octetstring value "test data"}
}
set structure [create_asn1_structure "sequence" $components]
puts "ASN.1 structure length: [string length $structure] bytes"
```

## Troubleshooting

### Common Issues

1. **"Unsupported ASN.1 type" error**
   - Check that the type is one of: integer, octetstring, utf8string, objectidentifier
   - Ensure the type name is spelled correctly

2. **"Invalid OID format" error**
   - Check that the OID uses dot notation (e.g., "1.2.3")
   - Ensure the OID contains only numbers and dots
   - Verify the OID is valid

3. **"wrong # args" error**
   - Ensure exactly two arguments are provided (type and value)
   - Check argument syntax

4. **Empty result**
   - Verify the input value is valid for the specified type
   - Check that the value is not empty for required types

### Debug Information

```tcl
# Debug ASN.1 encoding process
proc debug_asn1_encoding {type value} {
    puts "Debug: Encoding '$type' with value '$value'"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::asn1::encode $type $value]
        set end_time [clock milliseconds]
        
        puts "Debug: Encoding successful"
        puts "Debug: Encoding time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Result length: [string length $result] bytes"
        
        # Validate result
        if {[string length $result] >= 2} {
            puts "Debug: Result has minimum DER structure"
        } else {
            puts "Debug: Result may be too short"
        }
        
        return $result
    } err]} {
        puts "Debug: Encoding failed: $err"
        return ""
    }
}

# Usage
set test_cases {
    {integer 123}
    {octetstring "hello"}
    {utf8string "world"}
    {objectidentifier "1.2.3"}
}
foreach test_case $test_cases {
    set type [lindex $test_case 0]
    set value [lindex $test_case 1]
    set result [debug_asn1_encoding $type $value]
    puts "Final result for '$type $value': [string length $result] bytes"
    puts "---"
}
```

## ASN.1 Standards and DER Encoding

### Supported Types

- **INTEGER**: ASN.1 INTEGER type for numeric values
- **OCTET STRING**: ASN.1 OCTET STRING type for binary data
- **UTF8String**: ASN.1 UTF8String type for Unicode text
- **OBJECT IDENTIFIER**: ASN.1 OBJECT IDENTIFIER type for OIDs

### DER Encoding Rules

The command produces DER-encoded output following ASN.1 standards:
- **Tag**: Each type has a specific ASN.1 tag
- **Length**: Length field indicates the size of the value
- **Value**: The actual encoded data
- **Canonical**: DER ensures canonical encoding for interoperability

### Type-Specific Encoding

1. **INTEGER**: Encoded as signed integer with minimal length
2. **OCTET STRING**: Encoded as binary data with length prefix
3. **UTF8String**: Encoded as UTF-8 text with length prefix
4. **OBJECT IDENTIFIER**: Encoded as OID with compressed representation

## See Also

- `::tossl::asn1::parse` - Parse ASN.1 structures
- `::tossl::asn1::sequence_create` - Create ASN.1 SEQUENCE structures
- `::tossl::asn1::text_to_oid` - Convert text to OID
- `::tossl::asn1::oid_to_text` - Convert OID to text
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::csr::create` - Create certificate signing requests

## Technical Notes

### Encoding Behavior

1. **INTEGER**: Supports positive, negative, and zero values
2. **OCTET STRING**: Handles binary data and text strings
3. **UTF8String**: Supports Unicode and special characters
4. **OBJECT IDENTIFIER**: Validates OID format and encodes efficiently

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient DER encoding with minimal overhead

### Performance Characteristics

- **Time Complexity**: O(1) for most types, O(n) for strings
- **Space Complexity**: O(n) where n is the value size
- **Memory Usage**: Minimal overhead beyond the DER output

### OpenSSL Integration

The command leverages OpenSSL's ASN.1 encoding capabilities:
- **Standard Compliance**: Follows ASN.1 and DER standards
- **Optimized Encoding**: Uses OpenSSL's efficient encoding functions
- **Type Safety**: Validates types and values before encoding
- **Interoperability**: Produces standard DER output compatible with other systems 