# ::tossl::asn1::parse

Parse ASN.1 DER data and extract type information.

## Overview

`::tossl::asn1::parse` parses ASN.1 DER-encoded data and returns information about the ASN.1 type and structure. The command can parse various ASN.1 types including integers, octet strings, UTF8 strings, object identifiers, SETs, and SEQUENCEs. This is useful for analyzing ASN.1 structures, debugging certificate components, and understanding the structure of encoded ASN.1 data.

## Syntax

```
tossl::asn1::parse der_data
```

### Parameters

- **der_data**: Binary string containing DER-encoded ASN.1 data

### Return Value

Returns a string containing type information in the format:
- For basic types: `type=<type_number>, value_length=<length>`
- For object identifiers: `type=<type_number>, object=<oid_text>`

## Example

```tcl
# Parse an encoded integer
set int_encoded [tossl::asn1::encode integer 123]
set int_info [tossl::asn1::parse $int_encoded]
puts "Integer info: $int_info"

# Parse an encoded octet string
set octet_encoded [tossl::asn1::encode octetstring "hello"]
set octet_info [tossl::asn1::parse $octet_encoded]
puts "OctetString info: $octet_info"

# Parse an encoded OID
set oid_encoded [tossl::asn1::encode objectidentifier "1.2.3"]
set oid_info [tossl::asn1::parse $oid_encoded]
puts "OID info: $oid_info"

# Parse a SET structure
set set_encoded [tossl::asn1::set_create "element1" "element2"]
set set_info [tossl::asn1::parse $set_encoded]
puts "SET info: $set_info"

# Parse a SEQUENCE structure
set seq_encoded [tossl::asn1::sequence_create "element1" "element2"]
set seq_info [tossl::asn1::parse $seq_encoded]
puts "SEQUENCE info: $seq_info"
```

## Supported ASN.1 Types

### INTEGER (type=2)

Parses ASN.1 INTEGER types and returns the type number and value length.

```tcl
# Parse different integer values
set int_values {0 123 -456 999999}
foreach value $int_values {
    set encoded [tossl::asn1::encode integer $value]
    set info [tossl::asn1::parse $encoded]
    puts "Integer $value: $info"
}
```

### OCTET STRING (type=4)

Parses ASN.1 OCTET STRING types and returns the type number and value length.

```tcl
# Parse different string values
set string_values {"" "hello" "Hello, World!"}
foreach value $string_values {
    set encoded [tossl::asn1::encode octetstring $value]
    set info [tossl::asn1::parse $encoded]
    puts "OctetString '$value': $info"
}
```

### UTF8String (type=12)

Parses ASN.1 UTF8String types and returns the type number and value length.

```tcl
# Parse different UTF8 string values
set utf8_values {"" "hello" "Hello 世界"}
foreach value $utf8_values {
    set encoded [tossl::asn1::encode utf8string $value]
    set info [tossl::asn1::parse $encoded]
    puts "UTF8String '$value': $info"
}
```

### OBJECT IDENTIFIER (type=6)

Parses ASN.1 OBJECT IDENTIFIER types and returns the type number and OID text.

```tcl
# Parse different OID values
set oid_values {"1.2.3" "1.3.6.1.5.5.7.1.1" "2.5.4.3"}
foreach value $oid_values {
    set encoded [tossl::asn1::encode objectidentifier $value]
    set info [tossl::asn1::parse $encoded]
    puts "OID '$value': $info"
}
```

### SET (type=17)

Parses ASN.1 SET structures and returns the type number and value length.

```tcl
# Parse SET structures
set set_structures {
    {tossl::asn1::set_create 123 456 789}
    {tossl::asn1::set_create "hello" "world" "test"}
    {tossl::asn1::set_create 123 "hello" 456}
}
foreach create_cmd $set_structures {
    set encoded [eval $create_cmd]
    set info [tossl::asn1::parse $encoded]
    puts "SET: $info"
}
```

### SEQUENCE (type=16)

Parses ASN.1 SEQUENCE structures and returns the type number and value length.

```tcl
# Parse SEQUENCE structures
set seq_structures {
    {tossl::asn1::sequence_create 123 456 789}
    {tossl::asn1::sequence_create "hello" "world" "test"}
    {tossl::asn1::sequence_create 123 "hello" 456}
}
foreach create_cmd $seq_structures {
    set encoded [eval $create_cmd]
    set info [tossl::asn1::parse $encoded]
    puts "SEQUENCE: $info"
}
```

## Error Handling

- Returns an error if no DER data is provided
- Returns an error if the DER data is invalid or corrupted
- Returns an error if the DER data is empty
- Returns an error if the DER data is not properly formatted

## Advanced Usage

### Batch Parsing

```tcl
# Parse multiple ASN.1 structures efficiently
proc parse_multiple_structures {encoded_data_list} {
    set results {}
    foreach encoded_data $encoded_data_list {
        if {[catch {
            set info [tossl::asn1::parse $encoded_data]
            lappend results [dict create \
                data_length [string length $encoded_data] \
                parse_info $info \
                success true]
        } err]} {
            lappend results [dict create \
                data_length [string length $encoded_data] \
                error $err \
                success false]
        }
    }
    return $results
}

# Usage
set encoded_list {
    [tossl::asn1::encode integer 123]
    [tossl::asn1::encode octetstring "hello"]
    [tossl::asn1::encode objectidentifier "1.2.3"]
    [tossl::asn1::set_create "element1" "element2"]
}
set results [parse_multiple_structures $encoded_list]
foreach result $results {
    if {[dict get $result success]} {
        puts "[dict get $result data_length] bytes: [dict get $result parse_info]"
    } else {
        puts "[dict get $result data_length] bytes: ERROR - [dict get $result error]"
    }
}
```

### Type Analysis

```tcl
# Analyze ASN.1 types in detail
proc analyze_asn1_types {encoded_data_list} {
    set analysis {}
    foreach encoded_data $encoded_data_list {
        if {[catch {
            set info [tossl::asn1::parse $encoded_data]
            
            # Extract type information
            if {[regexp {type=(\d+)} $info -> type_num]} {
                set type_name [get_type_name $type_num]
                set value_info [get_value_info $info]
                
                lappend analysis [dict create \
                    type_number $type_num \
                    type_name $type_name \
                    value_info $value_info \
                    data_length [string length $encoded_data] \
                    parse_info $info]
            }
        } err]} {
            lappend analysis [dict create \
                error $err \
                data_length [string length $encoded_data]]
        }
    }
    return $analysis
}

# Helper functions
proc get_type_name {type_num} {
    switch $type_num {
        2 { return "INTEGER" }
        4 { return "OCTET STRING" }
        6 { return "OBJECT IDENTIFIER" }
        12 { return "UTF8String" }
        16 { return "SEQUENCE" }
        17 { return "SET" }
        default { return "UNKNOWN" }
    }
}

proc get_value_info {info} {
    if {[regexp {value_length=(\d+)} $info -> length]} {
        return "Length: $length"
    } elseif {[regexp {object=(.+)} $info -> oid]} {
        return "OID: $oid"
    } else {
        return "No value info"
    }
}

# Usage
set test_data {
    [tossl::asn1::encode integer 123]
    [tossl::asn1::encode octetstring "hello"]
    [tossl::asn1::encode objectidentifier "1.2.3"]
    [tossl::asn1::set_create "element1" "element2"]
}
set analysis [analyze_asn1_types $test_data]
foreach item $analysis {
    if {[dict exists $item error]} {
        puts "ERROR: [dict get $item error]"
    } else {
        puts "[dict get $item type_name] ([dict get $item type_number]): [dict get $item value_info]"
    }
}
```

### Certificate Component Analysis

```tcl
# Analyze certificate components
proc analyze_certificate_components {cert_components} {
    set analysis {}
    foreach component $cert_components {
        set type [dict get $component type]
        set value [dict get $component value]
        
        if {[catch {
            set encoded [tossl::asn1::encode $type $value]
            set info [tossl::asn1::parse $encoded]
            
            lappend analysis [dict create \
                component_type $type \
                component_value $value \
                parse_info $info \
                encoded_length [string length $encoded]]
        } err]} {
            lappend analysis [dict create \
                component_type $type \
                component_value $value \
                error $err]
        }
    }
    return $analysis
}

# Usage
set cert_components {
    {type integer value 2}
    {type objectidentifier value "1.2.840.113549.1.1.1"}
    {type octetstring value "subject"}
    {type utf8string value "Hello, World!"}
}
set analysis [analyze_certificate_components $cert_components]
foreach item $analysis {
    if {[dict exists $item error]} {
        puts "[dict get $item component_type] [dict get $item component_value]: ERROR"
    } else {
        puts "[dict get $item component_type] [dict get $item component_value]: [dict get $item parse_info] ([dict get $item encoded_length] bytes)"
    }
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized ASN.1 parsing functions
- **Memory Management**: Proper memory allocation and cleanup
- **DER Compliance**: Handles standard DER-encoded input
- **Type Detection**: Fast type identification and value extraction

### Performance Monitoring

```tcl
# Monitor ASN.1 parsing performance
proc benchmark_asn1_parsing {iterations encoded_data_list} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach encoded_data $encoded_data_list {
            set result [tossl::asn1::parse $encoded_data]
            if {![string match "*type=*" $result]} {
                error "Invalid result for parsing"
            }
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set total_operations [expr {$iterations * [llength $encoded_data_list]}]
    set avg_time [expr {double($total_time) / $total_operations}]
    
    return [dict create \
        total_time $total_time \
        total_operations $total_operations \
        average_time $avg_time \
        operations_per_second [expr {double($total_operations) * 1000 / $total_time}]]
}

# Usage
set test_data {
    [tossl::asn1::encode integer 123]
    [tossl::asn1::encode octetstring "hello"]
    [tossl::asn1::encode objectidentifier "1.2.3"]
    [tossl::asn1::set_create "element1" "element2"]
}
set benchmark [benchmark_asn1_parsing 25 $test_data]
puts "Average parsing time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Analyze certificate extensions
proc analyze_certificate_extensions {extensions} {
    set analysis {}
    foreach ext $extensions {
        set oid [dict get $ext oid]
        set value [dict get $ext value]
        set critical [dict get $ext critical]
        
        # Encode extension components
        if {[catch {
            set oid_encoded [tossl::asn1::encode objectidentifier $oid]
            set value_encoded [tossl::asn1::encode utf8string $value]
            
            set oid_info [tossl::asn1::parse $oid_encoded]
            set value_info [tossl::asn1::parse $value_encoded]
            
            lappend analysis [dict create \
                oid $oid \
                value $value \
                critical $critical \
                oid_info $oid_info \
                value_info $value_info]
        } err]} {
            puts "Warning: Failed to analyze extension $oid: $err"
        }
    }
    return $analysis
}

# Usage
set extensions {
    {oid "2.5.29.19" value "CA:TRUE" critical true}
    {oid "2.5.29.15" value "Digital Signature" critical false}
    {oid "2.5.29.17" value "DNS:example.com" critical false}
}
set analysis [analyze_certificate_extensions $extensions]
foreach ext $analysis {
    puts "[dict get $ext oid]: [dict get $ext oid_info], [dict get $ext value_info]"
}
```

### Cryptographic Algorithm Analysis

```tcl
# Analyze cryptographic algorithm identifiers
proc analyze_algorithm_identifiers {algorithms} {
    set analysis {}
    foreach alg $algorithms {
        set oid [dict get $alg oid]
        set parameters [dict get $alg parameters]
        
        if {[catch {
            set oid_encoded [tossl::asn1::encode objectidentifier $oid]
            set oid_info [tossl::asn1::parse $oid_encoded]
            
            set alg_analysis [dict create \
                oid $oid \
                oid_info $oid_info]
            
            if {$parameters ne ""} {
                set param_encoded [tossl::asn1::encode [dict get $alg param_type] $parameters]
                set param_info [tossl::asn1::parse $param_encoded]
                dict set alg_analysis param_info $param_info
            }
            
            lappend analysis $alg_analysis
        } err]} {
            puts "Warning: Failed to analyze algorithm $oid: $err"
        }
    }
    return $analysis
}

# Usage
set algorithms {
    {oid "1.2.840.113549.1.1.1" parameters "" param_type octetstring}
    {oid "1.2.840.113549.1.1.11" parameters "" param_type octetstring}
    {oid "1.2.840.10045.2.1" parameters "1.2.840.10045.3.1.7" param_type objectidentifier}
}
set analysis [analyze_algorithm_identifiers $algorithms]
foreach alg $analysis {
    puts "[dict get $alg oid]: [dict get $alg oid_info]"
    if {[dict exists $alg param_info]} {
        puts "  Parameters: [dict get $alg param_info]"
    }
}
```

### ASN.1 Structure Analysis

```tcl
# Analyze complex ASN.1 structures
proc analyze_asn1_structures {structure_definitions} {
    set analysis {}
    foreach structure_def $structure_definitions {
        set type [dict get $structure_def type]
        set elements [dict get $structure_def elements]
        
        if {[catch {
            switch $type {
                "set" {
                    set encoded [tossl::asn1::set_create {*}$elements]
                }
                "sequence" {
                    set encoded [tossl::asn1::sequence_create {*}$elements]
                }
                default {
                    error "Unknown structure type: $type"
                }
            }
            
            set info [tossl::asn1::parse $encoded]
            lappend analysis [dict create \
                type $type \
                elements $elements \
                parse_info $info \
                encoded_length [string length $encoded]]
        } err]} {
            lappend analysis [dict create \
                type $type \
                elements $elements \
                error $err]
        }
    }
    return $analysis
}

# Usage
set structures {
    {type "set" elements {"attribute1" "value1" "attribute2" "value2"}}
    {type "sequence" elements {"element1" "element2" "element3"}}
    {type "set" elements {123 456 789}}
}
set analysis [analyze_asn1_structures $structures]
foreach item $analysis {
    if {[dict exists $item error]} {
        puts "[dict get $item type]: ERROR - [dict get $item error]"
    } else {
        puts "[dict get $item type]: [dict get $item parse_info] ([dict get $item encoded_length] bytes)"
    }
}
```

## Troubleshooting

### Common Issues

1. **"Failed to parse ASN.1 data" error**
   - Check that the input is valid DER-encoded data
   - Ensure the data is not corrupted or truncated
   - Verify the data was created by a compatible ASN.1 encoder

2. **"wrong # args" error**
   - Ensure exactly one argument is provided (the DER data)
   - Check argument syntax

3. **Empty result**
   - Verify the input data is not empty
   - Check that the data contains valid ASN.1 structure

4. **Unexpected type numbers**
   - Verify the ASN.1 type mapping is correct
   - Check that the data was encoded with the expected type

### Debug Information

```tcl
# Debug ASN.1 parsing process
proc debug_asn1_parsing {der_data} {
    puts "Debug: Parsing DER data of length [string length $der_data]"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::asn1::parse $der_data]
        set end_time [clock milliseconds]
        
        puts "Debug: Parsing successful"
        puts "Debug: Parsing time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Parse result: $result"
        
        # Validate result format
        if {[string match "*type=*" $result]} {
            puts "Debug: Result has valid format"
        } else {
            puts "Debug: Result may not have valid format"
        }
        
        # Extract type information
        if {[regexp {type=(\d+)} $result -> type_num]} {
            puts "Debug: Type number: $type_num"
            switch $type_num {
                2 { puts "Debug: Type is INTEGER" }
                4 { puts "Debug: Type is OCTET STRING" }
                6 { puts "Debug: Type is OBJECT IDENTIFIER" }
                12 { puts "Debug: Type is UTF8String" }
                16 { puts "Debug: Type is SEQUENCE" }
                17 { puts "Debug: Type is SET" }
                default { puts "Debug: Type is UNKNOWN" }
            }
        }
        
        return $result
    } err]} {
        puts "Debug: Parsing failed: $err"
        return ""
    }
}

# Usage
set test_data [tossl::asn1::encode integer 123]
set result [debug_asn1_parsing $test_data]
puts "Final result: $result"
```

## ASN.1 Standards and Type Mapping

### Supported Types

| Type Name | Type Number | Description |
|-----------|-------------|-------------|
| INTEGER | 2 | ASN.1 INTEGER type |
| OCTET STRING | 4 | ASN.1 OCTET STRING type |
| OBJECT IDENTIFIER | 6 | ASN.1 OBJECT IDENTIFIER type |
| UTF8String | 12 | ASN.1 UTF8String type |
| SEQUENCE | 16 | ASN.1 SEQUENCE type |
| SET | 17 | ASN.1 SET type |

### Return Value Format

The command returns information in the following formats:

1. **Basic Types**: `type=<number>, value_length=<length>`
   - Example: `type=2, value_length=1` for INTEGER
   - Example: `type=4, value_length=5` for OCTET STRING

2. **Object Identifiers**: `type=<number>, object=<oid_text>`
   - Example: `type=6, object=1.2.3` for OBJECT IDENTIFIER

3. **Complex Types**: `type=<number>, value_length=<length>`
   - Example: `type=16, value_length=0` for SEQUENCE
   - Example: `type=17, value_length=0` for SET

### DER Parsing Rules

The command follows ASN.1 DER parsing standards:
- **Tag Detection**: Identifies ASN.1 type from the tag byte
- **Length Decoding**: Properly decodes length fields (short and long form)
- **Value Extraction**: Extracts value information based on type
- **Error Handling**: Graceful handling of malformed DER data

## See Also

- `::tossl::asn1::encode` - Encode ASN.1 types
- `::tossl::asn1::sequence_create` - Create ASN.1 SEQUENCE structures
- `::tossl::asn1::set_create` - Create ASN.1 SET structures
- `::tossl::asn1::text_to_oid` - Convert text to OID
- `::tossl::asn1::oid_to_text` - Convert OID to text
- `::tossl::x509::parse` - Parse X.509 certificates
- `::tossl::csr::parse` - Parse certificate signing requests

## Technical Notes

### Parsing Behavior

1. **Type Detection**: Automatically detects ASN.1 type from DER tag
2. **Value Extraction**: Extracts appropriate value information based on type
3. **Memory Management**: Proper cleanup of OpenSSL structures
4. **Error Recovery**: Graceful handling of parsing errors

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient DER parsing with minimal overhead

### Performance Characteristics

- **Time Complexity**: O(n) where n is the DER data size
- **Space Complexity**: O(1) for basic parsing operations
- **Memory Usage**: Minimal overhead beyond the parse result

### OpenSSL Integration

The command leverages OpenSSL's ASN.1 parsing capabilities:
- **Standard Compliance**: Follows ASN.1 and DER standards
- **Optimized Parsing**: Uses OpenSSL's efficient parsing functions
- **Type Safety**: Validates DER data before parsing
- **Interoperability**: Handles DER data from various sources

### Type Number Reference

| Type Number | ASN.1 Type | Description |
|-------------|------------|-------------|
| 2 | INTEGER | Signed integer values |
| 4 | OCTET STRING | Binary data or text strings |
| 6 | OBJECT IDENTIFIER | Object identifiers (OIDs) |
| 12 | UTF8String | Unicode text strings |
| 16 | SEQUENCE | Ordered collection of elements |
| 17 | SET | Unordered collection of elements |

### Value Length Interpretation

- **INTEGER**: Length of the encoded integer value
- **OCTET STRING**: Length of the string data
- **UTF8String**: Length of the UTF-8 encoded string
- **OBJECT IDENTIFIER**: Not applicable (returns OID text instead)
- **SEQUENCE/SET**: Length of the encoded structure (may be 0 for complex structures) 