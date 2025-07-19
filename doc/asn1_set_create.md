# ::tossl::asn1::set_create

Create ASN.1 SET structures.

## Overview

`::tossl::asn1::set_create` creates ASN.1 SET structures from multiple elements. Unlike SEQUENCE, which maintains order, SET structures are unordered collections of elements. The command automatically detects the type of each element (integer or string) and creates a properly encoded ASN.1 SET structure in DER format. This is useful for creating certificate extensions, attribute sets, and other ASN.1 structures that require SET encoding.

## Syntax

```
tossl::asn1::set_create element1 ?element2 ...?
```

### Parameters

- **element1**: The first element to include in the SET
- **element2...**: Additional elements to include in the SET (optional)

### Return Value

Returns a binary string containing the DER-encoded ASN.1 SET structure.

## Example

```tcl
# Create a single element set
set single_set [tossl::asn1::set_create "element1"]
puts "Single element set: [string length $single_set] bytes"

# Create a two element set
set two_set [tossl::asn1::set_create "element1" "element2"]
puts "Two element set: [string length $two_set] bytes"

# Create a set with integers
set int_set [tossl::asn1::set_create 123 456 789]
puts "Integer set: [string length $int_set] bytes"

# Create a mixed set
set mixed_set [tossl::asn1::set_create 123 "hello" 456]
puts "Mixed set: [string length $mixed_set] bytes"

# Create a set with many elements
set many_set [tossl::asn1::set_create "first" "second" "third" "fourth" "fifth"]
puts "Many element set: [string length $many_set] bytes"
```

## Supported Element Types

### INTEGER

Integer values are automatically detected and encoded as ASN.1 INTEGER type.

```tcl
# Positive integers
set pos_set [tossl::asn1::set_create 123 456 789]
puts "Positive integer set: [string length $pos_set] bytes"

# Negative integers
set neg_set [tossl::asn1::set_create -123 -456 -789]
puts "Negative integer set: [string length $neg_set] bytes"

# Mixed positive and negative
set mixed_int_set [tossl::asn1::set_create 123 -456 789]
puts "Mixed integer set: [string length $mixed_int_set] bytes"

# Large integers
set large_set [tossl::asn1::set_create 999999 123456789]
puts "Large integer set: [string length $large_set] bytes"
```

### OCTET STRING

String values are automatically encoded as ASN.1 OCTET STRING type.

```tcl
# Regular strings
set str_set [tossl::asn1::set_create "hello" "world" "test"]
puts "String set: [string length $str_set] bytes"

# Empty strings
set empty_set [tossl::asn1::set_create "" "non-empty"]
puts "Empty string set: [string length $empty_set] bytes"

# Long strings
set long_set [tossl::asn1::set_create "short" "medium length string" "very long string"]
puts "Long string set: [string length $long_set] bytes"

# Special characters
set special_set [tossl::asn1::set_create "Hello\nWorld" "Test\tString"]
puts "Special character set: [string length $special_set] bytes"

# Unicode strings
set unicode_set [tossl::asn1::set_create "Hello 世界" "Unicode Test"]
puts "Unicode set: [string length $unicode_set] bytes"
```

### Mixed Types

The command supports mixing integers and strings in the same SET.

```tcl
# Mixed integer and string set
set mixed_set [tossl::asn1::set_create 123 "hello" -456 "world" 789]
puts "Mixed set: [string length $mixed_set] bytes"

# Complex mixed set
set complex_set [tossl::asn1::set_create 0 "zero" 1 "one" -1 "negative" 999999 "large"]
puts "Complex mixed set: [string length $complex_set] bytes"
```

## Error Handling

- Returns an error if no elements are provided
- Returns an error if memory allocation fails
- Returns an error if the SET is too long for encoding
- Returns an error if element creation fails

## Advanced Usage

### Batch SET Creation

```tcl
# Create multiple sets efficiently
proc create_multiple_sets {set_definitions} {
    set results {}
    foreach set_def $set_definitions {
        set elements [lindex $set_def 0]
        set description [lindex $set_def 1]
        
        if {[catch {
            set result [tossl::asn1::set_create {*}$elements]
            lappend results [dict create \
                description $description \
                elements $elements \
                result $result \
                length [string length $result]]
        } err]} {
            lappend results [dict create \
                description $description \
                elements $elements \
                error $err]
        }
    }
    return $results
}

# Usage
set set_definitions {
    {{123 456 789} "Integer set"}
    {{"hello" "world"} "String set"}
    {{123 "hello" 456} "Mixed set"}
    {{"first" "second" "third" "fourth" "fifth"} "Large set"}
}
set results [create_multiple_sets $set_definitions]
foreach result $results {
    if {[dict exists $result error]} {
        puts "[dict get $result description]: ERROR - [dict get $result error]"
    } else {
        puts "[dict get $result description]: [dict get $result length] bytes"
    }
}
```

### SET vs SEQUENCE Comparison

```tcl
# Compare SET and SEQUENCE structures
proc compare_set_sequence {elements} {
    set set_result [tossl::asn1::set_create {*}$elements]
    set seq_result [tossl::asn1::sequence_create {*}$elements]
    
    puts "Elements: $elements"
    puts "SET length: [string length $set_result] bytes"
    puts "SEQUENCE length: [string length $seq_result] bytes"
    
    # Check tags
    set set_tag [scan [string index $set_result 0] %c]
    set seq_tag [scan [string index $seq_result 0] %c]
    
    puts "SET tag: 0x[format %02x $set_tag] (should be 0x31)"
    puts "SEQUENCE tag: 0x[format %02x $seq_tag] (should be 0x30)"
    
    return [dict create \
        set_result $set_result \
        seq_result $seq_result \
        set_tag $set_tag \
        seq_tag $seq_tag]
}

# Usage
set test_elements {"element1" "element2" "element3"}
set comparison [compare_set_sequence $test_elements]
```

### Certificate Extension SET Creation

```tcl
# Create certificate extension SET structures
proc create_extension_set {extensions} {
    set encoded_extensions {}
    foreach ext $extensions {
        set oid [dict get $ext oid]
        set value [dict get $ext value]
        set critical [dict get $ext critical]
        
        # Create extension structure
        set ext_elements [list $oid $value $critical]
        if {[catch {
            set ext_set [tossl::asn1::set_create {*}$ext_elements]
            lappend encoded_extensions [dict create \
                oid $oid \
                value $value \
                critical $critical \
                set_data $ext_set \
                length [string length $ext_set]]
        } err]} {
            puts "Warning: Failed to create extension for $oid: $err"
        }
    }
    return $encoded_extensions
}

# Usage
set extensions {
    {oid "2.5.29.19" value "CA:TRUE" critical true}
    {oid "2.5.29.15" value "Digital Signature" critical false}
    {oid "2.5.29.17" value "DNS:example.com" critical false}
}
set encoded_exts [create_extension_set $extensions]
foreach ext $encoded_exts {
    puts "[dict get $ext oid]: [dict get $ext length] bytes"
}
```

### Attribute SET Creation

```tcl
# Create attribute SET structures
proc create_attribute_set {attributes} {
    set encoded_attributes {}
    foreach attr $attributes {
        set type [dict get $attr type]
        set values [dict get $attr values]
        
        # Create attribute structure
        set attr_elements [linsert $values 0 $type]
        if {[catch {
            set attr_set [tossl::asn1::set_create {*}$attr_elements]
            lappend encoded_attributes [dict create \
                type $type \
                values $values \
                set_data $attr_set \
                length [string length $attr_set]]
        } err]} {
            puts "Warning: Failed to create attribute for $type: $err"
        }
    }
    return $encoded_attributes
}

# Usage
set attributes {
    {type "2.5.4.3" values {"Common Name" "Example Corp"}}
    {type "2.5.4.6" values {"Country" "US"}}
    {type "2.5.4.10" values {"Organization" "Example Organization"}}
}
set encoded_attrs [create_attribute_set $attributes]
foreach attr $encoded_attrs {
    puts "[dict get $attr type]: [dict get $attr length] bytes"
}
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized ASN.1 encoding functions
- **Memory Management**: Proper memory allocation and cleanup
- **DER Compliance**: Produces standard DER-encoded output
- **Type Detection**: Automatic type detection for integers and strings

### Performance Monitoring

```tcl
# Monitor ASN.1 SET creation performance
proc benchmark_set_creation {iterations element_lists} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        foreach element_list $element_lists {
            set result [tossl::asn1::set_create {*}$element_list]
            if {[string length $result] == 0} {
                error "Empty result for $element_list"
            }
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set total_operations [expr {$iterations * [llength $element_lists]}]
    set avg_time [expr {double($total_time) / $total_operations}]
    
    return [dict create \
        total_time $total_time \
        total_operations $total_operations \
        average_time $avg_time \
        operations_per_second [expr {double($total_operations) * 1000 / $total_time}]]
}

# Usage
set test_lists {
    {"element1" "element2"}
    {123 456 789}
    {"hello" "world" "test"}
    {123 "hello" 456}
}
set benchmark [benchmark_set_creation 25 $test_lists]
puts "Average SET creation time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Create certificate attribute SETs
proc create_certificate_attributes {subject_info} {
    set attribute_sets {}
    
    foreach {attr_type attr_values} $subject_info {
        if {[catch {
            set attr_elements [linsert $attr_values 0 $attr_type]
            set attr_set [tossl::asn1::set_create {*}$attr_elements]
            
            lappend attribute_sets [dict create \
                type $attr_type \
                values $attr_values \
                set_data $attr_set \
                length [string length $attr_set]]
        } err]} {
            puts "Warning: Failed to create attribute for $attr_type: $err"
        }
    }
    
    return $attribute_sets
}

# Usage
set subject_info {
    "2.5.4.3" {"Common Name" "Example Corp"}
    "2.5.4.6" {"Country" "US"}
    "2.5.4.10" {"Organization" "Example Organization"}
    "2.5.4.11" {"Organizational Unit" "IT Department"}
}
set attributes [create_certificate_attributes $subject_info]
foreach attr $attributes {
    puts "[dict get $attr type]: [dict get $attr length] bytes"
}
```

### Cryptographic Algorithm SET Creation

```tcl
# Create algorithm identifier SETs
proc create_algorithm_set {algorithms} {
    set encoded_algorithms {}
    foreach alg $algorithms {
        set oid [dict get $alg oid]
        set parameters [dict get $alg parameters]
        
        # Create algorithm structure
        if {$parameters ne ""} {
            set alg_elements [list $oid $parameters]
        } else {
            set alg_elements [list $oid]
        }
        
        if {[catch {
            set alg_set [tossl::asn1::set_create {*}$alg_elements]
            lappend encoded_algorithms [dict create \
                oid $oid \
                parameters $parameters \
                set_data $alg_set \
                length [string length $alg_set]]
        } err]} {
            puts "Warning: Failed to create algorithm for $oid: $err"
        }
    }
    return $encoded_algorithms
}

# Usage
set algorithms {
    {oid "1.2.840.113549.1.1.1" parameters ""}
    {oid "1.2.840.113549.1.1.11" parameters ""}
    {oid "1.2.840.10045.2.1" parameters "1.2.840.10045.3.1.7"}
}
set encoded_algs [create_algorithm_set $algorithms]
foreach alg $encoded_algs {
    puts "[dict get $alg oid]: [dict get $alg length] bytes"
}
```

### ASN.1 Structure Creation

```tcl
# Create complex ASN.1 structures with SETs
proc create_complex_asn1_structure {structure_definition} {
    set encoded_structure {}
    
    foreach component $structure_definition {
        set type [dict get $component type]
        set elements [dict get $component elements]
        
        switch $type {
            "set" {
                if {[catch {
                    set result [tossl::asn1::set_create {*}$elements]
                    lappend encoded_structure [dict create \
                        type $type \
                        elements $elements \
                        result $result \
                        length [string length $result]]
                } err]} {
                    puts "Warning: Failed to create SET: $err"
                }
            }
            "sequence" {
                if {[catch {
                    set result [tossl::asn1::sequence_create {*}$elements]
                    lappend encoded_structure [dict create \
                        type $type \
                        elements $elements \
                        result $result \
                        length [string length $result]]
                } err]} {
                    puts "Warning: Failed to create SEQUENCE: $err"
                }
            }
            default {
                puts "Warning: Unknown structure type: $type"
            }
        }
    }
    
    return $encoded_structure
}

# Usage
set structure_def {
    {type "set" elements {"attribute1" "value1" "attribute2" "value2"}}
    {type "sequence" elements {"element1" "element2" "element3"}}
    {type "set" elements {123 456 789}}
}
set structure [create_complex_asn1_structure $structure_def]
foreach comp $structure {
    puts "[dict get $comp type]: [dict get $comp length] bytes"
}
```

## Troubleshooting

### Common Issues

1. **"wrong # args" error**
   - Ensure at least one element is provided
   - Check argument syntax

2. **"Memory allocation failed" error**
   - Check available system memory
   - Reduce the number or size of elements

3. **"Set too long for encoding" error**
   - Reduce the number of elements
   - Use shorter element values

4. **Empty result**
   - Verify that elements are valid
   - Check that elements can be encoded

### Debug Information

```tcl
# Debug ASN.1 SET creation process
proc debug_set_creation {elements} {
    puts "Debug: Creating SET with elements: $elements"
    
    if {[catch {
        set start_time [clock milliseconds]
        set result [tossl::asn1::set_create {*}$elements]
        set end_time [clock milliseconds]
        
        puts "Debug: SET creation successful"
        puts "Debug: Creation time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Result length: [string length $result] bytes"
        
        # Validate result
        if {[string length $result] >= 2} {
            puts "Debug: Result has minimum DER structure"
        } else {
            puts "Debug: Result may be too short"
        }
        
        # Check SET tag
        set first_byte [scan [string index $result 0] %c]
        if {$first_byte == 49} {  ;# 0x31
            puts "Debug: Has correct SET tag (0x31)"
        } else {
            puts "Debug: May not have correct SET tag (got: 0x[format %02x $first_byte])"
        }
        
        return $result
    } err]} {
        puts "Debug: SET creation failed: $err"
        return ""
    }
}

# Usage
set test_elements {"element1" "element2" "element3"}
set result [debug_set_creation $test_elements]
puts "Final result: [string length $result] bytes"
```

## ASN.1 Standards and SET Encoding

### SET vs SEQUENCE

- **SET**: Unordered collection of elements (tag 0x31)
- **SEQUENCE**: Ordered collection of elements (tag 0x30)
- **Encoding**: Both use similar DER encoding but with different tags

### Supported Element Types

1. **INTEGER**: Automatically detected for numeric values
2. **OCTET STRING**: Automatically used for string values
3. **Mixed Types**: Support for combining integers and strings

### DER Encoding Rules

The command produces DER-encoded output following ASN.1 standards:
- **SET Tag**: 0x31 identifies the structure as a SET
- **Length**: Length field indicates the size of all elements
- **Elements**: Each element is encoded according to its type
- **Canonical**: DER ensures canonical encoding for interoperability

### Type Detection Logic

1. **INTEGER Detection**: Values that can be parsed as integers
2. **OCTET STRING Detection**: Values that cannot be parsed as integers
3. **Automatic Conversion**: No manual type specification required

## See Also

- `::tossl::asn1::sequence_create` - Create ASN.1 SEQUENCE structures
- `::tossl::asn1::encode` - Encode ASN.1 types
- `::tossl::asn1::parse` - Parse ASN.1 structures
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::csr::create` - Create certificate signing requests

## Technical Notes

### SET Creation Behavior

1. **Element Order**: Elements are processed in the order provided
2. **Type Detection**: Automatic detection of integer vs string types
3. **Memory Management**: Proper cleanup of OpenSSL structures
4. **Error Handling**: Graceful handling of invalid elements

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient DER encoding with minimal overhead

### Performance Characteristics

- **Time Complexity**: O(n) where n is the number of elements
- **Space Complexity**: O(n) where n is the total size of elements
- **Memory Usage**: Minimal overhead beyond the DER output

### OpenSSL Integration

The command leverages OpenSSL's ASN.1 encoding capabilities:
- **Standard Compliance**: Follows ASN.1 and DER standards
- **Optimized Encoding**: Uses OpenSSL's efficient encoding functions
- **Type Safety**: Validates elements before encoding
- **Interoperability**: Produces standard DER output compatible with other systems

### SET vs SEQUENCE Differences

| Feature | SET | SEQUENCE |
|---------|-----|----------|
| Tag | 0x31 | 0x30 |
| Order | Unordered | Ordered |
| Use Case | Attribute sets | Structured data |
| Encoding | Similar DER | Similar DER |

### Element Type Support

| Input Type | ASN.1 Type | Detection Method |
|------------|------------|------------------|
| Integer | INTEGER | `strtol()` parsing |
| String | OCTET STRING | Non-integer values |
| Mixed | Both | Automatic per element | 