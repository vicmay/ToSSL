# ::tossl::asn1::sequence_create

Create an ASN.1 SEQUENCE structure from multiple elements.

## Overview

`::tossl::asn1::sequence_create` creates an ASN.1 SEQUENCE structure containing multiple elements. The command automatically detects the type of each element (integer or octet string) and encodes them according to ASN.1 DER encoding rules. The resulting sequence is returned as a binary byte array that can be used in cryptographic operations, certificate structures, or other ASN.1-based protocols.

## Syntax

```
tossl::asn1::sequence_create element1 ?element2 ...?
```

### Parameters

- **element1, element2, ...**: One or more elements to include in the sequence. Each element can be:
  - An integer (positive or negative)
  - A string (including empty strings, special characters, and Unicode)

### Return Value

Returns a binary byte array containing the DER-encoded ASN.1 SEQUENCE structure.

## Example

```tcl
# Create a simple sequence with integer and string
set sequence [tossl::asn1::sequence_create 123 "hello"]

# Create a sequence with multiple elements
set complex_sequence [tossl::asn1::sequence_create 1 2 3 "test" 456]

# Create a sequence for certificate extensions
set extension_sequence [tossl::asn1::sequence_create "2.5.29.19" "basicConstraints"]

# Parse the created sequence
set parse_result [tossl::asn1::parse $sequence]
puts "Sequence structure: $parse_result"
```

## ASN.1 Structure

The command creates a proper ASN.1 SEQUENCE with the following structure:

```
SEQUENCE {
    element1,
    element2,
    ...
}
```

### Encoding Details

- **Tag**: 0x30 (SEQUENCE)
- **Length**: Variable-length encoding (short form for < 128 bytes, long form for ≥ 128 bytes)
- **Elements**: Each element is encoded according to its detected type:
  - **Integers**: ASN.1 INTEGER (tag 0x02)
  - **Strings**: ASN.1 OCTET STRING (tag 0x04)

## Error Handling

- Returns an error if no elements are provided
- Returns an error if memory allocation fails
- Returns an error if sequence encoding fails
- Returns an error if sequence length exceeds reasonable limits (> 16MB)

## Advanced Usage

### Creating Certificate Extensions

```tcl
# Create a basic constraints extension sequence
proc create_basic_constraints_extension {critical} {
    set oid "2.5.29.19"
    set value [tossl::asn1::sequence_create $critical]
    return [tossl::asn1::sequence_create $oid $value]
}

# Usage
set extension [create_basic_constraints_extension 1]
puts "Extension length: [string length $extension] bytes"
```

### Creating Complex ASN.1 Structures

```tcl
# Create a nested sequence structure
proc create_nested_sequence {outer_elements inner_elements} {
    set inner_seq [tossl::asn1::sequence_create {*}$inner_elements]
    set outer_seq [tossl::asn1::sequence_create {*}$outer_elements $inner_seq]
    return $outer_seq
}

# Usage
set nested [create_nested_sequence {1 2 3} {4 5 6}]
puts "Nested sequence length: [string length $nested] bytes"
```

### Batch Sequence Creation

```tcl
# Create multiple sequences efficiently
proc create_multiple_sequences {element_lists} {
    set sequences {}
    foreach elements $element_lists {
        set seq [tossl::asn1::sequence_create {*}$elements]
        lappend sequences $seq
    }
    return $sequences
}

# Usage
set element_lists {
    {1 2 3}
    {4 5 6}
    {7 8 9}
}
set sequences [create_multiple_sequences $element_lists]
puts "Created [llength $sequences] sequences"
```

## Performance Considerations

- **Efficient Implementation**: Uses OpenSSL's optimized ASN.1 encoding functions
- **Memory Management**: Proper memory allocation and cleanup
- **Batch Processing**: Can handle multiple sequence creation operations efficiently

### Performance Monitoring

```tcl
# Monitor sequence creation performance
proc benchmark_sequence_creation {iterations element_count} {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < $iterations} {incr i} {
        set elements {}
        for {set j 0} {$j < $element_count} {incr j} {
            lappend elements $j
            lappend elements "element$j"
        }
        set seq [tossl::asn1::sequence_create {*}$elements]
        if {[string length $seq] == 0} {
            error "Empty sequence generated on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set avg_time [expr {double($total_time) / $iterations}]
    
    return [dict create \
        total_time $total_time \
        average_time $avg_time \
        operations_per_second [expr {double($iterations) * 1000 / $total_time}]]
}

# Usage
set benchmark [benchmark_sequence_creation 100 10]
puts "Average sequence creation time: [dict get $benchmark average_time]ms"
puts "Operations per second: [format %.2f [dict get $benchmark operations_per_second]]"
```

## Integration Examples

### Certificate Authority Operations

```tcl
# Create certificate extension sequences
proc create_certificate_extensions {subject_alt_names} {
    set extensions {}
    
    # Basic constraints extension
    set basic_constraints [tossl::asn1::sequence_create "2.5.29.19" "CA:TRUE"]
    lappend extensions $basic_constraints
    
    # Subject alternative names extension
    if {[llength $subject_alt_names] > 0} {
        set san_sequence [tossl::asn1::sequence_create {*}$subject_alt_names]
        set san_extension [tossl::asn1::sequence_create "2.5.29.17" $san_sequence]
        lappend extensions $san_extension
    }
    
    return $extensions
}

# Usage
set alt_names {"DNS:example.com" "DNS:www.example.com"}
set extensions [create_certificate_extensions $alt_names]
puts "Created [llength $extensions] certificate extensions"
```

### Cryptographic Protocol Implementation

```tcl
# Create ASN.1 structures for cryptographic protocols
proc create_digital_signature_structure {algorithm_id signature_value} {
    set signature_algorithm [tossl::asn1::sequence_create $algorithm_id "NULL"]
    set signature [tossl::asn1::sequence_create $signature_algorithm $signature_value]
    return $signature
}

# Usage
set algorithm_id "1.2.840.113549.1.1.11"  ;# SHA-256 with RSA
set signature_value "base64_encoded_signature_here"
set signature_structure [create_digital_signature_structure $algorithm_id $signature_value]
puts "Signature structure length: [string length $signature_structure] bytes"
```

### Data Serialization

```tcl
# Create ASN.1 sequences for data serialization
proc serialize_user_data {user_id name email permissions} {
    set user_sequence [tossl::asn1::sequence_create $user_id $name $email]
    set permissions_sequence [tossl::asn1::sequence_create {*}$permissions]
    set complete_sequence [tossl::asn1::sequence_create $user_sequence $permissions_sequence]
    return $complete_sequence
}

# Usage
set user_id 12345
set name "John Doe"
set email "john.doe@example.com"
set permissions {"read" "write" "execute"}
set serialized_data [serialize_user_data $user_id $name $email $permissions]
puts "Serialized data length: [string length $serialized_data] bytes"
```

## Troubleshooting

### Common Issues

1. **"wrong # args" error**
   - Ensure at least one element is provided
   - Check argument syntax

2. **"Memory allocation failed" error**
   - Check system memory availability
   - Reduce sequence size if too large

3. **"Sequence too long for encoding" error**
   - Sequence exceeds 16MB limit
   - Break into smaller sequences

4. **"Failed to encode ASN.1 sequence" error**
   - Check element types and values
   - Verify OpenSSL installation

### Debug Information

```tcl
# Debug sequence creation process
proc debug_sequence_creation {elements} {
    puts "Debug: Creating sequence with [llength $elements] elements"
    
    if {[catch {
        set start_time [clock milliseconds]
        set sequence [tossl::asn1::sequence_create {*}$elements]
        set end_time [clock milliseconds]
        
        puts "Debug: Sequence creation successful"
        puts "Debug: Creation time: [expr {$end_time - $start_time}]ms"
        puts "Debug: Sequence length: [string length $sequence] bytes"
        
        # Validate ASN.1 structure
        set first_byte [scan [string index $sequence 0] %c]
        if {$first_byte == 48} {
            puts "Debug: Sequence has correct ASN.1 SEQUENCE tag (0x30)"
        } else {
            puts "Debug: Sequence may have incorrect ASN.1 structure"
        }
        
        # Parse the sequence
        set parse_result [tossl::asn1::parse $sequence]
        puts "Debug: Parse result: $parse_result"
        
        return $sequence
    } err]} {
        puts "Debug: Sequence creation failed: $err"
        return ""
    }
}

# Usage
set test_elements {123 "hello" 456 "world"}
set debug_sequence [debug_sequence_creation $test_elements]
```

## ASN.1 Standards Compliance

- **X.690**: DER encoding rules compliance
- **RFC 5280**: Certificate and CRL profile compatibility
- **RFC 5912**: New ASN.1 modules for PKIX compatibility
- **OpenSSL Compatibility**: Uses OpenSSL's ASN.1 implementation

### Encoding Rules

- **Tag-Length-Value (TLV)**: Standard ASN.1 encoding
- **Length Encoding**: Short form (< 128 bytes) and long form (≥ 128 bytes)
- **Big-Endian**: Network byte order for multi-byte values
- **Definite Length**: All lengths are explicitly encoded

## See Also

- `::tossl::asn1::parse` - Parse ASN.1 structures
- `::tossl::asn1::encode` - Encode ASN.1 types
- `::tossl::asn1::set_create` - Create ASN.1 SET structures
- `::tossl::asn1::oid_to_text` - Convert OID to text
- `::tossl::asn1::text_to_oid` - Convert text to OID
- `::tossl::x509::create` - Create X.509 certificates
- `::tossl::csr::create` - Create certificate signing requests

## Technical Notes

### Element Type Detection

The command automatically detects element types:

1. **Integer Detection**: Attempts to parse as decimal integer
   - Supports positive and negative integers
   - Handles zero values correctly
   - Limited by system integer size

2. **String Detection**: All non-integer values are treated as octet strings
   - Supports empty strings
   - Handles special characters and Unicode
   - No length limitations (within sequence limits)

### Memory Management

- **Automatic Cleanup**: All OpenSSL structures are properly freed
- **Error Recovery**: Memory is cleaned up even on errors
- **Buffer Management**: Efficient buffer allocation and deallocation

### Performance Characteristics

- **Time Complexity**: O(n) where n is the number of elements
- **Space Complexity**: O(n) for the resulting sequence
- **Memory Usage**: Minimal overhead beyond the encoded data 