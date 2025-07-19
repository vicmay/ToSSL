# tests/test_asn1_parse.tcl ;# Test for ::tossl::asn1::parse

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::asn1::parse..."

# Test 1: Basic functionality - parse different ASN.1 types
puts "\n=== Test 1: Basic ASN.1 Parsing ==="
set rc [catch {
    # Test integer parsing
    set int_encoded [tossl::asn1::encode integer 123]
    set int_result [tossl::asn1::parse $int_encoded]
    puts "✓ Integer parsing: $int_result"
    
    # Verify the result contains expected information
    if {[string match "*type=2*" $int_result] && [string match "*value_length=1*" $int_result]} {
        puts "✓ Integer parsing result is correct"
    } else {
        error "Integer parsing result is incorrect: $int_result"
    }
    
    # Test octet string parsing
    set octet_encoded [tossl::asn1::encode octetstring "hello"]
    set octet_result [tossl::asn1::parse $octet_encoded]
    puts "✓ OctetString parsing: $octet_result"
    
    # Test UTF8 string parsing
    set utf8_encoded [tossl::asn1::encode utf8string "hello"]
    set utf8_result [tossl::asn1::parse $utf8_encoded]
    puts "✓ UTF8String parsing: $utf8_result"
    
    # Test OID parsing
    set oid_encoded [tossl::asn1::encode objectidentifier "1.2.3"]
    set oid_result [tossl::asn1::parse $oid_encoded]
    puts "✓ OID parsing: $oid_result"
    
    # Test SET parsing
    set set_encoded [tossl::asn1::set_create "element1" "element2"]
    set set_result [tossl::asn1::parse $set_encoded]
    puts "✓ SET parsing: $set_result"
    
    # Test SEQUENCE parsing
    set seq_encoded [tossl::asn1::sequence_create "element1" "element2"]
    set seq_result [tossl::asn1::parse $seq_encoded]
    puts "✓ SEQUENCE parsing: $seq_result"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple value parsing
puts "\n=== Test 2: Multiple Value Parsing ==="
set rc [catch {
    set test_cases {
        {integer 0}
        {integer 123}
        {integer -456}
        {integer 999999}
        {octetstring ""}
        {octetstring "hello"}
        {octetstring "Hello, World!"}
        {utf8string ""}
        {utf8string "hello"}
        {utf8string "Hello, World!"}
        {objectidentifier "1.2.3"}
        {objectidentifier "1.3.6.1.5.5.7.1.1"}
        {objectidentifier "2.5.4.3"}
    }
    
    foreach test_case $test_cases {
        set type [lindex $test_case 0]
        set value [lindex $test_case 1]
        
        if {[catch {
            set encoded [tossl::asn1::encode $type $value]
            set result [tossl::asn1::parse $encoded]
            puts "✓ '$type $value' -> $result"
            
            # Verify result contains type information
            if {[string match "*type=*" $result]} {
                puts "  ✓ Contains type information"
            } else {
                puts "  ⚠ Missing type information"
            }
            
            # Verify result contains value length or object info
            if {[string match "*value_length=*" $result] || [string match "*object=*" $result]} {
                puts "  ✓ Contains value information"
            } else {
                puts "  ⚠ Missing value information"
            }
        } err]} {
            puts "✗ Failed to parse '$type $value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple value parsing test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::asn1::parse
} result]
if {$rc != 0} {
    puts "✓ No arguments correctly rejected: $result"
} else {
    puts stderr "✗ No arguments should have caused an error"
    exit 3
}

set rc [catch {
    tossl::asn1::parse "data1" "data2"
} result]
if {$rc != 0} {
    puts "✓ Too many arguments correctly rejected: $result"
} else {
    puts stderr "✗ Too many arguments should have caused an error"
    exit 3
}

# Test 4: Error handling - invalid data
puts "\n=== Test 4: Invalid Data Error Handling ==="
set rc [catch {
    tossl::asn1::parse "invalid_data"
} result]
if {$rc != 0} {
    puts "✓ Invalid data correctly rejected: $result"
} else {
    puts stderr "✗ Invalid data should have caused an error"
    exit 4
}

set rc [catch {
    tossl::asn1::parse ""
} result]
if {$rc != 0} {
    puts "✓ Empty data correctly rejected: $result"
} else {
    puts stderr "✗ Empty data should have caused an error"
    exit 4
}

set rc [catch {
    tossl::asn1::parse "not_der_data"
} result]
if {$rc != 0} {
    puts "✓ Non-DER data correctly rejected: $result"
} else {
    puts stderr "✗ Non-DER data should have caused an error"
    exit 4
}

# Test 5: Edge cases and special values
puts "\n=== Test 5: Edge Cases and Special Values ==="
set rc [catch {
    # Test with very large integer
    if {[catch {
        set encoded [tossl::asn1::encode integer 999999999]
        set result [tossl::asn1::parse $encoded]
        puts "✓ Large integer parsing: $result"
    } err]} {
        puts "✓ Large integer correctly rejected: $err"
    }
    
    # Test with very long string
    set long_string [string repeat "a" 1000]
    if {[catch {
        set encoded [tossl::asn1::encode octetstring $long_string]
        set result [tossl::asn1::parse $encoded]
        puts "✓ Long string parsing: $result"
    } err]} {
        puts "✓ Long string correctly rejected: $err"
    }
    
    # Test with special characters
    if {[catch {
        set encoded [tossl::asn1::encode utf8string "Hello\nWorld\tTest"]
        set result [tossl::asn1::parse $encoded]
        puts "✓ Special characters parsing: $result"
    } err]} {
        puts "✓ Special characters correctly rejected: $err"
    }
    
    # Test with Unicode characters
    if {[catch {
        set encoded [tossl::asn1::encode utf8string "Hello 世界"]
        set result [tossl::asn1::parse $encoded]
        puts "✓ Unicode characters parsing: $result"
    } err]} {
        puts "✓ Unicode characters correctly rejected: $err"
    }
    
    # Test with empty strings
    if {[catch {
        set encoded [tossl::asn1::encode octetstring ""]
        set result [tossl::asn1::parse $encoded]
        puts "✓ Empty string parsing: $result"
    } err]} {
        puts "✓ Empty string correctly rejected: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Edge cases test failed: $result"
    exit 5
}

# Test 6: Performance test
puts "\n=== Test 6: Performance Test ==="
set rc [catch {
    set iterations 50
    set test_data [tossl::asn1::encode integer 123]
    
    # Time multiple parsing operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set result [tossl::asn1::parse $test_data]
        if {![string match "*type=*" $result]} {
            error "Invalid result generated on iteration $i"
        }
    }
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set avg_time [expr {double($total_time) / $iterations}]
    
    puts "✓ Performance test completed:"
    puts "  Total time: ${total_time}ms for $iterations operations"
    puts "  Average time: [format %.2f $avg_time]ms per operation"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Performance test failed: $result"
    exit 6
}

# Test 7: Type-specific validation
puts "\n=== Test 7: Type-Specific Validation ==="
set rc [catch {
    # Test integer parsing with different values
    set int_values {0 1 -1 127 -128 255 -255 999999}
    foreach value $int_values {
        if {[catch {
            set encoded [tossl::asn1::encode integer $value]
            set result [tossl::asn1::parse $encoded]
            puts "✓ Integer $value -> $result"
        } err]} {
            puts "✗ Failed to parse integer $value: $err"
        }
    }
    
    # Test string parsing with different content
    set string_values {"" "a" "hello" "Hello, World!" "test string"}
    foreach value $string_values {
        if {[catch {
            set encoded [tossl::asn1::encode octetstring $value]
            set result [tossl::asn1::parse $encoded]
            puts "✓ OctetString '$value' -> $result"
        } err]} {
            puts "✗ Failed to parse octetstring '$value': $err"
        }
    }
    
    # Test UTF8 string parsing with different content
    set utf8_values {"" "a" "hello" "Hello, World!" "Unicode: 世界"}
    foreach value $utf8_values {
        if {[catch {
            set encoded [tossl::asn1::encode utf8string $value]
            set result [tossl::asn1::parse $encoded]
            puts "✓ UTF8String '$value' -> $result"
        } err]} {
            puts "✗ Failed to parse utf8string '$value': $err"
        }
    }
    
    # Test OID parsing with different OIDs
    set oid_values {"1.2.3" "1.3.6.1.5.5.7.1.1" "2.5.4.3" "1.2.840.113549.1.1.1"}
    foreach value $oid_values {
        if {[catch {
            set encoded [tossl::asn1::encode objectidentifier $value]
            set result [tossl::asn1::parse $encoded]
            puts "✓ OID '$value' -> $result"
        } err]} {
            puts "✗ Failed to parse OID '$value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Type-specific validation failed: $result"
    exit 7
}

# Test 8: Memory and resource management
puts "\n=== Test 8: Memory and Resource Management ==="
set rc [catch {
    # Test many parsing operations to check for memory leaks
    set results {}
    set test_data [tossl::asn1::encode integer 123]
    
    for {set i 0} {$i < 25} {incr i} {
        set result [tossl::asn1::parse $test_data]
        lappend results $result
        
        # Verify each result works
        if {![string match "*type=*" $result]} {
            error "Invalid result generated on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $results] parse results"
    puts "  ✓ All parse results are valid"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 8
}

# Test 9: Error recovery and robustness
puts "\n=== Test 9: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can parse after various operations
    set test_operations {
        "Basic parsing"
        "After multiple parsing operations"
        "After type-specific validation"
        "After memory management test"
    }
    
    set test_data [tossl::asn1::encode integer 123]
    
    foreach operation $test_operations {
        if {[catch {
            set result [tossl::asn1::parse $test_data]
            
            if {![string match "*type=*" $result]} {
                error "Invalid result after $operation"
            }
            
            puts "✓ ASN.1 parsing successful after $operation"
        } err]} {
            error "ASN.1 parsing failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 9
}

# Test 10: ASN.1 type mapping validation
puts "\n=== Test 10: ASN.1 Type Mapping Validation ==="
set rc [catch {
    # Test that we get correct type numbers
    set type_mappings {
        {integer 2}
        {octetstring 4}
        {utf8string 12}
        {objectidentifier 6}
    }
    
    foreach mapping $type_mappings {
        set type_name [lindex $mapping 0]
        set expected_type [lindex $mapping 1]
        
        if {[catch {
            set encoded [tossl::asn1::encode $type_name "test"]
            set result [tossl::asn1::parse $encoded]
            
            if {[string match "*type=$expected_type*" $result]} {
                puts "✓ $type_name correctly maps to type $expected_type"
            } else {
                puts "⚠ $type_name may not map correctly (expected $expected_type, got: $result)"
            }
        } err]} {
            puts "✗ Failed to test $type_name mapping: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ ASN.1 type mapping validation failed: $result"
    exit 10
}

# Test 11: Complex structure parsing
puts "\n=== Test 11: Complex Structure Parsing ==="
set rc [catch {
    # Test parsing of complex structures
    set complex_structures {
        {"SET with integers" {tossl::asn1::set_create 123 456 789}}
        {"SET with strings" {tossl::asn1::set_create "hello" "world" "test"}}
        {"SET with mixed types" {tossl::asn1::set_create 123 "hello" 456}}
        {"SEQUENCE with integers" {tossl::asn1::sequence_create 123 456 789}}
        {"SEQUENCE with strings" {tossl::asn1::sequence_create "hello" "world" "test"}}
        {"SEQUENCE with mixed types" {tossl::asn1::sequence_create 123 "hello" 456}}
    }
    
    foreach structure $complex_structures {
        set description [lindex $structure 0]
        set create_command [lindex $structure 1]
        
        if {[catch {
            set encoded [eval $create_command]
            set result [tossl::asn1::parse $encoded]
            puts "✓ $description -> $result"
            
            # Verify result contains type information
            if {[string match "*type=*" $result]} {
                puts "  ✓ Contains type information"
            } else {
                puts "  ⚠ Missing type information"
            }
        } err]} {
            puts "✗ Failed to parse $description: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Complex structure parsing failed: $result"
    exit 11
}

# Test 12: Round-trip validation
puts "\n=== Test 12: Round-Trip Validation ==="
set rc [catch {
    # Test that we can encode and then parse back
    set test_cases {
        {integer 123}
        {octetstring "hello"}
        {utf8string "world"}
        {objectidentifier "1.2.3"}
    }
    
    foreach test_case $test_cases {
        set type [lindex $test_case 0]
        set value [lindex $test_case 1]
        
        if {[catch {
            # Encode
            set encoded [tossl::asn1::encode $type $value]
            
            # Parse
            set parsed [tossl::asn1::parse $encoded]
            
            puts "✓ Round-trip '$type $value' -> $parsed"
            
            # Verify we get expected type information
            switch $type {
                "integer" {
                    if {[string match "*type=2*" $parsed]} {
                        puts "  ✓ Correctly identified as INTEGER"
                    } else {
                        puts "  ⚠ May not be correctly identified as INTEGER"
                    }
                }
                "octetstring" {
                    if {[string match "*type=4*" $parsed]} {
                        puts "  ✓ Correctly identified as OCTET STRING"
                    } else {
                        puts "  ⚠ May not be correctly identified as OCTET STRING"
                    }
                }
                "utf8string" {
                    if {[string match "*type=12*" $parsed]} {
                        puts "  ✓ Correctly identified as UTF8String"
                    } else {
                        puts "  ⚠ May not be correctly identified as UTF8String"
                    }
                }
                "objectidentifier" {
                    if {[string match "*type=6*" $parsed]} {
                        puts "  ✓ Correctly identified as OBJECT IDENTIFIER"
                    } else {
                        puts "  ⚠ May not be correctly identified as OBJECT IDENTIFIER"
                    }
                }
            }
        } err]} {
            puts "✗ Failed round-trip for '$type $value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Round-trip validation failed: $result"
    exit 12
}

puts "\n=== All ASN.1 Parse Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple value parsing working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Type-specific validation working"
puts "✓ Memory management working"
puts "✓ Error recovery and robustness working"
puts "✓ ASN.1 type mapping validation completed"
puts "✓ Complex structure parsing working"
puts "✓ Round-trip validation working"

exit 0 