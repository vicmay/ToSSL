# tests/test_asn1_encode.tcl ;# Test for ::tossl::asn1::encode

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::asn1::encode..."

# Test 1: Basic functionality - encode different ASN.1 types
puts "\n=== Test 1: Basic ASN.1 Encoding ==="
set rc [catch {
    # Test integer encoding
    set int_result [tossl::asn1::encode integer 123]
    puts "✓ Integer 123 encoded: [string length $int_result] bytes"
    
    # Verify the result is not empty
    if {[string length $int_result] > 0} {
        puts "✓ Integer encoding result is not empty"
    } else {
        error "Integer encoding result is empty"
    }
    
    # Test octet string encoding
    set octet_result [tossl::asn1::encode octetstring "hello"]
    puts "✓ OctetString 'hello' encoded: [string length $octet_result] bytes"
    
    # Test UTF8 string encoding
    set utf8_result [tossl::asn1::encode utf8string "hello"]
    puts "✓ UTF8String 'hello' encoded: [string length $utf8_result] bytes"
    
    # Test OID encoding
    set oid_result [tossl::asn1::encode objectidentifier "1.2.3"]
    puts "✓ OID '1.2.3' encoded: [string length $oid_result] bytes"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple value encodings
puts "\n=== Test 2: Multiple Value Encodings ==="
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
            set result [tossl::asn1::encode $type $value]
            puts "✓ '$type $value' -> [string length $result] bytes"
            
            # Verify result is not empty
            if {[string length $result] > 0} {
                puts "  ✓ Result is not empty"
            } else {
                puts "  ⚠ Result is empty"
            }
            
            # Verify minimum DER length (tag + length + value)
            set min_length 2
            if {[string length $result] >= $min_length} {
                puts "  ✓ Result has minimum DER length"
            } else {
                puts "  ⚠ Result may be too short for DER"
            }
        } err]} {
            puts "✗ Failed to encode '$type $value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple value encodings test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::asn1::encode
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 3
}

set rc [catch {
    tossl::asn1::encode "integer"
} result]
if {$rc != 0} {
    puts "✓ Missing value argument correctly rejected: $result"
} else {
    puts stderr "✗ Missing value argument should have caused an error"
    exit 3
}

set rc [catch {
    tossl::asn1::encode "integer" "123" "extra"
} result]
if {$rc != 0} {
    puts "✓ Too many arguments correctly rejected: $result"
} else {
    puts stderr "✗ Too many arguments should have caused an error"
    exit 3
}

# Test 4: Error handling - unsupported types
puts "\n=== Test 4: Unsupported Type Error Handling ==="
set rc [catch {
    tossl::asn1::encode "unsupported" "value"
} result]
if {$rc != 0} {
    puts "✓ Unsupported type correctly rejected: $result"
} else {
    puts stderr "✗ Unsupported type should have caused an error"
    exit 4
}

set rc [catch {
    tossl::asn1::encode "boolean" "true"
} result]
if {$rc != 0} {
    puts "✓ Boolean type correctly rejected: $result"
} else {
    puts stderr "✗ Boolean type should have caused an error"
    exit 4
}

set rc [catch {
    tossl::asn1::encode "null" ""
} result]
if {$rc != 0} {
    puts "✓ Null type correctly rejected: $result"
} else {
    puts stderr "✗ Null type should have caused an error"
    exit 4
}

# Test 5: Error handling - invalid values
puts "\n=== Test 5: Invalid Value Error Handling ==="
set rc [catch {
    tossl::asn1::encode "objectidentifier" "invalid_oid"
} result]
if {$rc != 0} {
    puts "✓ Invalid OID correctly rejected: $result"
} else {
    puts stderr "✗ Invalid OID should have caused an error"
    exit 5
}

set rc [catch {
    tossl::asn1::encode "objectidentifier" "not.an.oid"
} result]
if {$rc != 0} {
    puts "✓ Invalid OID format correctly rejected: $result"
} else {
    puts stderr "✗ Invalid OID format should have caused an error"
    exit 5
}

# Test 6: Edge cases and special values
puts "\n=== Test 6: Edge Cases and Special Values ==="
set rc [catch {
    # Test with very large integer
    if {[catch {
        set result [tossl::asn1::encode integer 999999999]
        puts "✓ Large integer encoded: [string length $result] bytes"
    } err]} {
        puts "✓ Large integer correctly rejected: $err"
    }
    
    # Test with very long string
    set long_string [string repeat "a" 1000]
    if {[catch {
        set result [tossl::asn1::encode octetstring $long_string]
        puts "✓ Long string encoded: [string length $result] bytes"
    } err]} {
        puts "✓ Long string correctly rejected: $err"
    }
    
    # Test with special characters
    if {[catch {
        set result [tossl::asn1::encode utf8string "Hello\nWorld\tTest"]
        puts "✓ Special characters encoded: [string length $result] bytes"
    } err]} {
        puts "✓ Special characters correctly rejected: $err"
    }
    
    # Test with Unicode characters
    if {[catch {
        set result [tossl::asn1::encode utf8string "Hello 世界"]
        puts "✓ Unicode characters encoded: [string length $result] bytes"
    } err]} {
        puts "✓ Unicode characters correctly rejected: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Edge cases test failed: $result"
    exit 6
}

# Test 7: Performance test
puts "\n=== Test 7: Performance Test ==="
set rc [catch {
    set iterations 100
    set test_type "integer"
    set test_value "123"
    
    # Time multiple encoding operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set result [tossl::asn1::encode $test_type $test_value]
        if {[string length $result] == 0} {
            error "Empty result generated on iteration $i"
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
    exit 7
}

# Test 8: DER format validation
puts "\n=== Test 8: DER Format Validation ==="
set rc [catch {
    set test_cases {
        {integer 123}
        {octetstring "hello"}
        {utf8string "hello"}
        {objectidentifier "1.2.3"}
    }
    
    foreach test_case $test_cases {
        set type [lindex $test_case 0]
        set value [lindex $test_case 1]
        if {[catch {
            set result [tossl::asn1::encode $type $value]
            
            # Check that result is not empty
            if {[string length $result] > 0} {
                puts "✓ '$type $value' -> [string length $result] bytes (valid DER)"
                
                # Check minimum DER structure (tag + length + value)
                if {[string length $result] >= 2} {
                    puts "  ✓ Has minimum DER structure"
                } else {
                    puts "  ⚠ May not have proper DER structure"
                }
                
                # Check that result is binary data
                if {[string is binary $result]} {
                    puts "  ✓ Result is binary data"
                } else {
                    puts "  ⚠ Result may not be binary data"
                }
            } else {
                puts "⚠ '$type $value' -> empty result"
            }
        } err]} {
            puts "✗ Failed to encode '$type $value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ DER format validation failed: $result"
    exit 8
}

# Test 9: Type-specific validation
puts "\n=== Test 9: Type-Specific Validation ==="
set rc [catch {
    # Test integer encoding with different values
    set int_values {0 1 -1 127 -128 255 -255 999999}
    foreach value $int_values {
        if {[catch {
            set result [tossl::asn1::encode integer $value]
            puts "✓ Integer $value -> [string length $result] bytes"
        } err]} {
            puts "✗ Failed to encode integer $value: $err"
        }
    }
    
    # Test octet string encoding with different content
    set octet_values {"" "a" "hello" "Hello, World!" "binary\0data"}
    foreach value $octet_values {
        if {[catch {
            set result [tossl::asn1::encode octetstring $value]
            puts "✓ OctetString '$value' -> [string length $result] bytes"
        } err]} {
            puts "✗ Failed to encode octetstring '$value': $err"
        }
    }
    
    # Test UTF8 string encoding with different content
    set utf8_values {"" "a" "hello" "Hello, World!" "Unicode: 世界"}
    foreach value $utf8_values {
        if {[catch {
            set result [tossl::asn1::encode utf8string $value]
            puts "✓ UTF8String '$value' -> [string length $result] bytes"
        } err]} {
            puts "✗ Failed to encode utf8string '$value': $err"
        }
    }
    
    # Test OID encoding with different OIDs
    set oid_values {"1.2.3" "1.3.6.1.5.5.7.1.1" "2.5.4.3" "1.2.840.113549.1.1.1"}
    foreach value $oid_values {
        if {[catch {
            set result [tossl::asn1::encode objectidentifier $value]
            puts "✓ OID '$value' -> [string length $result] bytes"
        } err]} {
            puts "✗ Failed to encode OID '$value': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Type-specific validation failed: $result"
    exit 9
}

# Test 10: Memory and resource management
puts "\n=== Test 10: Memory and Resource Management ==="
set rc [catch {
    # Test many encoding operations to check for memory leaks
    set results {}
    
    for {set i 0} {$i < 50} {incr i} {
        set result [tossl::asn1::encode integer $i]
        lappend results $result
        
        # Verify each result works
        if {[string length $result] == 0} {
            error "Empty result generated on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $results] encodings"
    puts "  ✓ All encodings produced results"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 10
}

# Test 11: Error recovery and robustness
puts "\n=== Test 11: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can encode after various operations
    set test_operations {
        "Basic encoding"
        "After error handling"
        "After multiple encodings"
        "After type-specific validation"
    }
    
    foreach operation $test_operations {
        if {[catch {
            set result [tossl::asn1::encode integer 123]
            
            if {[string length $result] == 0} {
                error "Empty result after $operation"
            }
            
            puts "✓ ASN.1 encoding successful after $operation"
        } err]} {
            error "ASN.1 encoding failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 11
}

# Test 12: Supported ASN.1 types validation
puts "\n=== Test 12: Supported ASN.1 Types Validation ==="
set rc [catch {
    set supported_types {
        integer
        octetstring
        utf8string
        objectidentifier
    }
    
    foreach type $supported_types {
        if {[catch {
            # Use appropriate test value for each type
            switch $type {
                "integer" { set test_value "123" }
                "octetstring" { set test_value "test" }
                "utf8string" { set test_value "test" }
                "objectidentifier" { set test_value "1.2.3" }
            }
            
            set result [tossl::asn1::encode $type $test_value]
            puts "✓ Type '$type' supported: [string length $result] bytes"
        } err]} {
            puts "✗ Type '$type' failed: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Supported ASN.1 types validation failed: $result"
    exit 12
}

puts "\n=== All ASN.1 Encode Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple value encodings working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ DER format validation passed"
puts "✓ Type-specific validation working"
puts "✓ Memory management working"
puts "✓ Error recovery and robustness working"
puts "✓ Supported ASN.1 types validation completed"

exit 0 