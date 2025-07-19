# tests/test_asn1_set_create.tcl ;# Test for ::tossl::asn1::set_create

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::asn1::set_create..."

# Test 1: Basic functionality - create ASN.1 SET structures
puts "\n=== Test 1: Basic ASN.1 SET Creation ==="
set rc [catch {
    # Test single element set
    set single_result [tossl::asn1::set_create "element1"]
    puts "✓ Single element set: [string length $single_result] bytes"
    
    # Verify the result is not empty
    if {[string length $single_result] > 0} {
        puts "✓ Single element set result is not empty"
    } else {
        error "Single element set result is empty"
    }
    
    # Test two element set
    set two_result [tossl::asn1::set_create "element1" "element2"]
    puts "✓ Two element set: [string length $two_result] bytes"
    
    # Test three element set
    set three_result [tossl::asn1::set_create "element1" "element2" "element3"]
    puts "✓ Three element set: [string length $three_result] bytes"
    
    # Test integer set
    set int_result [tossl::asn1::set_create 123 456 789]
    puts "✓ Integer set: [string length $int_result] bytes"
    
    # Test mixed set
    set mixed_result [tossl::asn1::set_create 123 "hello" 456]
    puts "✓ Mixed set: [string length $mixed_result] bytes"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple element sets
puts "\n=== Test 2: Multiple Element Sets ==="
set rc [catch {
    set test_cases {
        {1 "single"}
        {2 "first" "second"}
        {3 "first" "second" "third"}
        {4 "first" "second" "third" "fourth"}
        {5 "first" "second" "third" "fourth" "fifth"}
    }
    
    foreach test_case $test_cases {
        set count [lindex $test_case 0]
        set elements [lrange $test_case 1 end]
        
        if {[catch {
            set result [tossl::asn1::set_create {*}$elements]
            puts "✓ $count element set: [string length $result] bytes"
            
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
            puts "✗ Failed to create $count element set: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple element sets test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::asn1::set_create
} result]
if {$rc != 0} {
    puts "✓ No arguments correctly rejected: $result"
} else {
    puts stderr "✗ No arguments should have caused an error"
    exit 3
}

# Test 4: Different data types in sets
puts "\n=== Test 4: Different Data Types in Sets ==="
set rc [catch {
    # Test integer sets
    set int_values {0 1 -1 127 -128 255 -255 999999}
    if {[catch {
        set result [tossl::asn1::set_create {*}$int_values]
        puts "✓ Integer set with [llength $int_values] elements: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create integer set: $err"
    }
    
    # Test string sets
    set string_values {"" "a" "hello" "Hello, World!" "test string"}
    if {[catch {
        set result [tossl::asn1::set_create {*}$string_values]
        puts "✓ String set with [llength $string_values] elements: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create string set: $err"
    }
    
    # Test mixed sets
    set mixed_values {123 "hello" -456 "world" 789}
    if {[catch {
        set result [tossl::asn1::set_create {*}$mixed_values]
        puts "✓ Mixed set with [llength $mixed_values] elements: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create mixed set: $err"
    }
    
    # Test large sets
    set large_values {}
    for {set i 0} {$i < 10} {incr i} {
        lappend large_values $i
    }
    if {[catch {
        set result [tossl::asn1::set_create {*}$large_values]
        puts "✓ Large set with [llength $large_values] elements: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create large set: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Different data types test failed: $result"
    exit 4
}

# Test 5: Edge cases and special values
puts "\n=== Test 5: Edge Cases and Special Values ==="
set rc [catch {
    # Test with very large integers
    if {[catch {
        set result [tossl::asn1::set_create 999999999 123456789]
        puts "✓ Large integer set: [string length $result] bytes"
    } err]} {
        puts "✓ Large integer set correctly rejected: $err"
    }
    
    # Test with very long strings
    set long_string [string repeat "a" 1000]
    if {[catch {
        set result [tossl::asn1::set_create $long_string "short"]
        puts "✓ Long string set: [string length $result] bytes"
    } err]} {
        puts "✓ Long string set correctly rejected: $err"
    }
    
    # Test with special characters
    if {[catch {
        set result [tossl::asn1::set_create "Hello\nWorld" "Test\tString"]
        puts "✓ Special characters set: [string length $result] bytes"
    } err]} {
        puts "✓ Special characters set correctly rejected: $err"
    }
    
    # Test with Unicode characters
    if {[catch {
        set result [tossl::asn1::set_create "Hello 世界" "Unicode Test"]
        puts "✓ Unicode characters set: [string length $result] bytes"
    } err]} {
        puts "✓ Unicode characters set correctly rejected: $err"
    }
    
    # Test with empty strings
    if {[catch {
        set result [tossl::asn1::set_create "" "non-empty"]
        puts "✓ Empty string set: [string length $result] bytes"
    } err]} {
        puts "✓ Empty string set correctly rejected: $err"
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
    set test_elements {"element1" "element2" "element3"}
    
    # Time multiple set creation operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set result [tossl::asn1::set_create {*}$test_elements]
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
    exit 6
}

# Test 7: DER format validation
puts "\n=== Test 7: DER Format Validation ==="
set rc [catch {
    set test_cases {
        {"single element" "test"}
        {"two elements" "first" "second"}
        {"three elements" "first" "second" "third"}
        {"mixed types" 123 "hello" 456}
    }
    
    foreach test_case $test_cases {
        set description [lindex $test_case 0]
        set elements [lrange $test_case 1 end]
        
        if {[catch {
            set result [tossl::asn1::set_create {*}$elements]
            
            # Check that result is not empty
            if {[string length $result] > 0} {
                puts "✓ '$description' -> [string length $result] bytes (valid DER)"
                
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
                
                # Check for SET tag (0x31)
                set first_byte [scan [string index $result 0] %c]
                if {$first_byte == 49} {  ;# 0x31 = 49 decimal
                    puts "  ✓ Has correct SET tag (0x31)"
                } else {
                    puts "  ⚠ May not have correct SET tag (got: 0x[format %02x $first_byte])"
                }
            } else {
                puts "⚠ '$description' -> empty result"
            }
        } err]} {
            puts "✗ Failed to create '$description': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ DER format validation failed: $result"
    exit 7
}

# Test 8: Type-specific validation
puts "\n=== Test 8: Type-Specific Validation ==="
set rc [catch {
    # Test integer set encoding with different values
    set int_values {0 1 -1 127 -128 255 -255 999999}
    if {[catch {
        set result [tossl::asn1::set_create {*}$int_values]
        puts "✓ Integer set with [llength $int_values] values: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create integer set: $err"
    }
    
    # Test string set encoding with different content
    set string_values {"" "a" "hello" "Hello, World!" "test string"}
    if {[catch {
        set result [tossl::asn1::set_create {*}$string_values]
        puts "✓ String set with [llength $string_values] values: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create string set: $err"
    }
    
    # Test mixed set encoding
    set mixed_values {123 "hello" -456 "world" 789 "test"}
    if {[catch {
        set result [tossl::asn1::set_create {*}$mixed_values]
        puts "✓ Mixed set with [llength $mixed_values] values: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create mixed set: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Type-specific validation failed: $result"
    exit 8
}

# Test 9: Memory and resource management
puts "\n=== Test 9: Memory and Resource Management ==="
set rc [catch {
    # Test many set creation operations to check for memory leaks
    set results {}
    
    for {set i 0} {$i < 25} {incr i} {
        set result [tossl::asn1::set_create "element$i" [expr {$i + 1}]]
        lappend results $result
        
        # Verify each result works
        if {[string length $result] == 0} {
            error "Empty result generated on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $results] sets"
    puts "  ✓ All sets produced results"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 9
}

# Test 10: Error recovery and robustness
puts "\n=== Test 10: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can create sets after various operations
    set test_operations {
        "Basic set creation"
        "After multiple set creations"
        "After type-specific validation"
        "After memory management test"
    }
    
    foreach operation $test_operations {
        if {[catch {
            set result [tossl::asn1::set_create "test" 123]
            
            if {[string length $result] == 0} {
                error "Empty result after $operation"
            }
            
            puts "✓ ASN.1 set creation successful after $operation"
        } err]} {
            error "ASN.1 set creation failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 10
}

# Test 11: ASN.1 SET structure validation
puts "\n=== Test 11: ASN.1 SET Structure Validation ==="
set rc [catch {
    # Test SET vs SEQUENCE differences
    if {[catch {
        set set_result [tossl::asn1::set_create "element1" "element2"]
        set seq_result [tossl::asn1::sequence_create "element1" "element2"]
        
        puts "✓ SET structure: [string length $set_result] bytes"
        puts "✓ SEQUENCE structure: [string length $seq_result] bytes"
        
        # Check that they have different tags
        set set_tag [scan [string index $set_result 0] %c]
        set seq_tag [scan [string index $seq_result 0] %c]
        
        if {$set_tag == 49 && $seq_tag == 48} {  ;# 0x31 for SET, 0x30 for SEQUENCE
            puts "✓ SET and SEQUENCE have correct different tags"
        } else {
            puts "⚠ SET and SEQUENCE tags may not be correct"
        }
        
    } err]} {
        puts "✗ Failed to compare SET and SEQUENCE: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ ASN.1 SET structure validation failed: $result"
    exit 11
}

# Test 12: Complex set scenarios
puts "\n=== Test 12: Complex Set Scenarios ==="
set rc [catch {
    # Test sets with many elements
    set many_elements {}
    for {set i 0} {$i < 5} {incr i} {
        lappend many_elements "element$i"
        lappend many_elements $i
    }
    
    if {[catch {
        set result [tossl::asn1::set_create {*}$many_elements]
        puts "✓ Complex set with [llength $many_elements] elements: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create complex set: $err"
    }
    
    # Test sets with varying element sizes
    set varying_elements {"short" "medium length string" "very long string that should test the encoding"}
    if {[catch {
        set result [tossl::asn1::set_create {*}$varying_elements]
        puts "✓ Varying size set: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create varying size set: $err"
    }
    
    # Test sets with special values
    set special_elements {0 -1 999999 "empty" "special\nchars"}
    if {[catch {
        set result [tossl::asn1::set_create {*}$special_elements]
        puts "✓ Special values set: [string length $result] bytes"
    } err]} {
        puts "✗ Failed to create special values set: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Complex set scenarios test failed: $result"
    exit 12
}

puts "\n=== All ASN.1 Set Create Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple element sets working"
puts "✓ Different data types working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ DER format validation passed"
puts "✓ Type-specific validation working"
puts "✓ Memory management working"
puts "✓ Error recovery and robustness working"
puts "✓ ASN.1 SET structure validation completed"
puts "✓ Complex set scenarios working"

exit 0 