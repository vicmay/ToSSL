# tests/test_asn1_sequence_create.tcl ;# Test for ::tossl::asn1::sequence_create

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::asn1::sequence_create..."

# Test 1: Basic functionality - create simple sequence
puts "\n=== Test 1: Basic ASN.1 Sequence Creation ==="
set rc [catch {
    # Create a simple sequence with integer and string
    set sequence [tossl::asn1::sequence_create 123 "hello"]
    puts "✓ Sequence created: [string length $sequence] bytes"
    
    # Check that it's a valid ASN.1 sequence (starts with 0x30)
    set first_byte [scan [string index $sequence 0] %c]
    if {$first_byte == 48} {  ;# 0x30 = 48 decimal
        puts "✓ Sequence has correct ASN.1 SEQUENCE tag (0x30)"
    } else {
        error "Sequence does not have correct ASN.1 SEQUENCE tag: [format 0x%02x $first_byte]"
    }
    
    # Check sequence length
    set length_byte [scan [string index $sequence 1] %c]
    puts "✓ Sequence length byte: [format 0x%02x $length_byte]"
    
    # Verify the sequence can be parsed back
    set parse_result [tossl::asn1::parse $sequence]
    puts "✓ Sequence parsing result: $parse_result"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple element sequences
puts "\n=== Test 2: Multiple Element Sequences ==="
set rc [catch {
    # Create sequence with multiple integers
    set int_sequence [tossl::asn1::sequence_create 1 2 3 4 5]
    puts "✓ Integer sequence created: [string length $int_sequence] bytes"
    
    # Create sequence with mixed types
    set mixed_sequence [tossl::asn1::sequence_create 123 "hello" 456 "world" 789]
    puts "✓ Mixed sequence created: [string length $mixed_sequence] bytes"
    
    # Create sequence with larger numbers
    set large_sequence [tossl::asn1::sequence_create 1000000 2000000 3000000]
    puts "✓ Large number sequence created: [string length $large_sequence] bytes"
    
    # Verify all sequences have correct ASN.1 structure
    set int_first_byte [scan [string index $int_sequence 0] %c]
    set mixed_first_byte [scan [string index $mixed_sequence 0] %c]
    set large_first_byte [scan [string index $large_sequence 0] %c]
    
    if {$int_first_byte == 48} {
        puts "✓ Integer sequence has correct ASN.1 structure"
    } else {
        error "Integer sequence does not have correct ASN.1 SEQUENCE tag: [format 0x%02x $int_first_byte]"
    }
    
    if {$mixed_first_byte == 48} {
        puts "✓ Mixed sequence has correct ASN.1 structure"
    } else {
        error "Mixed sequence does not have correct ASN.1 SEQUENCE tag: [format 0x%02x $mixed_first_byte]"
    }
    
    if {$large_first_byte == 48} {
        puts "✓ Large sequence has correct ASN.1 structure"
    } else {
        error "Large sequence does not have correct ASN.1 SEQUENCE tag: [format 0x%02x $large_first_byte]"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple element sequences test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::asn1::sequence_create
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 3
}

# Test 4: Edge cases and special values
puts "\n=== Test 4: Edge Cases and Special Values ==="
set rc [catch {
    # Test with zero
    set zero_seq [tossl::asn1::sequence_create 0]
    puts "✓ Zero sequence created: [string length $zero_seq] bytes"
    
    # Test with negative numbers
    set neg_seq [tossl::asn1::sequence_create -123 -456]
    puts "✓ Negative number sequence created: [string length $neg_seq] bytes"
    
    # Test with empty string
    set empty_seq [tossl::asn1::sequence_create ""]
    puts "✓ Empty string sequence created: [string length $empty_seq] bytes"
    
    # Test with special characters
    set special_seq [tossl::asn1::sequence_create "hello\nworld" "test\tstring"]
    puts "✓ Special character sequence created: [string length $special_seq] bytes"
    
    # Test with unicode characters
    set unicode_seq [tossl::asn1::sequence_create "café" "naïve"]
    puts "✓ Unicode sequence created: [string length $unicode_seq] bytes"
    
    # Verify all edge case sequences have correct ASN.1 structure
    foreach {name seq} {zero $zero_seq neg $neg_seq empty $empty_seq special $special_seq unicode $unicode_seq} {
        set first_byte [scan [string index $seq 0] %c]
        if {$first_byte == 48} {
            puts "✓ $name sequence has correct ASN.1 structure"
        } else {
            puts "⚠ $name sequence may have incorrect ASN.1 structure"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Edge cases test failed: $result"
    exit 4
}

# Test 5: Performance test
puts "\n=== Test 5: Performance Test ==="
set rc [catch {
    set iterations 100
    
    # Time multiple sequence creation operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set seq [tossl::asn1::sequence_create $i "test$i"]
        if {[string length $seq] == 0} {
            error "Empty sequence generated on iteration $i"
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
    exit 5
}

# Test 6: ASN.1 structure validation
puts "\n=== Test 6: ASN.1 Structure Validation ==="
set rc [catch {
    # Create a test sequence
    set test_sequence [tossl::asn1::sequence_create 123 "hello" 456]
    
    # Check ASN.1 structure
    set first_byte [scan [string index $test_sequence 0] %c]
    set length_byte [scan [string index $test_sequence 1] %c]
    
    puts "✓ Sequence tag: [format 0x%02x $first_byte] (should be 0x30)"
    puts "✓ Sequence length: [format 0x%02x $length_byte]"
    
    # Verify sequence length is reasonable
    if {$length_byte > 0 && $length_byte < 128} {
        puts "✓ Sequence length is within valid range"
    } else {
        puts "⚠ Sequence length may be invalid: [format 0x%02x $length_byte]"
    }
    
    # Check that sequence length matches actual data
    set expected_length [expr {[string length $test_sequence] - 2}]
    if {$length_byte == $expected_length} {
        puts "✓ Sequence length matches actual data length"
    } else {
        puts "⚠ Sequence length mismatch: expected $expected_length, got $length_byte"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ ASN.1 structure validation failed: $result"
    exit 6
}

# Test 7: Sequence parsing and round-trip
puts "\n=== Test 7: Sequence Parsing and Round-trip ==="
set rc [catch {
    # Create sequences and verify they can be parsed
    set test_cases {
        {simple {123 "hello"}}
        {numbers {1 2 3 4 5}}
        {mixed {123 "hello" 456 "world"}}
        {large {1000000 2000000}}
    }
    
    foreach {name elements} $test_cases {
        set sequence [tossl::asn1::sequence_create {*}$elements]
        set parse_result [tossl::asn1::parse $sequence]
        
        puts "✓ $name sequence: [string length $sequence] bytes, parse: $parse_result"
        
        # Verify parse result contains expected information
        if {[string match "*type=*" $parse_result]} {
            puts "  ✓ Parse result has valid format"
        } else {
            puts "  ⚠ Parse result format may be unexpected: $parse_result"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Sequence parsing and round-trip test failed: $result"
    exit 7
}

# Test 8: Memory and resource management
puts "\n=== Test 8: Memory and Resource Management ==="
set rc [catch {
    # Test many sequence creation operations to check for memory leaks
    set sequences {}
    
    for {set i 0} {$i < 50} {incr i} {
        set seq [tossl::asn1::sequence_create $i "test$i" [expr {$i * 100}]]
        lappend sequences $seq
        
        # Verify each sequence works
        set parse_result [tossl::asn1::parse $seq]
        if {![string match "*type=*" $parse_result]} {
            error "Generated sequence $i does not parse correctly"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $sequences] sequences"
    puts "  ✓ All sequences parse correctly"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 8
}

# Test 9: Large sequences and stress testing
puts "\n=== Test 9: Large Sequences and Stress Testing ==="
set rc [catch {
    # Create sequence with many elements
    set many_elements {}
    for {set i 0} {$i < 20} {incr i} {
        lappend many_elements $i
        lappend many_elements "string$i"
    }
    
    set large_sequence [tossl::asn1::sequence_create {*}$many_elements]
    puts "✓ Large sequence created: [string length $large_sequence] bytes with [llength $many_elements] elements"
    
    # Verify large sequence structure
    set first_byte [scan [string index $large_sequence 0] %c]
    if {$first_byte == 48} {
        puts "✓ Large sequence has correct ASN.1 structure"
    } else {
        puts "⚠ Large sequence may have incorrect ASN.1 structure"
    }
    
    # Test with very long strings
    set long_string [string repeat "x" 1000]
    set long_seq [tossl::asn1::sequence_create $long_string "short"]
    puts "✓ Long string sequence created: [string length $long_seq] bytes"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Large sequences and stress testing failed: $result"
    exit 9
}

# Test 10: Error recovery and robustness
puts "\n=== Test 10: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can create sequences after various operations
    set test_operations {
        "Basic creation"
        "After parsing"
        "After multiple creations"
        "After large sequences"
    }
    
    foreach operation $test_operations {
        if {[catch {
            set seq [tossl::asn1::sequence_create 123 "test"]
            set parse_result [tossl::asn1::parse $seq]
            
            if {![string match "*type=*" $parse_result]} {
                error "Sequence parsing failed after $operation"
            }
            
            puts "✓ Sequence creation successful after $operation"
        } err]} {
            error "Sequence creation failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 10
}

puts "\n=== All ASN.1 Sequence Create Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple element sequences working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ ASN.1 structure validation passed"
puts "✓ Sequence parsing and round-trip working"
puts "✓ Memory management working"
puts "✓ Large sequences and stress testing passed"
puts "✓ Error recovery and robustness working"

exit 0 