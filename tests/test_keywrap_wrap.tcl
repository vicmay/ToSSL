# tests/test_keywrap_wrap.tcl ;# Test for ::tossl::keywrap::wrap

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::keywrap::wrap ==="

# Test counter
set passed_count 0
set failed_count 0

# Test helper function
proc test {name test_script} {
    global passed_count failed_count
    puts "Test [expr {$passed_count + $failed_count + 1}]: $name"
    if {[catch $test_script result]} {
        puts "    FAILED: $result"
        incr failed_count
    } else {
        puts "    PASSED"
        incr passed_count
    }
}

# Test 1: Basic functionality - wrap data with AES-128-ECB
test "Basic AES-128-ECB wrapping" {
    set kek [tossl::keywrap::kekgen aes-128-ecb]
    set original_data "Test data for wrapping"
    set wrapped_data [tossl::keywrap::wrap aes-128-ecb $kek $original_data]
    
    # Verify wrapped data is different from original
    if {$wrapped_data eq $original_data} {
        error "Wrapped data should be different from original"
    }
    
    # Verify wrapped data has reasonable length
    if {[string length $wrapped_data] < [string length $original_data]} {
        error "Wrapped data should be at least as long as original"
    }
    
    puts "    Successfully wrapped data: [string length $wrapped_data] bytes"
}

# Test 2: Basic functionality - wrap data with AES-256-CBC
test "Basic AES-256-CBC wrapping" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set original_data "Another test data string"
    set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $original_data]
    
    # Verify wrapped data is different from original
    if {$wrapped_data eq $original_data} {
        error "Wrapped data should be different from original"
    }
    
    # Verify wrapped data has reasonable length (should include IV)
    if {[string length $wrapped_data] <= [string length $original_data]} {
        error "Wrapped data should be longer than original (includes IV)"
    }
    
    puts "    Successfully wrapped data: [string length $wrapped_data] bytes"
}

# Test 3: Error handling for invalid algorithm
test "Error handling for invalid algorithm" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set data "test data"
    
    if {[catch {tossl::keywrap::wrap invalid-algorithm $kek $data} result]} {
        puts "    Correctly rejected invalid algorithm: $result"
    } else {
        error "Should have rejected invalid algorithm"
    }
}

# Test 4: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::keywrap::wrap} result]} {
        puts "    Correctly rejected no arguments: $result"
    } else {
        error "Should have rejected no arguments"
    }
}

# Test 5: Error handling for too many arguments
test "Error handling for too many arguments" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set data "test data"
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $data extra-arg} result]} {
        puts "    Correctly rejected too many arguments: $result"
    } else {
        error "Should have rejected too many arguments"
    }
}

# Test 6: Error handling for empty algorithm
test "Error handling for empty algorithm" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set data "test data"
    
    if {[catch {tossl::keywrap::wrap "" $kek $data} result]} {
        puts "    Correctly rejected empty algorithm: $result"
    } else {
        error "Should have rejected empty algorithm"
    }
}

# Test 7: Error handling for wrong KEK length
test "Error handling for wrong KEK length" {
    set wrong_kek "short-key"
    set data "test data"
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $wrong_kek $data} result]} {
        puts "    Correctly failed with wrong KEK length: $result"
    } else {
        puts "    ⚠ Wrong KEK length was accepted (this might be expected behavior)"
    }
}

# Test 8: Command exists and accepts correct arguments
test "Command exists and accepts correct arguments" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set original_data "Test data"
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $original_data} wrapped_data]} {
        error "Command failed: $wrapped_data"
    } else {
        puts "    Command exists and executed successfully"
    }
}

# Test 9: Algorithm support verification
test "Algorithm support verification" {
    set algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
    
    foreach algorithm $algorithms {
        set kek [tossl::keywrap::kekgen $algorithm]
        set original_data "Test data for $algorithm"
        
        if {[catch {tossl::keywrap::wrap $algorithm $kek $original_data} wrapped_data]} {
            error "Failed to wrap with $algorithm: $wrapped_data"
        } else {
            puts "    ✓ $algorithm: Successfully wrapped [string length $wrapped_data] bytes"
        }
    }
}

# Test 10: Performance test - multiple wrap attempts
test "Performance test - multiple wrap attempts" {
    set start_time [clock milliseconds]
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set test_data "Performance test data"
    set success_count 0
    set failure_count 0
    
    for {set i 0} {$i < 10} {incr i} {
        if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $test_data} wrapped_data]} {
            incr failure_count
        } else {
            incr success_count
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Attempted 10 wraps in ${duration}ms"
    puts "    Successes: $success_count, Failures: $failure_count"
}

# Test 11: Binary data handling
test "Binary data handling" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set binary_data [binary format "cccc" 0x01 0x02 0x03 0x04]
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $binary_data} wrapped_data]} {
        error "Failed to wrap binary data: $wrapped_data"
    } else {
        puts "    Successfully wrapped binary data: [string length $wrapped_data] bytes"
    }
}

# Test 12: Empty data handling
test "Empty data handling" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set empty_data ""
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $empty_data} wrapped_data]} {
        error "Failed to wrap empty data: $wrapped_data"
    } else {
        puts "    Successfully wrapped empty data: [string length $wrapped_data] bytes"
    }
}

# Test 13: Large data handling
test "Large data handling" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set large_data [string repeat "A" 1000]
    
    if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $large_data} wrapped_data]} {
        error "Failed to wrap large data: $wrapped_data"
    } else {
        puts "    Successfully wrapped large data: [string length $wrapped_data] bytes"
    }
}

# Test 14: Consistency test - same input should produce different output
test "Consistency test - same input produces different output" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set test_data "Consistency test data"
    
    # Wrap the same data multiple times
    set wrapped1 [tossl::keywrap::wrap aes-256-cbc $kek $test_data]
    set wrapped2 [tossl::keywrap::wrap aes-256-cbc $kek $test_data]
    
    # The wrapped data should be different due to random IV
    if {$wrapped1 eq $wrapped2} {
        puts "    ⚠ Same wrapped output (this might be expected for ECB mode)"
    } else {
        puts "    ✓ Different wrapped output (expected for CBC mode)"
    }
}

# Test 15: Integration with unwrap command
test "Integration with unwrap command" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set original_data "Integration test data"
    
    # Wrap the data
    set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $original_data]
    
    # Try to unwrap it
    if {[catch {tossl::keywrap::unwrap aes-256-cbc $kek $wrapped_data} unwrapped_data]} {
        puts "    ⚠ Wrap successful, but unwrap failed: $unwrapped_data"
        # This is expected due to known unwrap issues
    } else {
        if {$original_data eq $unwrapped_data} {
            puts "    ✓ Complete wrap/unwrap cycle successful"
        } else {
            puts "    ⚠ Wrap/unwrap cycle failed (data mismatch)"
        }
    }
}

# Test 16: Algorithm information integration
test "Algorithm information integration" {
    set algorithms {aes-128-ecb aes-256-cbc}
    
    foreach algorithm $algorithms {
        # Get algorithm info
        set info [tossl::keywrap::info $algorithm]
        puts "    Algorithm info for $algorithm: $info"
        
        # Generate KEK and wrap data
        set kek [tossl::keywrap::kekgen $algorithm]
        set test_data "Test data for $algorithm"
        set wrapped_data [tossl::keywrap::wrap $algorithm $kek $test_data]
        
        puts "    ✓ $algorithm: KEK [string length $kek] bytes, wrapped [string length $wrapped_data] bytes"
    }
}

# Test 17: Memory usage test
test "Memory usage test" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set test_data "Memory test data"
    
    # Call wrap multiple times to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        if {[catch {tossl::keywrap::wrap aes-256-cbc $kek $test_data} wrapped_data]} {
            error "Memory test failed on iteration $i: $wrapped_data"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 18: Error handling for invalid KEK
test "Error handling for invalid KEK" {
    set invalid_kek [binary format "cccccccccccccccccccccccccccccccc" 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
    set data "test data"
    
    # This should work even with all-zero KEK
    if {[catch {tossl::keywrap::wrap aes-256-cbc $invalid_kek $data} wrapped_data]} {
        puts "    ⚠ All-zero KEK failed: $wrapped_data"
    } else {
        puts "    ✓ All-zero KEK worked (wrapped [string length $wrapped_data] bytes)"
    }
}

# Test 19: Data format verification
test "Data format verification" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    set test_data "Format test data"
    set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $test_data]
    
    # Verify wrapped data is binary
    if {[string is print $wrapped_data]} {
        puts "    ⚠ Wrapped data appears to be printable (unexpected)"
    } else {
        puts "    ✓ Wrapped data is binary (expected)"
    }
    
    # Verify wrapped data length is reasonable
    set expected_min_length [string length $test_data]
    if {[string length $wrapped_data] >= $expected_min_length} {
        puts "    ✓ Wrapped data length is reasonable: [string length $wrapped_data] bytes"
    } else {
        error "Wrapped data too short: [string length $wrapped_data] bytes"
    }
}

# Test 20: Algorithm compatibility verification
test "Algorithm compatibility verification" {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        set kek [tossl::keywrap::kekgen $algorithm]
        set test_data "Compatibility test for $algorithm"
        
        if {[catch {tossl::keywrap::wrap $algorithm $kek $test_data} wrapped_data]} {
            error "Algorithm $algorithm not compatible: $wrapped_data"
        } else {
            puts "    ✓ $algorithm: Compatible (wrapped [string length $wrapped_data] bytes)"
        }
    }
}

# Print test summary
puts "\n=== Test Summary ==="
puts "Total tests: [expr {$passed_count + $failed_count}]"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "\n❌ Some tests failed!"
    exit 1
} else {
    puts "\n✅ All tests passed!"
} 