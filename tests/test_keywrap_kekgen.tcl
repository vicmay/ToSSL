#!/usr/bin/env tclsh

# Test script for ::tossl::keywrap::kekgen command
# Tests key encryption key generation for various algorithms

package require tossl

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

proc test {name test_body} {
    global test_count passed_count failed_count
    incr test_count
    puts "Test $test_count: $name"
    
    if {[catch {eval $test_body} result]} {
        puts "  FAILED: $result"
        incr failed_count
        return 0
    } else {
        puts "  PASSED"
        incr passed_count
        return 1
    }
}

proc assert_equal {expected actual} {
    if {$expected != $actual} {
        error "Expected '$expected', got '$actual'"
    }
}

proc assert_not_equal {expected actual} {
    if {$expected == $actual} {
        error "Expected different from '$expected', got '$actual'"
    }
}

proc assert_length {expected_length data} {
    set actual_length [string length $data]
    if {$expected_length != $actual_length} {
        error "Expected length $expected_length, got $actual_length"
    }
}

proc assert_hex_length {expected_length hex_data} {
    set actual_length [string length $hex_data]
    if {$expected_length != $actual_length} {
        error "Expected hex length $expected_length, got $actual_length"
    }
}

puts "=== Testing ::tossl::keywrap::kekgen ==="

# Test 1: Basic KEK generation for AES-128-ECB
test "Basic AES-128-ECB KEK generation" {
    set kek [tossl::keywrap::kekgen aes-128-ecb]
    assert_length 16 $kek
    puts "    Generated KEK: [binary encode hex $kek]"
}

# Test 2: Basic KEK generation for AES-192-ECB
test "Basic AES-192-ECB KEK generation" {
    set kek [tossl::keywrap::kekgen aes-192-ecb]
    assert_length 24 $kek
    puts "    Generated KEK: [binary encode hex $kek]"
}

# Test 3: Basic KEK generation for AES-256-ECB
test "Basic AES-256-ECB KEK generation" {
    set kek [tossl::keywrap::kekgen aes-256-ecb]
    assert_length 32 $kek
    puts "    Generated KEK: [binary encode hex $kek]"
}

# Test 4: Basic KEK generation for AES-128-CBC
test "Basic AES-128-CBC KEK generation" {
    set kek [tossl::keywrap::kekgen aes-128-cbc]
    assert_length 16 $kek
    puts "    Generated KEK: [binary encode hex $kek]"
}

# Test 5: Basic KEK generation for AES-256-CBC
test "Basic AES-256-CBC KEK generation" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    assert_length 32 $kek
    puts "    Generated KEK: [binary encode hex $kek]"
}

# Test 6: KEK uniqueness (multiple generations should be different)
test "KEK uniqueness across multiple generations" {
    set kek1 [tossl::keywrap::kekgen aes-256-cbc]
    set kek2 [tossl::keywrap::kekgen aes-256-cbc]
    set kek3 [tossl::keywrap::kekgen aes-256-cbc]
    
    assert_not_equal $kek1 $kek2
    assert_not_equal $kek1 $kek3
    assert_not_equal $kek2 $kek3
    
    puts "    KEK1: [binary encode hex $kek1]"
    puts "    KEK2: [binary encode hex $kek2]"
    puts "    KEK3: [binary encode hex $kek3]"
}

# Test 7: Error handling - invalid algorithm
test "Error handling for invalid algorithm" {
    if {![catch {tossl::keywrap::kekgen invalid-algorithm} result]} {
        error "Expected error for invalid algorithm, but got: $result"
    }
    puts "    Correctly rejected invalid algorithm"
}

# Test 8: Error handling - empty algorithm
test "Error handling for empty algorithm" {
    if {![catch {tossl::keywrap::kekgen ""} result]} {
        error "Expected error for empty algorithm, but got: $result"
    }
    puts "    Correctly rejected empty algorithm"
}

# Test 9: Error handling - wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {![catch {tossl::keywrap::kekgen} result]} {
        error "Expected error for no arguments, but got: $result"
    }
    puts "    Correctly rejected no arguments"
}

# Test 10: Error handling - too many arguments
test "Error handling for too many arguments" {
    if {![catch {tossl::keywrap::kekgen aes-256-cbc extra-arg} result]} {
        error "Expected error for too many arguments, but got: $result"
    }
    puts "    Correctly rejected too many arguments"
}

# Test 11: Performance test - multiple rapid generations
test "Performance test - multiple rapid generations" {
    set start_time [clock milliseconds]
    for {set i 0} {$i < 100} {incr i} {
        set kek [tossl::keywrap::kekgen aes-256-cbc]
        assert_length 32 $kek
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "    Generated 100 KEKs in ${duration}ms"
    
    if {$duration > 5000} {
        error "Performance too slow: ${duration}ms for 100 generations"
    }
}

# Test 12: Algorithm validation with keywrap::info
test "Algorithm validation with keywrap::info" {
    set algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
    
    foreach algorithm $algorithms {
        # Get algorithm info
        set info [tossl::keywrap::info $algorithm]
        
        # Generate KEK
        set kek [tossl::keywrap::kekgen $algorithm]
        
        # Extract key length from info
        if {[regexp {key_length (\d+)} $info -> key_length]} {
            assert_length $key_length $kek
            puts "    $algorithm: [string length $kek] bytes (expected: $key_length)"
        } else {
            error "Could not extract key length from info: $info"
        }
    }
}

# Test 13: Binary data handling
test "Binary data handling" {
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    
    # Test that the key contains binary data (not just printable characters)
    set has_binary 0
    for {set i 0} {$i < [string length $kek]} {incr i} {
        set byte [string index $kek $i]
        set byte_val [scan $byte %c]
        if {$byte_val < 32 || $byte_val > 126} {
            set has_binary 1
            break
        }
    }
    
    if {!$has_binary} {
        error "Generated key appears to contain only printable characters"
    }
    
    puts "    Generated key contains binary data (as expected)"
}



# Test 15: Basic key wrapping with generated KEK
test "Basic key wrapping with generated KEK" {
    # Generate KEK
    set kek [tossl::keywrap::kekgen aes-256-cbc]
    assert_length 32 $kek
    
    # Generate test data
    set test_data "This is test data for key wrapping"
    
    # Wrap the data (this should work with the generated KEK)
    set wrapped_data [tossl::keywrap::wrap aes-256-cbc $kek $test_data]
    
    # Verify wrapped data is not empty and different from original
    if {[string length $wrapped_data] == 0} {
        error "Wrapped data is empty"
    }
    
    if {$wrapped_data eq $test_data} {
        error "Wrapped data is identical to original data"
    }
    
    puts "    Successfully wrapped data using generated KEK ([string length $wrapped_data] bytes)"
}

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "\n❌ Some tests failed!"
    exit 1
} else {
    puts "\n✅ All tests passed!"
    exit 0
} 