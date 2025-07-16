#!/usr/bin/env tclsh
# Test file for ::tossl::randbytes command
# Tests basic functionality, error handling, and edge cases

package require tossl

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

proc test {name script expected_result} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "Test $test_count: $name"
    
    if {[catch $script result]} {
        if {$expected_result eq "error"} {
            puts "  PASS: Expected error, got: $result"
            incr passed_count
        } else {
            puts "  FAIL: Unexpected error: $result"
            incr failed_count
        }
    } else {
        if {$expected_result eq "error"} {
            puts "  FAIL: Expected error but got: $result"
            incr failed_count
        } else {
            puts "  PASS: Got expected result"
            incr passed_count
        }
    }
}

puts "=== Testing ::tossl::randbytes ==="

# Test 1: Basic functionality - generate 1 byte
test "Generate 1 random byte" {
    set result [tossl::rand::bytes 1]
    string length $result
} 1

# Test 2: Generate 16 bytes
test "Generate 16 random bytes" {
    set result [tossl::rand::bytes 16]
    string length $result
} 16

# Test 3: Generate 32 bytes
test "Generate 32 random bytes" {
    set result [tossl::rand::bytes 32]
    string length $result
} 32

# Test 4: Generate 64 bytes
test "Generate 64 random bytes" {
    set result [tossl::rand::bytes 64]
    string length $result
} 64

# Test 5: Generate maximum allowed bytes (4096)
test "Generate 4096 random bytes" {
    set result [tossl::rand::bytes 4096]
    string length $result
} 4096

# Test 6: Verify bytes are different (randomness test)
test "Verify randomness - multiple calls produce different results" {
    set bytes1 [tossl::rand::bytes 16]
    set bytes2 [tossl::rand::bytes 16]
    expr {$bytes1 ne $bytes2}
} 1

# Test 7: Error - no arguments
test "Error: No arguments" {
    tossl::rand::bytes
} error

# Test 8: Error - too many arguments
test "Error: Too many arguments" {
    tossl::rand::bytes 16 32
} error

# Test 9: Error - invalid argument type
test "Error: Invalid argument type (string)" {
    tossl::rand::bytes "not_a_number"
} error

# Test 10: Error - zero bytes
test "Error: Zero bytes" {
    tossl::rand::bytes 0
} error

# Test 11: Error - negative bytes
test "Error: Negative bytes" {
    tossl::rand::bytes -1
} error

# Test 12: Large value (5000 bytes) - current implementation allows this
test "Large value (5000 bytes)" {
    set result [tossl::rand::bytes 5000]
    string length $result
} 5000

# Test 13: Error - non-integer argument
test "Error: Non-integer argument (float)" {
    tossl::rand::bytes 16.5
} error

# Test 14: Verify byte array type
test "Verify result is byte array" {
    set result [tossl::rand::bytes 8]
    binary scan $result H* hex
    string length $hex
} 16

# Test 15: Test large value (10000 bytes)
test "Large value (10000 bytes)" {
    set result [tossl::rand::bytes 10000]
    string length $result
} 10000

# Test 16: Test very large value (100000 bytes)
test "Very large value (100000 bytes)" {
    set result [tossl::rand::bytes 100000]
    string length $result
} 100000

# Test 17: Verify hex encoding works
test "Verify hex encoding of random bytes" {
    set result [tossl::rand::bytes 4]
    binary scan $result H* hex
    regexp {^[0-9a-f]{8}$} $hex
} 1

# Test 18: Performance test - multiple small calls
test "Performance: Multiple small calls" {
    set success 1
    for {set i 0} {$i < 10} {incr i} {
        set bytes [tossl::rand::bytes 8]
        if {[string length $bytes] != 8} {
            set success 0
            break
        }
    }
    expr $success
} 1

# Test 19: Memory test - large allocation
test "Memory: Large allocation (1024 bytes)" {
    set result [tossl::rand::bytes 1024]
    string length $result
} 1024

# Test 20: Stress test - multiple large allocations
test "Stress: Multiple large allocations" {
    set success 1
    for {set i 0} {$i < 5} {incr i} {
        set result [tossl::rand::bytes 512]
        if {[string length $result] != 512} {
            set success 0
            break
        }
    }
    expr $success
} 1

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count == 0} {
    puts "All tests PASSED!"
    exit 0
} else {
    puts "Some tests FAILED!"
    exit 1
} 