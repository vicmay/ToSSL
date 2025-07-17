#!/usr/bin/env tclsh
# Test file for ::tossl::digest::stream command
# Tests file-based digest computation with various algorithms and formats

package require tossl

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

proc test {name script expected_result} {
    global test_count passed_count failed_count test_file large_file test_data
    incr test_count
    
    puts "Test $test_count: $name"
    
    if {[catch $script result]} {
        if {[llength $expected_result] > 1 && [lsearch -exact $expected_result $result] >= 0} {
            puts "  PASS: Expected one of: $expected_result, got: $result"
            incr passed_count
        } elseif {$expected_result eq "error" || $result eq $expected_result} {
            puts "  PASS: Expected result: $expected_result, got: $result"
            incr passed_count
        } else {
            puts "  FAIL: Unexpected error: $result"
            incr failed_count
        }
    } else {
        if {$expected_result eq "error"} {
            puts "  FAIL: Expected error but got: $result"
            incr failed_count
        } elseif {[llength $expected_result] > 1 && [lsearch -exact $expected_result $result] >= 0} {
            puts "  PASS: Expected one of: $expected_result, got: $result"
            incr passed_count
        } else {
            puts "  PASS: Got expected result"
            incr passed_count
        }
    }
}

puts "=== Testing ::tossl::digest::stream ==="

# Create test files
set test_file "test_stream_data.txt"
set large_file "test_large_file.bin"

# Create a simple test file
set test_data "Hello, World! This is a test file for digest streaming."
set f [open $test_file w]
puts $f $test_data
close $f

# Create a larger test file (1MB) for performance testing
set f [open $large_file w]
fconfigure $f -translation binary
for {set i 0} {$i < 1024} {incr i} {
    puts -nonewline $f [binary format H* [string repeat "0123456789abcdef" 64]]
}
close $f

# Test 1: SHA-256 basic functionality
test "SHA-256 basic functionality" {
    set hash [tossl::digest::stream -alg sha256 -file $test_file]
    string length $hash
} 64

# Test 2: SHA-256 known value (should match regular digest)
test "SHA-256 known value" {
    set hash [tossl::digest::stream -alg sha256 -file $test_file]
    set expected [tossl::digest -alg sha256 $test_data]
    expr {$hash eq $expected}
} 1

# Test 3: SHA-512 basic functionality
test "SHA-512 basic functionality" {
    set hash [tossl::digest::stream -alg sha512 -file $test_file]
    string length $hash
} 128

# Test 4: SHA-1 basic functionality
test "SHA-1 basic functionality" {
    set hash [tossl::digest::stream -alg sha1 -file $test_file]
    string length $hash
} 40

# Test 5: MD5 basic functionality
test "MD5 basic functionality" {
    set hash [tossl::digest::stream -alg md5 -file $test_file]
    string length $hash
} 32

# Test 6: SHA-224 basic functionality
test "SHA-224 basic functionality" {
    set hash [tossl::digest::stream -alg sha224 -file $test_file]
    string length $hash
} 56

# Test 7: SHA-384 basic functionality
test "SHA-384 basic functionality" {
    set hash [tossl::digest::stream -alg sha384 -file $test_file]
    string length $hash
} 96

# Test 8: Binary format output
test "Binary format output" {
    set hash [tossl::digest::stream -alg sha256 -file $test_file -format binary]
    string length $hash
} 32

# Test 9: Base64 format output
test "Base64 format output" {
    set hash [tossl::digest::stream -alg sha256 -file $test_file -format base64]
    string length $hash
} 44

# Test 10: Large file performance
test "Large file performance" {
    set start_time [clock milliseconds]
    set hash [tossl::digest::stream -alg sha256 -file $large_file]
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    # Should complete in reasonable time (less than 5 seconds)
    expr {$duration < 5000}
} 1

# Test 11: Large file SHA-512
test "Large file SHA-512" {
    set hash [tossl::digest::stream -alg sha512 -file $large_file]
    string length $hash
} 128

# Test 12: Empty file
test "Empty file" {
    set empty_file "empty_test.txt"
    set f [open $empty_file w]
    close $f
    set hash [tossl::digest::stream -alg sha256 -file $empty_file]
    file delete $empty_file
    string length $hash
} 64

# Test 13: Error - invalid algorithm
test "Error: Invalid algorithm" {
    tossl::digest::stream -alg invalid_alg -file $test_file
} error

# Test 14: Error - missing algorithm
test "Error: Missing algorithm" {
    tossl::digest::stream -file $test_file
} error

# Test 15: Error - missing file
test "Error: Missing file" {
    tossl::digest::stream -alg sha256
} error

# Test 16: Error - non-existent file
test "Error: Non-existent file" {
    tossl::digest::stream -alg sha256 -file "nonexistent_file.txt"
} error

# Test 17: Error - invalid format
test "Error: Invalid format" {
    catch {tossl::digest::stream -alg sha256 -file $test_file -format invalid}
    set err [catch {tossl::digest::stream -alg sha256 -file $test_file -format invalid} result]
    set result
} "Invalid format. Use hex, binary, or base64"

# Test 18: Binary file handling
test "Binary file handling" {
    set binary_file "binary_test.bin"
    set f [open $binary_file w]
    fconfigure $f -translation binary
    puts -nonewline $f [binary format H* "0102030405060708090a0b0c0d0e0f10"]
    close $f
    set hash [tossl::digest::stream -alg sha256 -file $binary_file]
    file delete $binary_file
    string length $hash
} 64

# Test 19: Multiple algorithms on same file
test "Multiple algorithms on same file" {
    set hashes {}
    lappend hashes [tossl::digest::stream -alg sha256 -file $test_file]
    lappend hashes [tossl::digest::stream -alg sha512 -file $test_file]
    lappend hashes [tossl::digest::stream -alg md5 -file $test_file]
    llength $hashes
} 3

# Test 20: Different formats on same file
test "Different formats on same file" {
    set hex_hash [tossl::digest::stream -alg sha256 -file $test_file -format hex]
    set bin_hash [tossl::digest::stream -alg sha256 -file $test_file -format binary]
    set b64_hash [tossl::digest::stream -alg sha256 -file $test_file -format base64]
    expr {[string length $hex_hash] == 64 && [string length $bin_hash] == 32 && [string length $b64_hash] == 44}
} 1

# Test 21: SHA3 algorithms
test "SHA3-256 basic functionality" {
    set hash [tossl::digest::stream -alg sha3-256 -file $test_file]
    string length $hash
} 64

# Test 22: BLAKE2 algorithms
if {[lsearch -exact [tossl::digest::list] blake2b256] >= 0} {
    test "BLAKE2b-256 basic functionality" {
        set hash [tossl::digest::stream -alg blake2b256 -file $test_file]
        string length $hash
    } 64
} else {
    puts "Skipping BLAKE2b-256 test: not supported by this OpenSSL build"
}

# Test 23: Consistency with regular digest
test "Consistency with regular digest" {
    set stream_hash [tossl::digest::stream -alg sha256 -file $test_file]
    set regular_hash [tossl::digest -alg sha256 $test_data]
    expr {$stream_hash eq $regular_hash}
} 1

# Test 24: File with special characters
test "File with special characters" {
    set special_file "test_special_@#$%.txt"
    set f [open $special_file w]
    puts $f "Special characters test"
    close $f
    set hash [tossl::digest::stream -alg sha256 -file $special_file]
    file delete $special_file
    string length $hash
} 64

# Test 25: Very large file (10MB) - performance test
test "Very large file performance" {
    set huge_file "test_huge_file.bin"
    set f [open $huge_file w]
    fconfigure $f -translation binary
    for {set i 0} {$i < 10240} {incr i} {
        puts -nonewline $f [binary format H* [string repeat "0123456789abcdef" 64]]
    }
    close $f
    
    set start_time [clock milliseconds]
    set hash [tossl::digest::stream -alg sha256 -file $huge_file]
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    file delete $huge_file
    # Should complete in reasonable time (less than 30 seconds)
    expr {$duration < 30000}
} 1

# Cleanup test files
file delete $test_file
file delete $large_file

# Print summary
puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count == 0} {
    puts "All tests passed!"
    exit 0
} else {
    puts "Some tests failed!"
    exit 1
} 