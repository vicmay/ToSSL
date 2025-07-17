#!/usr/bin/env tclsh
# Test file for ::tossl::digest::compare command
# Tests hash comparison functionality, edge cases, and error handling

package require tossl

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

proc test {name script expected_result} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "Test $test_count: $name"
    
    if {[catch {uplevel 1 $script} result]} {
        if {$expected_result eq "error" || $result eq $expected_result} {
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
        } elseif {$result eq $expected_result} {
            puts "  PASS: Got expected result"
            incr passed_count
        } else {
            puts "  FAIL: Expected: $expected_result, got: $result"
            incr failed_count
        }
    }
}

puts "=== Testing ::tossl::digest::compare ==="

# Test data - create some known hashes
set test_data "Hello, World!"
set hash1 [tossl::digest -alg sha256 $test_data]
set hash2 [tossl::digest -alg sha256 $test_data]
set hash3 [tossl::digest -alg sha256 "Different data"]

# Test 1: Basic functionality - identical hashes
test "Identical hashes should return 1" {
    tossl::digest::compare $hash1 $hash2
} 1

# Test 2: Different hashes should return 0
test "Different hashes should return 0" {
    tossl::digest::compare $hash1 $hash3
} 0

# Test 3: Same hash compared to itself
test "Hash compared to itself should return 1" {
    tossl::digest::compare $hash1 $hash1
} 1

# Test 4: Different algorithms with same data
set md5_hash [tossl::digest -alg md5 $test_data]
set sha1_hash [tossl::digest -alg sha1 $test_data]
test "Different algorithms should return 0" {
    tossl::digest::compare $md5_hash $sha1_hash
} 0

# Test 5: Empty strings
test "Empty strings should return 1" {
    tossl::digest::compare "" ""
} 1

# Test 6: Empty vs non-empty
test "Empty vs non-empty should return 0" {
    tossl::digest::compare "" $hash1
} 0

# Test 7: Different length hashes
set short_hash "abc123"
test "Different length hashes should return 0" {
    tossl::digest::compare $short_hash $hash1
} 0

# Test 8: Case sensitivity
set upper_hash [string toupper $hash1]
test "Case sensitive comparison" {
    tossl::digest::compare $hash1 $upper_hash
} 0

# Test 9: Single character difference
set modified_hash [string replace $hash1 0 0 "f"]
test "Single character difference should return 0" {
    tossl::digest::compare $hash1 $modified_hash
} 0

# Test 10: Last character difference
set last_char [string index $hash1 end]
set new_char [expr {$last_char eq "f" ? "a" : "f"}]
set modified_hash [string replace $hash1 end end $new_char]
test "Last character difference should return 0" {
    tossl::digest::compare $hash1 $modified_hash
} 0

# Test 11: Middle character difference
set modified_hash [string replace $hash1 32 32 "f"]
test "Middle character difference should return 0" {
    tossl::digest::compare $hash1 $modified_hash
} 0

# Test 12: Very long hashes
set long_data [string repeat "A" 1000]
set long_hash1 [tossl::digest -alg sha512 $long_data]
set long_hash2 [tossl::digest -alg sha512 $long_data]
test "Very long hashes comparison" {
    tossl::digest::compare $long_hash1 $long_hash2
} 1

# Test 13: Binary data hashes
set binary_data [binary format H* "0102030405060708090a0b0c0d0e0f10"]
set bin_hash1 [tossl::digest -alg sha256 $binary_data]
set bin_hash2 [tossl::digest -alg sha256 $binary_data]
test "Binary data hashes comparison" {
    tossl::digest::compare $bin_hash1 $bin_hash2
} 1

# Test 14: Unicode data hashes
set unicode_data "Hello, 世界! 🌍"
set uni_hash1 [tossl::digest -alg sha256 $unicode_data]
set uni_hash2 [tossl::digest -alg sha256 $unicode_data]
test "Unicode data hashes comparison" {
    tossl::digest::compare $uni_hash1 $uni_hash2
} 1

# Test 15: Special characters
set special_data "!@#$%^&*()_+-=[]{}|;':\",./<>?"
set spec_hash1 [tossl::digest -alg sha256 $special_data]
set spec_hash2 [tossl::digest -alg sha256 $special_data]
test "Special characters hashes comparison" {
    tossl::digest::compare $spec_hash1 $spec_hash2
} 1

# Test 16: Multiple algorithms comparison
set algorithms {md5 sha1 sha224 sha256 sha384 sha512}
set test_string "Test string for multiple algorithms"
set hashes {}
foreach alg $algorithms {
    lappend hashes [tossl::digest -alg $alg $test_string]
}
test "Multiple algorithms comparison" {
    set all_different 1
    for {set i 0} {$i < [llength $hashes]} {incr i} {
        for {set j [expr $i + 1]} {$j < [llength $hashes]} {incr j} {
            if {[tossl::digest::compare [lindex $hashes $i] [lindex $hashes $j]] == 1} {
                set all_different 0
                break
            }
        }
    }
    set all_different
} 1

# Test 17: Performance test with many comparisons
test "Performance test - many comparisons" {
    set count 0
    for {set i 0} {$i < 100} {incr i} {
        if {[tossl::digest::compare $hash1 $hash1] == 1} {
            incr count
        }
    }
    set count
} 100

# Test 18: Error handling - wrong number of arguments
test "Wrong number of arguments should error" {
    tossl::digest::compare $hash1
} error

# Test 19: Error handling - too many arguments
test "Too many arguments should error" {
    tossl::digest::compare $hash1 $hash2 $hash3
} error

# Test 20: Error handling - no arguments
test "No arguments should error" {
    tossl::digest::compare
} error

# Test 21: Security test - timing attack resistance
# This test verifies that comparison time is not significantly different
# for matching vs non-matching hashes (basic timing attack resistance)
test "Timing attack resistance check" {
    set start_time [clock clicks -microseconds]
    tossl::digest::compare $hash1 $hash1
    set match_time [expr [clock clicks -microseconds] - $start_time]
    
    set start_time [clock clicks -microseconds]
    tossl::digest::compare $hash1 $hash3
    set mismatch_time [expr [clock clicks -microseconds] - $start_time]
    
    # The times should be reasonably close (within 10x)
    expr {abs($match_time - $mismatch_time) < [expr $match_time * 10]}
} 1

# Test 22: Edge case - very short hashes
set short1 "a"
set short2 "b"
test "Very short different hashes" {
    tossl::digest::compare $short1 $short2
} 0

# Test 23: Edge case - very short identical hashes
test "Very short identical hashes" {
    tossl::digest::compare $short1 $short1
} 1

# Test 24: Edge case - single character hashes
test "Single character different hashes" {
    tossl::digest::compare "a" "b"
} 0

# Test 25: Edge case - single character identical hashes
test "Single character identical hashes" {
    tossl::digest::compare "a" "a"
} 1

# Test 26: Real-world scenario - file integrity check
set temp_file "temp_test_file.txt"
set file_content "This is a test file for integrity checking."
set fd [open $temp_file w]
puts $fd $file_content
close $fd

set file_hash1 [tossl::digest::stream -alg sha256 -file $temp_file]
set file_hash2 [tossl::digest::stream -alg sha256 -file $temp_file]

test "File integrity check - same file" {
    tossl::digest::compare $file_hash1 $file_hash2
} 1

# Modify the file
set fd [open $temp_file w]
puts $fd "Modified content"
close $fd

set file_hash3 [tossl::digest::stream -alg sha256 -file $temp_file]

test "File integrity check - modified file" {
    tossl::digest::compare $file_hash1 $file_hash3
} 0

# Clean up
file delete $temp_file

# Test 27: Integration with other digest commands
set data1 "First piece of data"
set data2 "Second piece of data"
set hash1_new [tossl::digest -alg sha256 $data1]
set hash2_new [tossl::digest -alg sha256 $data2]

test "Integration test - different data" {
    tossl::digest::compare $hash1_new $hash2_new
} 0

# Test 28: Integration with HMAC
set key [binary format H* "00112233445566778899aabbccddeeff"]
set data "test data"
set hmac1 [tossl::hmac -alg sha256 -key $key $data]
set hmac2 [tossl::hmac -alg sha256 -key $key $data]

test "Integration test - HMAC comparison" {
    tossl::digest::compare $hmac1 $hmac2
} 1

# Test 29: Different HMAC keys
set key2 [binary format H* "ffeeddccbbaa99887766554433221100"]
set hmac3 [tossl::hmac -alg sha256 -key $key2 $data]

test "Integration test - different HMAC keys" {
    tossl::digest::compare $hmac1 $hmac3
} 0

# Test 30: Stress test - many different hashes
test "Stress test - many comparisons" {
    set test_strings {"a" "b" "c" "d" "e" "f" "g" "h" "i" "j"}
    set hashes {}
    foreach str $test_strings {
        lappend hashes [tossl::digest -alg sha256 $str]
    }
    
    set correct_comparisons 0
    for {set i 0} {$i < [llength $hashes]} {incr i} {
        for {set j 0} {$j < [llength $hashes]} {incr j} {
            set expected [expr {$i == $j ? 1 : 0}]
            set actual [tossl::digest::compare [lindex $hashes $i] [lindex $hashes $j]]
            if {$actual == $expected} {
                incr correct_comparisons
            }
        }
    }
    set correct_comparisons
} 100

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "ERROR: Some tests failed!"
    exit 1
} else {
    puts "SUCCESS: All tests passed!"
    exit 0
} 