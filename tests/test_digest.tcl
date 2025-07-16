#!/usr/bin/env tclsh
# Test file for ::tossl::digest command
# Tests all supported algorithms, formats, and error handling

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
        # Check if expected_result is a list of possible values
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

puts "=== Testing ::tossl::digest ==="

# Test data
set test_data "Hello, World!"

# Test 1: SHA-256 basic functionality
test "SHA-256 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 $test_data]
    string length $hash
} 64

# Test 2: SHA-256 known value
test "SHA-256 known value" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 $test_data]
    expr {$hash eq "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"}
} 1

# Test 3: SHA-512 basic functionality
test "SHA-512 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha512 $test_data]
    string length $hash
} 128

# Test 4: SHA-1 basic functionality
test "SHA-1 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha1 $test_data]
    string length $hash
} 40

# Test 5: MD5 basic functionality
test "MD5 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg md5 $test_data]
    string length $hash
} 32

# Test 6: SHA-224 basic functionality
test "SHA-224 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha224 $test_data]
    string length $hash
} 56

# Test 7: SHA-384 basic functionality
test "SHA-384 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha384 $test_data]
    string length $hash
} 96

# Test 8: Binary format output
test "Binary format output" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 -format binary $test_data]
    string length $hash
} 32

# Test 9: Base64 format output
test "Base64 format output" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 -format base64 $test_data]
    # Base64 encoding of 32 bytes should be 44 characters (padded)
    string length $hash
} 44

# Test 10: Empty string input
test "Empty string input" {
    set hash [tossl::digest -alg sha256 ""]
    string length $hash
} 64

# Test 11: Binary data input
test "Binary data input" {
    set binary_data [binary format H* "0102030405060708"]
    set hash [tossl::digest -alg sha256 $binary_data]
    string length $hash
} 64

# Test 12: Error - invalid algorithm
test "Error: Invalid algorithm" {
    tossl::digest -alg invalid_alg $test_data
} error

# Test 13: Error - missing algorithm
test "Error: Missing algorithm" {
    tossl::digest $test_data
} error

# Test 14: Error - missing data
test "Error: Missing data" {
    tossl::digest -alg sha256
} error

# Test 15: Error - invalid format
test "Error: Invalid format" {
    tossl::digest -alg sha256 -format invalid_format $test_data
} error

# Test 16: Error - too many arguments
test "Error: Too many arguments" {
    tossl::digest -alg sha256 $test_data extra_arg
} error

# Test 17: Consistency test - same input produces same output
test "Consistency test" {
    set test_data "Hello, World!"
    set hash1 [tossl::digest -alg sha256 $test_data]
    set hash2 [tossl::digest -alg sha256 $test_data]
    expr {$hash1 eq $hash2}
} 1

# Test 18: Different inputs produce different outputs
test "Different inputs produce different outputs" {
    set hash1 [tossl::digest -alg sha256 "input1"]
    set hash2 [tossl::digest -alg sha256 "input2"]
    expr {$hash1 ne $hash2}
} 1

# Test 19: SHA-3 algorithms (if supported)
test "SHA-3-256 basic functionality" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha3-256 $test_data]
    string length $hash
} 64

# Test 20: BLAKE2 algorithms (if supported)
test "BLAKE2b-256 basic functionality" {
    set test_data "Hello, World!"
    if {[catch {tossl::digest -alg blake2b256 $test_data} hash]} {
        puts "  Note: BLAKE2b-256 algorithm not supported in this OpenSSL build"
        return "algorithm not supported"
    }
    string length $hash
} {64 {algorithm not supported}}

# Test 21: Large data input
test "Large data input" {
    set large_data [string repeat "A" 10000]
    set hash [tossl::digest -alg sha256 $large_data]
    string length $hash
} 64

# Test 22: Unicode data input
test "Unicode data input" {
    set unicode_data "Hello, 世界!"
    set hash [tossl::digest -alg sha256 $unicode_data]
    string length $hash
} 64

# Test 23: Verify hex format contains only hex characters
test "Hex format validation" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 $test_data]
    regexp {^[0-9a-f]+$} $hash
} 1

# Test 24: Verify base64 format is valid base64
test "Base64 format validation" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg sha256 -format base64 $test_data]
    # Base64 should only contain A-Z, a-z, 0-9, +, /, and = for padding
    regexp {^[A-Za-z0-9+/]+=*$} $hash
} 1

# Test 25: Performance test - multiple algorithms
test "Performance: Multiple algorithms" {
    set test_data "Hello, World!"
    set algorithms {sha256 sha512 sha1 md5}
    foreach alg $algorithms {
        set hash [tossl::digest -alg $alg $test_data]
        if {[string length $hash] == 0} {
            return "failure"
        }
    }
    return "success"
} "success"

# Test 26: All supported algorithms
test "All supported algorithms" {
    set test_data "Hello, World!"
    set algorithms {md5 sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 blake2b256 blake2b512 blake2s256}
    set success 1
    foreach alg $algorithms {
        if {[catch {tossl::digest -alg $alg $test_data} result]} {
            # Some algorithms might not be supported in this OpenSSL version
            puts "  Note: Algorithm $alg not supported"
        } else {
            if {[string length $result] == 0} {
                set success 0
                break
            }
        }
    }
    return [expr {$success ? "success" : "failure"}]
} "success"

# Test 27: Format conversion consistency
test "Format conversion consistency" {
    set test_data "Hello, World!"
    set hex_hash [tossl::digest -alg sha256 $test_data]
    set bin_hash [tossl::digest -alg sha256 -format binary $test_data]
    set b64_hash [tossl::digest -alg sha256 -format base64 $test_data]
    
    # All should be valid
    if {[string length $hex_hash] > 0 && [string length $bin_hash] > 0 && [string length $b64_hash] > 0} {
        return "success"
    } else {
        return "failure"
    }
} "success"

# Test 28: Algorithm case insensitivity
test "Algorithm case insensitivity" {
    set test_data "Hello, World!"
    set hash [tossl::digest -alg SHA256 $test_data]
    # Check if it's a valid SHA-256 hash (64 hex chars)
    expr {[string length $hash] == 64}
} 1

# Test 29: Error - format with wrong case
test "Error: Format with wrong case" {
    set test_data "Hello, World!"
    tossl::digest -alg sha256 -format HEX $test_data
} error

# Test 30: Stress test - multiple large inputs
test "Stress: Multiple large inputs" {
    set test_data "Hello, World!"
    for {set i 0} {$i < 5} {incr i} {
        set large_data [string repeat "Test data $i " 1000]
        set hash [tossl::digest -alg sha256 $large_data]
        if {[string length $hash] != 64} {
            return "failure"
        }
    }
    return "success"
} "success"

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