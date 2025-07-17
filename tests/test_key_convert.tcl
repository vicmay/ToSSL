#!/usr/bin/env tclsh
# Test file for ::tossl::key::convert command
# Tests key conversion functionality, edge cases, and error handling

package require tossl

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
        } elseif {$result eq $expected_result || $expected_result eq "any"} {
            puts "  PASS: Got expected result"
            incr passed_count
        } else {
            puts "  FAIL: Expected: $expected_result, got: $result"
            incr failed_count
        }
    }
}

puts "=== Testing ::tossl::key::convert ==="

# Generate RSA key pair
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_priv [dict get $rsa_keys private]
set rsa_pub [dict get $rsa_keys public]

# Test 1: Convert RSA private PEM to DER
test "Convert RSA private PEM to DER" {
    set der [tossl::key::convert -key $rsa_priv -from pem -to der -type private]
    puts "DEBUG: type=[tcl::unsupported::representation $der] length=[string length $der]"
    expr {[string length $der] > 100}
} 1

# Test 2: Convert RSA public PEM to DER
test "Convert RSA public PEM to DER" {
    set der [tossl::key::convert -key $rsa_pub -from pem -to der -type public]
    expr {[string length $der] > 100}
} 1

# Test 3: Convert RSA private DER to PEM
test "Convert RSA private DER to PEM" {
    set der [tossl::key::convert -key $rsa_priv -from pem -to der -type private]
    set pem [tossl::key::convert -key $der -from der -to pem -type private]
    string match "*-----BEGIN PRIVATE KEY-----*" $pem
} 1

# Test 4: Convert RSA public DER to PEM
test "Convert RSA public DER to PEM" {
    set der [tossl::key::convert -key $rsa_pub -from pem -to der -type public]
    set pem [tossl::key::convert -key $der -from der -to pem -type public]
    string match "*-----BEGIN PUBLIC KEY-----*" $pem
} 1

# Generate EC key pair
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_priv [dict get $ec_keys private]
set ec_pub [dict get $ec_keys public]

# Test 5: Convert EC private PEM to DER
test "Convert EC private PEM to DER" {
    set der [tossl::key::convert -key $ec_priv -from pem -to der -type private]
    expr {[string length $der] > 50}
} 1

# Test 6: Convert EC public PEM to DER
test "Convert EC public PEM to DER" {
    set der [tossl::key::convert -key $ec_pub -from pem -to der -type public]
    expr {[string length $der] > 50}
} 1

# Test 7: Convert EC private DER to PEM
test "Convert EC private DER to PEM" {
    set der [tossl::key::convert -key $ec_priv -from pem -to der -type private]
    set pem [tossl::key::convert -key $der -from der -to pem -type private]
    string match "*-----BEGIN PRIVATE KEY-----*" $pem
} 1

# Test 8: Convert EC public DER to PEM
test "Convert EC public DER to PEM" {
    set der [tossl::key::convert -key $ec_pub -from pem -to der -type public]
    set pem [tossl::key::convert -key $der -from der -to pem -type public]
    string match "*-----BEGIN PUBLIC KEY-----*" $pem
} 1

# Generate DSA key pair (if supported)
set dsa_keys [catch {tossl::key::generate -type dsa -bits 1024} dsa_result]
if {!$dsa_keys} {
    set dsa_dict $dsa_result
    set dsa_priv [dict get $dsa_dict private]
    set dsa_pub [dict get $dsa_dict public]
    test "Convert DSA private PEM to DER" {
        set der [tossl::key::convert -key $dsa_priv -from pem -to der -type private]
        expr {[string length $der] > 50}
    } 1
    test "Convert DSA public PEM to DER" {
        set der [tossl::key::convert -key $dsa_pub -from pem -to der -type public]
        expr {[string length $der] > 50}
    } 1
}

# Test 9: Invalid key data
test "Invalid key data should error" {
    tossl::key::convert -key "not a key" -from pem -to der -type private
} error

# Test 10: Unknown from format
test "Unknown from format should error" {
    tossl::key::convert -key $rsa_priv -from foo -to der -type private
} error

# Test 11: Unknown to format
test "Unknown to format should error" {
    tossl::key::convert -key $rsa_priv -from pem -to foo -type private
} error

# Test 12: Unknown type
test "Unknown type should error" {
    tossl::key::convert -key $rsa_priv -from pem -to der -type foo
} error

# Test 13: Missing parameters
test "Missing parameters should error" {
    tossl::key::convert -key $rsa_priv -from pem -to der
} error

# Test 14: Too many arguments should error
test "Too many arguments should error" {
    tossl::key::convert -key $rsa_priv -from pem -to der -type private extra
} error

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count == 0} {
    puts "SUCCESS: All tests passed!"
    exit 0
} else {
    puts "FAILURE: $failed_count test(s) failed!"
    exit 1
} 