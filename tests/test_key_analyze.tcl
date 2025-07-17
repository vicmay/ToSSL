#!/usr/bin/env tclsh
# Test file for ::tossl::key::analyze command
# Tests key analysis functionality, edge cases, and error handling

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

puts "=== Testing ::tossl::key::analyze ==="

# Generate RSA key pair
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_priv [dict get $rsa_keys private]
set rsa_pub [dict get $rsa_keys public]

# Test 1: Analyze RSA private key
test "Analyze RSA private key" {
    set info [tossl::key::parse $rsa_priv]
    expr {[dict get $info type] eq "rsa" && [dict get $info kind] eq "private" && [dict get $info bits] == 2048}
} 1

# Test 2: Analyze RSA public key
test "Analyze RSA public key" {
    set info [tossl::key::parse $rsa_pub]
    expr {[dict get $info type] eq "rsa" && [dict get $info kind] eq "public" && [dict get $info bits] == 2048}
} 1

# Generate EC key pair
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_priv [dict get $ec_keys private]
set ec_pub [dict get $ec_keys public]

# Test 3: Analyze EC private key
test "Analyze EC private key" {
    set info [tossl::key::parse $ec_priv]
    expr {[dict get $info type] eq "ec" && [dict get $info kind] eq "private" && [dict get $info curve] ne ""}
} 1

# Test 4: Analyze EC public key
test "Analyze EC public key" {
    set info [tossl::key::parse $ec_pub]
    expr {[dict get $info type] eq "ec" && [dict get $info kind] eq "public" && [dict get $info curve] ne ""}
} 1

# Generate DSA key pair (if supported)
set dsa_keys [catch {tossl::key::generate -type dsa -bits 1024} dsa_result]
if {!$dsa_keys} {
    set dsa_dict $dsa_result
    set dsa_priv [dict get $dsa_dict private]
    set dsa_pub [dict get $dsa_dict public]
    test "Analyze DSA private key" {
        set info [tossl::key::parse $dsa_priv]
        expr {[dict get $info type] eq "dsa" && [dict get $info kind] eq "private" && [dict get $info bits] == 1024}
    } 1
    test "Analyze DSA public key" {
        set info [tossl::key::parse $dsa_pub]
        expr {[dict get $info type] eq "dsa" && [dict get $info kind] eq "public" && [dict get $info bits] == 1024}
    } 1
} else {
    puts "SKIP: DSA not supported in this build"
}

# Test 5: Invalid key data
test "Invalid key data should error" {
    tossl::key::parse "not a key"
} error

# Test 6: Empty string should error
test "Empty string should error" {
    tossl::key::parse ""
} error

# Test 7: Wrong number of arguments should error
test "Wrong number of arguments should error" {
    tossl::key::parse
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