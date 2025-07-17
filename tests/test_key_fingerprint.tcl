#!/usr/bin/env tclsh
# Test file for ::tossl::key::fingerprint command
# Tests key fingerprinting functionality, edge cases, and error handling

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

puts "=== Testing ::tossl::key::fingerprint ==="

# Generate RSA key pair
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_pub [dict get $rsa_keys public]

# Test 1: Fingerprint RSA public key (default digest)
test "Fingerprint RSA public key (sha256)" {
    set fp [tossl::key::fingerprint -key $rsa_pub]
    expr {[string length $fp] == 64}
} 1

# Test 2: Fingerprint RSA public key (sha1)
test "Fingerprint RSA public key (sha1)" {
    set fp [tossl::key::fingerprint -key $rsa_pub -alg sha1]
    expr {[string length $fp] == 40}
} 1

# Test 3: Fingerprint RSA public key (sha512)
test "Fingerprint RSA public key (sha512)" {
    set fp [tossl::key::fingerprint -key $rsa_pub -alg sha512]
    expr {[string length $fp] == 128}
} 1

# Generate EC key pair
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_pub [dict get $ec_keys public]

# Test 4: Fingerprint EC public key (default digest)
test "Fingerprint EC public key (sha256)" {
    set fp [tossl::key::fingerprint -key $ec_pub]
    expr {[string length $fp] == 64}
} 1

# Generate DSA key pair (if supported)
set dsa_keys [catch {tossl::key::generate -type dsa -bits 1024} dsa_result]
if {!$dsa_keys} {
    set dsa_dict $dsa_result
    set dsa_pub [dict get $dsa_dict public]
    test "Fingerprint DSA public key (sha256)" {
        set fp [tossl::key::fingerprint -key $dsa_pub]
        expr {[string length $fp] == 64}
    } 1
} else {
    puts "SKIP: DSA not supported in this build"
}

# Test 5: Invalid key data
test "Invalid key data should error" {
    tossl::key::fingerprint -key "not a key"
} error

# Test 6: Empty string should error
test "Empty string should error" {
    tossl::key::fingerprint -key ""
} error

# Test 7: Unknown digest algorithm
test "Unknown digest algorithm should error" {
    tossl::key::fingerprint -key $rsa_pub -alg notadigest
} error

# Test 8: Missing key parameter
test "Missing key parameter should error" {
    tossl::key::fingerprint
} error

# Test 9: Too many arguments should error
test "Too many arguments should error" {
    tossl::key::fingerprint -key $rsa_pub -alg sha256 extra
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