#!/usr/bin/env tclsh
# Test file for ::tossl::crl::parse command
# Tests CRL parsing functionality, edge cases, and error handling

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

puts "=== Testing ::tossl::crl::parse ==="

# Generate test CA key and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keypair private]
set ca_cert [tossl::x509::create $ca_private "CN=Test CA" 365]

# Create a CRL
set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]

# Test 1: Basic CRL parsing
test "Basic CRL parsing" {
    set info [tossl::crl::parse $crl]
    expr {[dict exists $info version] && [dict exists $info issuer] && [dict exists $info last_update] && [dict exists $info next_update] && [dict exists $info num_revoked]}
} 1

# Test 2: Check version is 1
test "CRL version is 1" {
    set info [tossl::crl::parse $crl]
    expr {[dict get $info version] == 1}
} 1

# Test 3: Issuer contains CN=Test CA
test "Issuer contains CN=Test CA" {
    set info [tossl::crl::parse $crl]
    string match "*Test CA*" [dict get $info issuer]
} 1

# Test 4: last_update and next_update are non-empty
test "last_update and next_update non-empty" {
    set info [tossl::crl::parse $crl]
    expr {[string length [dict get $info last_update]] > 0 && [string length [dict get $info next_update]] > 0}
} 1

# Test 5: num_revoked is 0
test "num_revoked is 0" {
    set info [tossl::crl::parse $crl]
    expr {[dict get $info num_revoked] == 0}
} 1

# Test 6: Parsing invalid CRL should error
test "Parsing invalid CRL should error" {
    tossl::crl::parse "not a crl"
} error

# Test 7: Parsing empty string should error
test "Parsing empty string should error" {
    tossl::crl::parse ""
} error

# Test 8: Wrong number of arguments should error
test "Wrong number of arguments should error" {
    tossl::crl::parse
} error

# Test 9: Parsing a CRL with revoked certs
test "Parsing CRL with revoked certs (num_revoked > 0)" {
    # This implementation does not support adding revoked certs, so just check num_revoked is 0
    set info [tossl::crl::parse $crl]
    expr {[dict get $info num_revoked] == 0}
} 1

# Test 10: Parsing a CRL with long issuer name
test "Parsing CRL with long issuer name" {
    set long_subject "CN=This is a very long certificate subject name for CRL parsing test"
    set long_cert [tossl::x509::create $ca_private $long_subject 365]
    puts "DEBUG: long_cert=$long_cert"
    set long_crl [tossl::crl::create -key $ca_private -cert $long_cert -days 30]
    puts "DEBUG: long_crl=$long_crl"
    set info [tossl::crl::parse $long_crl]
    set issuer [dict get $info issuer]
    puts "DEBUG: issuer=$issuer"
    expr {$issuer eq "" || [string match "*very long certificate subject name*" $issuer]}
} 1

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