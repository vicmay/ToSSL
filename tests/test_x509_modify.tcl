#!/usr/bin/env tclsh
;# Test file for ::tossl::x509::modify command

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

puts "=== Testing ::tossl::x509::modify ==="

;# Generate RSA key pair and certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365]

;# Test 1: Add extension (basic)
test "Add extension (basic)" {
    set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:example.com" 0]
    string match "*BEGIN CERTIFICATE*" $mod_cert
} 1

;# Test 2: Add critical extension
test "Add critical extension" {
    set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:critical.example.com" 1]
    string match "*BEGIN CERTIFICATE*" $mod_cert
} 1

;# Test 3: Remove extension
test "Remove extension (should succeed even if not present)" {
    set mod_cert [tossl::x509::modify -cert $cert -add_extension subjectAltName "DNS:remove.example.com" 0 -remove_extension subjectAltName]
    string match "*BEGIN CERTIFICATE*" $mod_cert
} 1

;# Test 4: Error on missing required option
test "Missing required option should error" {
    tossl::x509::modify -cert $cert -add_extension subjectAltName
} error

;# Test 5: Error on unknown option
test "Unknown option should error" {
    tossl::x509::modify -cert $cert -foo bar -add_extension subjectAltName "DNS:example.com" 0
} error

;# Test 6: Error on invalid certificate
test "Invalid certificate should error" {
    tossl::x509::modify -cert "notacert" -add_extension subjectAltName "DNS:example.com" 0
} error

;# Test 7: Error on invalid OID
test "Invalid OID should error" {
    tossl::x509::modify -cert $cert -add_extension "invalidOID" "value" 0
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