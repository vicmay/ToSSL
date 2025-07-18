#!/usr/bin/env tclsh
;# Test file for ::tossl::x509::create command

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

puts "=== Testing ::tossl::x509::create ==="

;# Generate RSA key pair
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

;# Test 1: Self-signed certificate (basic)
test "Self-signed certificate (basic)" {
    set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365]
    string match "*BEGIN CERTIFICATE*" $cert
} 1

;# Test 2: Certificate with SAN
test "Certificate with SAN" {
    set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365 -san {example.com www.example.com 127.0.0.1}]
    string match "*BEGIN CERTIFICATE*" $cert
} 1

;# Test 3: Certificate with key usage
test "Certificate with key usage" {
    set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365 -keyusage {digitalSignature keyEncipherment}]
    string match "*BEGIN CERTIFICATE*" $cert
} 1

;# Test 4: CA-signed certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_priv [dict get $ca_keys private]
set ca_pub [dict get $ca_keys public]
set ca_cert [tossl::x509::create -subject "Test CA" -issuer "Test CA" -pubkey $ca_pub -privkey $ca_priv -days 3650]
test "CA-signed certificate" {
    set cert [tossl::x509::create -subject "User" -issuer "Test CA" -pubkey $pub -privkey $ca_priv -days 365]
    string match "*BEGIN CERTIFICATE*" $cert
} 1

;# Test 5: Error on missing required option
test "Missing required option should error" {
    tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -days 365
} error

;# Test 6: Error on invalid key
test "Invalid key should error" {
    tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey "notakey" -days 365
} error

;# Test 7: Error on invalid days
test "Invalid days should error" {
    tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 0
} error

;# Test 8: Error on unknown option
test "Unknown option should error" {
    tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 365 -foo bar
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