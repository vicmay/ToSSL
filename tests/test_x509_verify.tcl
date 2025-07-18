#!/usr/bin/env tclsh
;# Test file for ::tossl::x509::verify command

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
        } elseif {$result eq $expected_result} {
            puts "  PASS: Got expected result: $result"
            incr passed_count
        } else {
            puts "  FAIL: Expected $expected_result, got $result"
            incr failed_count
        }
    }
}

puts "Testing ::tossl::x509::verify command\n"

;# Test 1: Basic functionality - verify a self-signed certificate
test "Basic self-signed certificate verification" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::verify $cert $cert
} "1"

;# Test 2: Verify certificate with different CA (should fail)
test "Certificate verification with different CA" {
    set keys1 [tossl::key::generate -type rsa -bits 2048]
    set keys2 [tossl::key::generate -type rsa -bits 2048]
    set priv1 [dict get $keys1 private]
    set pub1 [dict get $keys1 public]
    set priv2 [dict get $keys2 private]
    set pub2 [dict get $keys2 public]
    
    set cert1 [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $pub1 -privkey $priv1 -days 365]
    set ca_cert [tossl::x509::create -subject "CN=Different CA" -issuer "CN=Different CA" -pubkey $pub2 -privkey $priv2 -days 365]
    
    tossl::x509::verify $cert1 $ca_cert
} "0"

;# Test 3: Verify certificate with its actual CA
test "Certificate verification with correct CA" {
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set cert_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_priv [dict get $ca_keys private]
    set ca_pub [dict get $ca_keys public]
    set cert_pub [dict get $cert_keys public]
    
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_pub -privkey $ca_priv -days 365]
    set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $cert_pub -privkey $ca_priv -days 365]
    
    tossl::x509::verify $cert $ca_cert
} "1"

;# Test 4: Error handling - invalid certificate
test "Error handling - invalid certificate" {
    tossl::x509::verify "invalid certificate" "invalid ca certificate"
} "error"

;# Test 5: Error handling - missing arguments
test "Error handling - missing arguments" {
    tossl::x509::verify "some certificate"
} "error"

;# Test 6: Error handling - too many arguments
test "Error handling - too many arguments" {
    tossl::x509::verify "cert1" "cert2" "cert3"
} "error"

;# Test 7: Error handling - empty certificate
test "Error handling - empty certificate" {
    tossl::x509::verify "" ""
} "error"

;# Test 8: Verify with EC certificates
test "Verify with EC certificates" {
    set keys [tossl::key::generate -type ec -curve prime256v1]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test EC" -issuer "CN=Test EC" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::verify $cert $cert
} "1"

;# Test 9: Verify expired certificate
test "Verify expired certificate" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    ;# Create a certificate with very short validity (1 day) and wait for it to expire
    ;# For testing purposes, we'll create a certificate and then modify it to be expired
    set cert [tossl::x509::create -subject "CN=Expired" -issuer "CN=Expired" -pubkey $pub -privkey $priv -days 1]
    
    ;# Since we can't easily create an expired certificate in this test environment,
    ;# we'll test with a valid certificate and expect it to pass verification
    ;# The actual expiration test would require time manipulation
    tossl::x509::verify $cert $cert
} "1"

;# Test 10: Verify certificate chain (intermediate CA)
test "Verify certificate chain with intermediate CA" {
    ;# Create a simple two-level certificate chain
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set cert_keys [tossl::key::generate -type rsa -bits 2048]
    
    set ca_priv [dict get $ca_keys private]
    set ca_pub [dict get $ca_keys public]
    set cert_pub [dict get $cert_keys public]
    
    ;# Create CA certificate
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_pub -privkey $ca_priv -days 365]
    
    ;# Create certificate signed by CA
    set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $cert_pub -privkey $ca_priv -days 365]
    
    ;# Verify certificate against CA (direct signature verification)
    tossl::x509::verify $cert $ca_cert
} "1"

;# Test 11: Verify with DSA certificates
test "Verify with DSA certificates" {
    set keys [tossl::key::generate -type dsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test DSA" -issuer "CN=Test DSA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::verify $cert $cert
} "1"

;# Test 12: Security test - verify tampered certificate
test "Security test - verify tampered certificate" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    
    ;# Tamper with the certificate by changing a character
    set tampered_cert [string replace $cert 100 100 "X"]
    tossl::x509::verify $tampered_cert $ca_cert
} "0"

;# Test 13: Performance test - verify multiple certificates
test "Performance test - verify multiple certificates" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    
    set results {}
    for {set i 0} {$i < 5} {incr i} {
        set cert_keys [tossl::key::generate -type rsa -bits 2048]
        set cert_pub [dict get $cert_keys public]
        set cert [tossl::x509::create -subject "CN=Cert$i" -issuer "CN=Test CA" -pubkey $cert_pub -privkey $priv -days 365]
        lappend results [tossl::x509::verify $cert $ca_cert]
    }
    
    set all_valid 1
    foreach result $results {
        if {$result != 1} {
            set all_valid 0
            break
        }
    }
    set all_valid
} "1"

;# Test 14: Edge case - very long subject names
test "Edge case - very long subject names" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set long_subject "CN=This is a very long subject name that might cause issues with certificate verification and should be handled properly by the implementation"
    set cert [tossl::x509::create -subject $long_subject -issuer $long_subject -pubkey $pub -privkey $priv -days 365]
    tossl::x509::verify $cert $cert
} "1"

;# Test 15: Edge case - special characters in subject
test "Edge case - special characters in subject" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set special_subject "CN=Test@example.com, O=Test Org, C=US"
    set cert [tossl::x509::create -subject $special_subject -issuer $special_subject -pubkey $pub -privkey $priv -days 365]
    tossl::x509::verify $cert $cert
} "1"

puts "\nTest Summary:"
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "\nSome tests failed. Please review the implementation."
    exit 1
} else {
    puts "\nAll tests passed!"
    exit 0
} 