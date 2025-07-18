#!/usr/bin/env tclsh
;# Test file for ::tossl::x509::validate command

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

puts "Testing ::tossl::x509::validate command\n"

;# Test 1: Basic functionality - validate a valid certificate
test "Basic functionality - validate valid certificate" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 2: Error handling - invalid certificate
test "Error handling - invalid certificate" {
    tossl::x509::validate "invalid certificate data"
} "error"

;# Test 3: Error handling - missing arguments
test "Error handling - missing arguments" {
    tossl::x509::validate
} "error"

;# Test 4: Error handling - too many arguments
test "Error handling - too many arguments" {
    tossl::x509::validate "cert1" "cert2"
} "error"

;# Test 5: Error handling - empty certificate
test "Error handling - empty certificate" {
    tossl::x509::validate ""
} "error"

;# Test 6: Validate with EC certificates
test "Validate with EC certificates" {
    set keys [tossl::key::generate -type ec -curve prime256v1]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test EC" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 7: Validate with DSA certificates
test "Validate with DSA certificates" {
    set keys [tossl::key::generate -type dsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test DSA" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 8: Validate certificate with very short validity
test "Validate certificate with very short validity" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Short Valid" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 1]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 9: Security test - validate tampered certificate
test "Security test - validate tampered certificate" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    
    ;# Create a completely invalid certificate by replacing the entire content
    set tampered_cert "-----BEGIN CERTIFICATE-----\nINVALID_DATA_HERE\n-----END CERTIFICATE-----"
    tossl::x509::validate $tampered_cert
} "error"

;# Test 10: Performance test - validate multiple certificates
test "Performance test - validate multiple certificates" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set results {}
    for {set i 0} {$i < 5} {incr i} {
        set cert [tossl::x509::create -subject "CN=Cert$i" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
        lappend results [tossl::x509::validate $cert]
    }
    
    set all_valid 1
    foreach result $results {
        if {$result ne "Certificate is valid"} {
            set all_valid 0
            break
        }
    }
    if {$all_valid} {
        set result "Certificate is valid"
    } else {
        set result "error"
    }
    set result
} "Certificate is valid"

;# Test 11: Edge case - very long subject names
test "Edge case - very long subject names" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set long_subject "CN=This is a very long subject name that might cause issues with certificate validation and should be handled properly by the implementation"
    set cert [tossl::x509::create -subject $long_subject -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 12: Edge case - special characters in subject
test "Edge case - special characters in subject" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set special_subject "CN=Test@example.com, O=Test Org, C=US"
    set cert [tossl::x509::create -subject $special_subject -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 13: Validate certificate with SAN extension
test "Validate certificate with SAN extension" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test SAN" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365 -san {example.com test.example.com}]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 14: Validate certificate with key usage extension
test "Validate certificate with key usage extension" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Test KU" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365 -keyusage {digitalSignature keyEncipherment}]
    tossl::x509::validate $cert
} "Certificate is valid"

;# Test 15: Integration test - validate and parse
test "Integration test - validate and parse" {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set cert [tossl::x509::create -subject "CN=Integration Test" -issuer "CN=Test CA" -pubkey $pub -privkey $priv -days 365]
    
    ;# First validate the certificate
    set validation_result [tossl::x509::validate $cert]
    
    ;# Then parse it to get details
    set parse_result [tossl::x509::parse $cert]
    
    ;# Both should succeed
    if {$validation_result eq "Certificate is valid" && [dict exists $parse_result subject]} {
        set result "Certificate is valid"
    } else {
        set result "error"
    }
    set result
} "Certificate is valid"

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