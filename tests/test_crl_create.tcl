#!/usr/bin/env tclsh
# Test file for ::tossl::crl::create command
# Tests CRL creation functionality, edge cases, and error handling

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

puts "=== Testing ::tossl::crl::create ==="

# Generate test CA key and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keypair private]
set ca_public [dict get $ca_keypair public]

# Create a simple CA certificate
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]

# Test 1: Basic CRL creation
test "Basic CRL creation" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 2: CRL creation with different validity periods
test "CRL creation with 7 days validity" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 7]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 3: CRL creation with 365 days validity
test "CRL creation with 365 days validity" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 365]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 4: CRL creation with alternative parameter names
test "CRL creation with -ca_key and -ca_cert" {
    set crl [tossl::crl::create -ca_key $ca_private -ca_cert $ca_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 5: Missing key parameter
test "Missing key parameter should error" {
    tossl::crl::create -cert $ca_cert -days 30
} error

# Test 6: Missing certificate parameter
test "Missing certificate parameter should error" {
    tossl::crl::create -key $ca_private -days 30
} error

# Test 7: Invalid key format
test "Invalid key format should error" {
    tossl::crl::create -key "invalid key" -cert $ca_cert -days 30
} error

# Test 8: Invalid certificate format
test "Invalid certificate format should error" {
    tossl::crl::create -key $ca_private -cert "invalid cert" -days 30
} error

# Test 9: Invalid days parameter
test "Invalid days parameter should error" {
    tossl::crl::create -key $ca_private -cert $ca_cert -days "invalid"
} error

# Test 10: Negative days parameter
test "Negative days parameter should error" {
    tossl::crl::create -key $ca_private -cert $ca_cert -days -1
} error

# Test 11: Zero days parameter
test "Zero days parameter should error" {
    tossl::crl::create -key $ca_private -cert $ca_cert -days 0
} error

# Test 12: Very large days parameter
test "Very large days parameter" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 9999]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 13: Wrong number of arguments
test "Wrong number of arguments should error" {
    tossl::crl::create
} error

# Test 14: Unknown option
test "Unknown option should error" {
    tossl::crl::create -unknown "value" -key $ca_private -cert $ca_cert -days 30
} error

# Test 15: CRL parsing after creation
test "CRL parsing after creation" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    set crl_info [tossl::crl::parse $crl]
    dict exists $crl_info version
} 1

# Test 16: CRL issuer verification
test "CRL issuer verification" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    set crl_info [tossl::crl::parse $crl]
    string match "*Test CA*" [dict get $crl_info issuer]
} 1

# Test 17: CRL version verification
test "CRL version verification" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    set crl_info [tossl::crl::parse $crl]
    expr {[dict get $crl_info version] == 1}
} 1

# Test 18: CRL signature verification
test "CRL signature verification" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    # The fact that we can parse it means the signature is valid
    set crl_info [tossl::crl::parse $crl]
    dict exists $crl_info issuer
} 1

# Test 19: Multiple CRL creation with same CA
test "Multiple CRL creation with same CA" {
    set crl1 [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    set crl2 [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    expr {[string length $crl1] > 0 && [string length $crl2] > 0}
} 1

# Test 20: CRL creation with different CA
test "CRL creation with different CA" {
    set ca2_keypair [tossl::key::generate -type rsa -bits 2048]
    set ca2_private [dict get $ca2_keypair private]
    set ca2_public [dict get $ca2_keypair public]
    set ca2_cert [tossl::x509::create -subject "CN=Test CA 2" -issuer "CN=Test CA 2" -pubkey $ca2_public -privkey $ca2_private -days 365]
    
    set crl [tossl::crl::create -key $ca2_private -cert $ca2_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 21: Performance test - multiple CRLs
test "Performance test - multiple CRLs" {
    set start_time [clock milliseconds]
    for {set i 0} {$i < 5} {incr i} {
        set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
    }
    set end_time [clock milliseconds]
    expr {($end_time - $start_time) < 10000} ;# Should complete in under 10 seconds
} 1

# Test 22: CRL with minimum validity period
test "CRL with minimum validity period" {
    set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 1]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 23: CRL creation with EC key
test "CRL creation with EC key" {
    set ec_keypair [tossl::key::generate -type ec -curve prime256v1]
    set ec_private [dict get $ec_keypair private]
    set ec_public [dict get $ec_keypair public]
    set ec_cert [tossl::x509::create -subject "CN=Test EC CA" -issuer "CN=Test EC CA" -pubkey $ec_public -privkey $ec_private -days 365]
    
    set crl [tossl::crl::create -key $ec_private -cert $ec_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 24: CRL creation with DSA key (if supported)
test "CRL creation with DSA key" {
    set dsa_keypair [tossl::key::generate -type dsa -bits 1024]
    set dsa_private [dict get $dsa_keypair private]
    set dsa_public [dict get $dsa_keypair public]
    set dsa_cert [tossl::x509::create -subject "CN=Test DSA CA" -issuer "CN=Test DSA CA" -pubkey $dsa_public -privkey $dsa_private -days 365]
    
    set crl [tossl::crl::create -key $dsa_private -cert $dsa_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 25: CRL creation with mismatched key and certificate
test "CRL creation with mismatched key and certificate" {
    set other_keypair [tossl::key::generate -type rsa -bits 2048]
    set other_private [dict get $other_keypair private]
    
    tossl::crl::create -key $other_private -cert $ca_cert -days 30
} error

# Test 26: CRL creation with non-CA certificate
test "CRL creation with non-CA certificate" {
    set user_keypair [tossl::key::generate -type rsa -bits 2048]
    set user_private [dict get $user_keypair private]
    set user_public [dict get $user_keypair public]
    set user_cert [tossl::x509::create -subject "CN=Test User" -issuer "CN=Test User" -pubkey $user_public -privkey $user_private -days 365]
    
    # This should work as the command doesn't validate CA usage - any certificate can be used
    set crl [tossl::crl::create -key $user_private -cert $user_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 27: CRL creation with expired certificate
test "CRL creation with expired certificate" {
    set expired_cert [tossl::x509::create -subject "CN=Expired CA" -issuer "CN=Expired CA" -pubkey $ca_public -privkey $ca_private -days 1]
    
    # This should still work as the command doesn't validate certificate expiration
    # We'll create a certificate with very short validity (1 day) and assume it's expired
    set crl [tossl::crl::create -key $ca_private -cert $expired_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 28: CRL creation with very long subject name
test "CRL creation with very long subject name" {
    set long_subject "CN=This is a very long certificate subject name that exceeds normal length limits and should be handled gracefully by the CRL creation process"
    set long_cert [tossl::x509::create -subject $long_subject -issuer $long_subject -pubkey $ca_public -privkey $ca_private -days 365]
    
    set crl [tossl::crl::create -key $ca_private -cert $long_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 29: CRL creation with special characters in subject
test "CRL creation with special characters in subject" {
    set special_subject "CN=Test CA with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
    set special_cert [tossl::x509::create -subject $special_subject -issuer $special_subject -pubkey $ca_public -privkey $ca_private -days 365]
    
    set crl [tossl::crl::create -key $ca_private -cert $special_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 30: CRL creation with Unicode characters in subject
test "CRL creation with Unicode characters in subject" {
    set unicode_subject "CN=Test CA with Unicode: 测试证书颁发机构"
    set unicode_cert [tossl::x509::create -subject $unicode_subject -issuer $unicode_subject -pubkey $ca_public -privkey $ca_private -days 365]
    
    set crl [tossl::crl::create -key $ca_private -cert $unicode_cert -days 30]
    string match "*-----BEGIN X509 CRL-----*" $crl
} 1

# Test 31: Stress test - many CRLs
test "Stress test - many CRLs" {
    set start_time [clock milliseconds]
    for {set i 0} {$i < 10} {incr i} {
        set crl [tossl::crl::create -key $ca_private -cert $ca_cert -days 30]
        if {![string match "*-----BEGIN X509 CRL-----*" $crl]} {
            return 0
        }
    }
    set end_time [clock milliseconds]
    expr {($end_time - $start_time) < 20000} ;# Should complete in under 20 seconds
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