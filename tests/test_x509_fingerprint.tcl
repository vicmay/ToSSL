#!/usr/bin/env tclsh
;# Test file for ::tossl::x509::fingerprint command
;# Tests certificate fingerprinting functionality, edge cases, and error handling

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

puts "=== Testing ::tossl::x509::fingerprint ==="

;# Generate a test certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

;# Create a self-signed certificate
set cert [tossl::x509::create -subject "/CN=Test Certificate" -issuer "/CN=Test Certificate" -pubkey $pub -privkey $priv -days 365]

;# Test 1: Basic fingerprint with SHA256
test "Basic fingerprint with SHA256" {
    set fp [tossl::x509::fingerprint $cert sha256]
    expr {[string length $fp] == 64}
} 1

;# Test 2: Fingerprint with SHA1
test "Fingerprint with SHA1" {
    set fp [tossl::x509::fingerprint $cert sha1]
    expr {[string length $fp] == 40}
} 1

;# Test 3: Fingerprint with SHA512
test "Fingerprint with SHA512" {
    set fp [tossl::x509::fingerprint $cert sha512]
    expr {[string length $fp] == 128}
} 1

;# Test 4: Fingerprint with MD5 (if supported)
test "Fingerprint with MD5" {
    set fp [tossl::x509::fingerprint $cert md5]
    expr {[string length $fp] == 32}
} 1

;# Test 5: Same certificate should produce same fingerprint
test "Same certificate produces same fingerprint" {
    set fp1 [tossl::x509::fingerprint $cert sha256]
    set fp2 [tossl::x509::fingerprint $cert sha256]
    expr {$fp1 eq $fp2}
} 1

;# Test 6: Different algorithms produce different fingerprints
test "Different algorithms produce different fingerprints" {
    set fp1 [tossl::x509::fingerprint $cert sha256]
    set fp2 [tossl::x509::fingerprint $cert sha1]
    expr {$fp1 ne $fp2}
} 1

;# Test 7: Invalid certificate should error
test "Invalid certificate should error" {
    tossl::x509::fingerprint "not a certificate" sha256
} error

;# Test 8: Empty certificate should error
test "Empty certificate should error" {
    tossl::x509::fingerprint "" sha256
} error

;# Test 9: Unknown digest algorithm should error
test "Unknown digest algorithm should error" {
    tossl::x509::fingerprint $cert notadigest
} error

;# Test 10: Missing arguments should error
test "Missing arguments should error" {
    tossl::x509::fingerprint $cert
} error

;# Test 11: Too many arguments should error
test "Too many arguments should error" {
    tossl::x509::fingerprint $cert sha256 extra
} error

;# Test 12: Fingerprint format should be hex
test "Fingerprint format should be hex" {
    set fp [tossl::x509::fingerprint $cert sha256]
    regexp {^[a-f0-9]+$} $fp
} 1

;# Test 13: Different certificates should produce different fingerprints
test "Different certificates produce different fingerprints" {
    set cert2 [tossl::x509::create -subject "/CN=Test Certificate 2" -issuer "/CN=Test Certificate 2" -pubkey $pub -privkey $priv -days 365]
    set fp1 [tossl::x509::fingerprint $cert sha256]
    set fp2 [tossl::x509::fingerprint $cert2 sha256]
    expr {$fp1 ne $fp2}
} 1

;# Test 14: Test with a CA-signed certificate
test "CA-signed certificate fingerprint" {
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_priv [dict get $ca_keys private]
    set ca_pub [dict get $ca_keys public]
    set ca_cert [tossl::ca::generate -key $ca_priv -subject "/CN=Test CA" -days 3650]
    set csr [tossl::csr::create -key $priv -subject [dict create CN "Test User"]]
    set signed_cert [tossl::ca::sign -ca_key $ca_priv -ca_cert $ca_cert -csr $csr -days 365]
    set fp [tossl::x509::fingerprint $signed_cert sha256]
    expr {[string length $fp] == 64}
} 1

;# Test 15: Test with DER certificate (should fail)
test "DER certificate should error" {
    set der_cert [tossl::key::convert -key $cert -from pem -to der]
    tossl::x509::fingerprint $der_cert sha256
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