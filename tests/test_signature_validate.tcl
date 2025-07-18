#!/usr/bin/env tclsh

# Test script for ::tossl::signature::validate command
# This script tests signature validation functionality

# Load the TOSSL extension
if {[catch {load ./libtossl.so} err]} {
    puts "Error loading TOSSL extension: $err"
    exit 1
}

# Test counter
set test_count 0
set passed_count 0

# Test procedure
proc test_signature_validate {test_name expected_result args} {
    global test_count passed_count
    incr test_count
    
    puts -nonewline "Test $test_count: $test_name... "
    
    set result [catch {eval ::tossl::signature::validate $args} output]
    
    if {$result == 0} {
        if {[string is list $expected_result]} {
            if {$output in $expected_result} {
                puts "PASSED"
                incr passed_count
                return
            }
        } elseif {$output eq $expected_result} {
            puts "PASSED"
            incr passed_count
            return
        }
        puts "FAILED (expected: $expected_result, got: $output)"
    } else {
        if {$expected_result eq "ERROR"} {
            puts "PASSED (expected error: $output)"
            incr passed_count
        } else {
            puts "FAILED (unexpected error: $output)"
        }
    }
}

# Generate test key pair for RSA
puts "Generating RSA test key pair..."
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_private_key [dict get $rsa_keys private]
set rsa_public_key [dict get $rsa_keys public]

# Generate test key pair for EC
puts "Generating EC test key pair..."
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_private_key [dict get $ec_keys private]
set ec_public_key [dict get $ec_keys public]

# Test data
set test_data "Hello, World! This is a test message for signature validation."
set test_data_empty ""
set test_data_large [string repeat "A" 10000]

# Create signatures for testing
puts "Creating test signatures..."
set rsa_signature_binary_sha256 [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha256]
set rsa_signature_binary_sha1 [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha1]
set ec_signature_binary_sha256 [tossl::ec::sign $ec_private_key $test_data sha256]

# Convert binary signatures to hex format for signature validate command
binary scan $rsa_signature_binary_sha256 H* rsa_signature_sha256
binary scan $rsa_signature_binary_sha1 H* rsa_signature_sha1
binary scan $ec_signature_binary_sha256 H* ec_signature_sha256

puts "\n=== Testing ::tossl::signature::validate ==="

# NOTE: The current implementation of ::tossl::signature::validate appears to have
# issues with signature verification. Valid signatures are being reported as invalid.
# This may be due to a mismatch between the verification method used and the 
# signature format expected. The tests below document the current behavior.

# Test 1: RSA signature with SHA-256 (now should be valid)
test_signature_validate "RSA signature with SHA-256" "valid" \
    $rsa_public_key $test_data $rsa_signature_sha256 "sha256"

# Test 2: RSA signature with SHA-1 (now should be valid)
test_signature_validate "RSA signature with SHA-1" "valid" \
    $rsa_public_key $test_data $rsa_signature_sha1 "sha1"

# Test 3: EC signature with SHA-256 (now should be valid)
test_signature_validate "EC signature with SHA-256" "valid" \
    $ec_public_key $test_data $ec_signature_sha256 "sha256"

# Test 4: Invalid signature (wrong data)
test_signature_validate "Invalid signature (wrong data)" "invalid" \
    $rsa_public_key "Different data" $rsa_signature_sha256 "sha256"

# Test 5: Invalid signature (corrupted signature)
set corrupted_signature [string replace $rsa_signature_sha256 0 1 "FF"]
test_signature_validate "Invalid signature (corrupted)" "invalid" \
    $rsa_public_key $test_data $corrupted_signature "sha256"

# Test 6: Invalid signature (wrong key)
test_signature_validate "Invalid signature (wrong key)" "invalid" \
    $ec_public_key $test_data $rsa_signature_sha256 "sha256"

# Test 7: Empty data (now should be valid)
set empty_signature_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data_empty -alg sha256]
binary scan $empty_signature_binary H* empty_signature
test_signature_validate "Signature with empty data" "valid" \
    $rsa_public_key $test_data_empty $empty_signature "sha256"

# Test 8: Large data (now should be valid)
set large_signature_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data_large -alg sha256]
binary scan $large_signature_binary H* large_signature
test_signature_validate "Signature with large data" "valid" \
    $rsa_public_key $test_data_large $large_signature "sha256"

# Test 9: Different digest algorithms (now should be valid)
set sig_512_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha512]
binary scan $sig_512_binary H* sig_512
test_signature_validate "Signature with SHA-512" "valid" \
    $rsa_public_key $test_data $sig_512 "sha512"

set sig_384_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha384]
binary scan $sig_384_binary H* sig_384
test_signature_validate "Signature with SHA-384" "valid" \
    $rsa_public_key $test_data $sig_384 "sha384"

# Error handling tests

# Test 10: Wrong number of arguments
test_signature_validate "Error: Too few arguments" "ERROR" \
    $rsa_public_key $test_data

# Test 11: Wrong number of arguments (too many)
test_signature_validate "Error: Too many arguments" "ERROR" \
    $rsa_public_key $test_data $rsa_signature_sha256 "sha256" "extra"

# Test 12: Invalid public key
test_signature_validate "Error: Invalid public key" "ERROR" \
    "invalid-key-data" $test_data $rsa_signature_sha256 "sha256"

# Test 13: Invalid digest algorithm
test_signature_validate "Error: Invalid digest algorithm" "ERROR" \
    $rsa_public_key $test_data $rsa_signature_sha256 "invalid-digest"

# Test 14: Invalid signature format (non-hex) - returns invalid instead of error
test_signature_validate "Invalid signature format (non-hex)" "invalid" \
    $rsa_public_key $test_data "not-hex-data" "sha256"

# Test 15: Invalid signature format (odd length hex) - returns invalid instead of error
test_signature_validate "Invalid signature format (odd length)" "invalid" \
    $rsa_public_key $test_data "ABC" "sha256"

# Cross-validation tests

# Test 16: RSA signature with EC key
test_signature_validate "Invalid: RSA signature with EC key" "invalid" \
    $ec_public_key $test_data $rsa_signature_sha256 "sha256"

# Test 17: EC signature with RSA key  
test_signature_validate "Invalid: EC signature with RSA key" "invalid" \
    $rsa_public_key $test_data $ec_signature_sha256 "sha256"

# Test 18: Wrong digest algorithm for signature
test_signature_validate "Invalid: Wrong digest algorithm" "invalid" \
    $rsa_public_key $test_data $rsa_signature_sha256 "sha1"

# Performance tests

# Test 19: Performance test with multiple validations
puts -nonewline "Test 19: Performance: Multiple validations... "
set start_time [clock milliseconds]
for {set i 0} {$i < 100} {incr i} {
    ::tossl::signature::validate $rsa_public_key $test_data $rsa_signature_sha256 "sha256"
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "PASSED (100 validations in ${duration}ms)"
incr test_count
incr passed_count

# Test 20: Stress test with different key sizes (documenting current behavior)
puts -nonewline "Test 20: Stress: Different key sizes (known issues)... "
set stress_passed 0
set stress_total 0

# Test with 1024-bit RSA (now should be valid)
catch {
    set rsa_1024_keys [tossl::key::generate -type rsa -bits 1024]
    set rsa_1024_priv [dict get $rsa_1024_keys private]
    set rsa_1024_pub [dict get $rsa_1024_keys public]
    set sig_1024_binary [tossl::rsa::sign -key $rsa_1024_priv -data $test_data -alg sha256]
    binary scan $sig_1024_binary H* sig_1024
    set result [::tossl::signature::validate $rsa_1024_pub $test_data $sig_1024 "sha256"]
    if {$result eq "valid"} {incr stress_passed}
    incr stress_total
}

# Test with 4096-bit RSA (now should be valid)
catch {
    set rsa_4096_keys [tossl::key::generate -type rsa -bits 4096]
    set rsa_4096_priv [dict get $rsa_4096_keys private]
    set rsa_4096_pub [dict get $rsa_4096_keys public]
    set sig_4096_binary [tossl::rsa::sign -key $rsa_4096_priv -data $test_data -alg sha256]
    binary scan $sig_4096_binary H* sig_4096
    set result [::tossl::signature::validate $rsa_4096_pub $test_data $sig_4096 "sha256"]
    if {$result eq "valid"} {incr stress_passed}
    incr stress_total
}

# Test with different EC curves (now should be valid)
foreach curve {secp384r1 secp521r1} {
    catch {
        set ec_keys [tossl::key::generate -type ec -curve $curve]
        set ec_priv [dict get $ec_keys private]
        set ec_pub [dict get $ec_keys public]
        set ec_sig_binary [tossl::ec::sign $ec_priv $test_data sha256]
        binary scan $ec_sig_binary H* ec_sig
        set result [::tossl::signature::validate $ec_pub $test_data $ec_sig "sha256"]
        if {$result eq "valid"} {incr stress_passed}
        incr stress_total
    }
}

if {$stress_passed == $stress_total && $stress_total > 0} {
    puts "PASSED ($stress_passed/$stress_total consistent results)"
    incr passed_count
} else {
    puts "FAILED ($stress_passed/$stress_total consistent results)"
}
incr test_count

# Summary
puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: [expr {$test_count - $passed_count}]"

if {$passed_count == $test_count} {
    puts "All tests passed!"
    exit 0
} else {
    puts "Some tests failed!"
    exit 1
}
