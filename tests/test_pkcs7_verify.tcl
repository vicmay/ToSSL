#!/usr/bin/env tclsh

;# Test script for ::tossl::pkcs7::verify command
;# Tests PKCS7/CMS signature verification (attached and detached)

package require tossl

set ::errors 0

proc test {name script expected} {
    set result [catch {uplevel 1 $script} output]
    if {$result == 0 && $output eq $expected} {
        puts "PASS: $name"
    } else {
        puts "FAIL: $name - expected '$expected', got '$output'"
        incr ::errors
    }
}

proc test_error {name script} {
    set result [catch {uplevel 1 $script} output]
    if {$result != 0} {
        puts "PASS: $name (error as expected: $output)"
    } else {
        puts "FAIL: $name - expected error, got '$output'"
        incr ::errors
    }
}

puts "Testing ::tossl::pkcs7::verify command..."

;# Generate test certificate and key
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set data "signed data"

;# Test 1: Attached signature
puts "\n1. Testing attached signature..."
set sig_result [catch {tossl::pkcs7::sign -data $data -key $key -cert $cert} sig]
if {$sig_result == 0} {
    set verify_result [catch {tossl::pkcs7::verify -ca $cert $sig $data} valid]
    if {$verify_result == 0 && $valid == 1} {
        puts "PASS: Attached signature verified"
    } else {
        puts "FAIL: Attached signature verify failed: $valid"
        incr ::errors
    }
} else {
    puts "FAIL: Signature creation failed: $sig"
    incr ::errors
}

;# Test 2: Detached signature
puts "\n2. Testing detached signature..."
set sig_result [catch {tossl::pkcs7::sign -data $data -key $key -cert $cert -detached 1} sig]
if {$sig_result == 0} {
    set verify_result [catch {tossl::pkcs7::verify -ca $cert $sig $data} valid]
    if {$verify_result == 0 && $valid == 1} {
        puts "PASS: Detached signature verified"
    } else {
        puts "FAIL: Detached signature verify failed: $valid"
        incr ::errors
    }
} else {
    puts "FAIL: Detached signature creation failed: $sig"
    incr ::errors
}

;# Test 3: Error handling (invalid signature)
puts "\n3. Testing error handling..."
test "invalid signature" {tossl::pkcs7::verify -ca $cert "notasig" $data} 0

test_error "missing arguments" {tossl::pkcs7::verify}

test_error "wrong ca" {tossl::pkcs7::verify -ca "notaca" $sig $data}

;# Summary
puts "\n=== Test Summary ==="
if {$::errors == 0} {
    puts "ALL TESTS PASSED"
    exit 0
} else {
    puts "FAILED: $::errors test(s)"
    exit 1
} 