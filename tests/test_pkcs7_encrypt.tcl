#!/usr/bin/env tclsh

;# Test script for ::tossl::pkcs7::encrypt command
;# Tests PKCS7/CMS encryption (single and multi-recipient)

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

puts "Testing ::tossl::pkcs7::encrypt command..."

;# Generate test certificate and key
set keys1 [tossl::key::generate -type rsa -bits 2048]
set key1 [dict get $keys1 private]
set pub1 [dict get $keys1 public]
set cert1 [tossl::x509::create -subject "Test Cert 1" -issuer "Test Cert 1" -pubkey $pub1 -privkey $key1 -days 365]
set keys2 [tossl::key::generate -type rsa -bits 2048]
set key2 [dict get $keys2 private]
set pub2 [dict get $keys2 public]
set cert2 [tossl::x509::create -subject "Test Cert 2" -issuer "Test Cert 2" -pubkey $pub2 -privkey $key2 -days 365]
set data "secret message"

;# Test 1: Single recipient
puts "\n1. Testing single recipient..."
set enc_result [catch {tossl::pkcs7::encrypt -data $data -cert $cert1} encrypted]
if {$enc_result == 0} {
    puts "PASS: Single recipient encryption"
    set dec_result [catch {tossl::pkcs7::decrypt $encrypted $key1} decrypted]
    if {$dec_result == 0 && $decrypted eq $data} {
        puts "PASS: Single recipient decrypt round-trip"
    } else {
        puts "FAIL: Single recipient decrypt failed: $decrypted"
        incr ::errors
    }
} else {
    puts "FAIL: Single recipient encryption failed: $encrypted"
    incr ::errors
}

;# Test 2: Multi-recipient
puts "\n2. Testing multi-recipient..."
set enc_result [catch {tossl::pkcs7::encrypt -data $data -cert $cert1 -cert $cert2} encrypted]
if {$enc_result == 0} {
    puts "PASS: Multi-recipient encryption"
    set dec_result1 [catch {tossl::pkcs7::decrypt $encrypted $key1} decrypted1]
    set dec_result2 [catch {tossl::pkcs7::decrypt $encrypted $key2} decrypted2]
    if {$dec_result1 == 0 && $decrypted1 eq $data && $dec_result2 == 0 && $decrypted2 eq $data} {
        puts "PASS: Multi-recipient decrypt round-trip (both keys)"
    } else {
        puts "FAIL: Multi-recipient decrypt failed: $decrypted1 / $decrypted2"
        incr ::errors
    }
} else {
    puts "FAIL: Multi-recipient encryption failed: $encrypted"
    incr ::errors
}

;# Test 3: Error handling
puts "\n3. Testing error handling..."
test_error "missing arguments" {tossl::pkcs7::encrypt}
test_error "invalid cert" {tossl::pkcs7::encrypt -data $data -cert "notacert"}

;# Summary
puts "\n=== Test Summary ==="
if {$::errors == 0} {
    puts "ALL TESTS PASSED"
    exit 0
} else {
    puts "FAILED: $::errors test(s)"
    exit 1
} 