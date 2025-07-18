#!/usr/bin/env tclsh

;# Test script for ::tossl::x448::generate and ::tossl::x448::derive
;# Tests X448 key generation and key agreement

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

puts "Testing ::tossl::x448::generate and ::tossl::x448::derive..."

;# Test 1: Key generation
puts "\n1. Testing key generation..."
set priv1 [tossl::x448::generate]
set priv2 [tossl::x448::generate]
if {[string match *BEGIN* $priv1] && [string match *BEGIN* $priv2]} {
    puts "PASS: X448 key generation"
} else {
    puts "FAIL: X448 key generation output"
    incr ::errors
}

;# Test 2: Key agreement (shared secret)
puts "\n2. Testing key agreement..."
;# Extract public keys
set pub1 [tossl::key::getpub -key $priv1]
set pub2 [tossl::key::getpub -key $priv2]
set secret1 [tossl::x448::derive $priv1 $pub2]
set secret2 [tossl::x448::derive $priv2 $pub1]
if {$secret1 eq $secret2} {
    puts "PASS: X448 key agreement (shared secret matches)"
} else {
    puts "FAIL: X448 key agreement mismatch"
    incr ::errors
}

;# Test 3: Error handling
puts "\n3. Testing error handling..."
test_error "missing arguments" {tossl::x448::derive}
test_error "invalid private key" {tossl::x448::derive "notakey" $pub2}
test_error "invalid public key" {tossl::x448::derive $priv1 "notapub"}

;# Summary
puts "\n=== Test Summary ==="
if {$::errors == 0} {
    puts "ALL TESTS PASSED"
    exit 0
} else {
    puts "FAILED: $::errors test(s)"
    exit 1
} 