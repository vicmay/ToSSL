#!/usr/bin/env tclsh

package require tossl

# Generate RSA key pair
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]

# Create a valid CSR
set csr [tossl::csr::create -key $privkey -subject "CN=test.example.com"]
puts "CSR created: $csr"

# Test: Validate valid CSR
set valid [tossl::csr::validate $csr]
puts "Valid CSR: $valid"
if {!$valid} {
    puts "FAIL: Valid CSR did not validate"
    exit 1
}

# Test: Tamper with CSR (change a byte)
set tampered [string replace $csr 50 50 X]
set valid2 [catch {tossl::csr::validate $tampered} err2]
if {!$valid2} {
    puts "FAIL: Tampered CSR did not error"
    exit 1
} else {
    puts "PASS: Tampered CSR error: $err2"
}

# Test: Invalid input
set valid3 [catch {tossl::csr::validate "not-a-csr"} err3]
if {!$valid3} {
    puts "FAIL: Invalid input did not error"
    exit 1
} else {
    puts "PASS: Invalid input error: $err3"
}

puts "PASS: All tests passed"
exit 0 