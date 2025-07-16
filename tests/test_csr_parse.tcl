#!/usr/bin/env tclsh

package require tossl

# Generate RSA key pair
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]

# Create a CSR with subject and extensions
set subject [dict create CN test.example.com O ExampleOrg]
set extensions [list [dict create oid subjectAltName value {DNS:test.example.com,DNS:www.test.example.com} critical 0] [dict create oid keyUsage value {digitalSignature,keyEncipherment} critical 1]]
set csr [tossl::csr::create -key $privkey -subject $subject -extensions $extensions]
puts "CSR created: $csr"

# Test: Parse valid CSR
set info [tossl::csr::parse $csr]
puts "Parsed CSR: $info"
if {![dict exists $info subject]} {
    puts "FAIL: Parsed CSR missing subject"
    exit 1
}
if {![dict exists $info key_type]} {
    puts "FAIL: Parsed CSR missing key_type"
    exit 1
}
# Print extensions field for debugging
if {[dict exists $info extensions]} {
    puts "Extensions: [dict get $info extensions]"
} else {
    puts "Extensions field missing (may be empty if no extensions present)"
}

# Test: Tampered CSR
set tampered [string replace $csr 50 50 X]
set result [catch {tossl::csr::parse $tampered} err]
if {!$result} {
    puts "FAIL: Tampered CSR did not error"
    exit 1
} else {
    puts "PASS: Tampered CSR error: $err"
}

# Test: Invalid input
set result2 [catch {tossl::csr::parse "not-a-csr"} err2]
if {!$result2} {
    puts "FAIL: Invalid input did not error"
    exit 1
} else {
    puts "PASS: Invalid input error: $err2"
}

puts "PASS: All tests passed"
exit 0 