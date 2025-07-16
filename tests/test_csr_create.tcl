#!/usr/bin/env tclsh

package require tossl

# Generate RSA key pair
set keypair [tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]

# Test: Create CSR with minimal subject (string)
set csr [tossl::csr::create -key $privkey -subject "CN=test.example.com"]
puts "CSR created: $csr"

# Test: Parse CSR
set info [tossl::csr::parse $csr]
puts "Parsed CSR: $info"
if {[dict get $info subject] eq ""} {
    puts "FAIL: CSR subject missing"
    exit 1
}

# Test: Validate CSR
set valid [tossl::csr::validate $csr]
puts "CSR valid: $valid"
if {!$valid} {
    puts "FAIL: CSR did not validate"
    exit 1
}

# Test: Create CSR with subject as dict and extensions/attributes
set subject [dict create CN alt.example.com O ExampleOrg]
set extensions [list [dict create oid subjectAltName value {DNS:alt.example.com,DNS:www.alt.example.com} critical 0] [dict create oid keyUsage value {digitalSignature,keyEncipherment} critical 1]]
set attributes [list [dict create oid challengePassword value mypassword]]
set csr2 [tossl::csr::create -key $privkey -subject $subject -extensions $extensions -attributes $attributes]
puts "CSR with extensions: $csr2"
set info2 [tossl::csr::parse $csr2]
puts "Parsed CSR2: $info2"

# Test: Error on missing arguments
set errorCaught 0
if {[catch {tossl::csr::create -key $privkey} err]} {
    set errorCaught 1
}
if {!$errorCaught} {
    puts "FAIL: Missing subject did not error"
    exit 1
}

# Test: Error on invalid key
set errorCaught 0
if {[catch {tossl::csr::create -key "not-a-key" -subject "CN=fail.example.com"} err]} {
    set errorCaught 1
}
if {!$errorCaught} {
    puts "FAIL: Invalid key did not error"
    exit 1
}

puts "PASS: All tests passed"
exit 0 