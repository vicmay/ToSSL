#!/usr/bin/env tclsh

# Test for ::tossl::csr::fingerprint

package require tossl

set supported 1
if {[catch {tossl::key::generate -type rsa -bits 2048} keypair]} {
    puts "SKIP: Key generation not supported: $keypair"
    set supported 0
} else {
    set privkey [dict get $keypair private]
}
if {$supported} {
    if {[catch {tossl::csr::create -key $privkey -subject "CN=test.example.com"} csr]} {
        puts "SKIP: CSR creation not supported: $csr"
        set supported 0
    }
}
if {!$supported} {
    exit 0
}

# Test: Basic fingerprint
set fp [tossl::csr::fingerprint $csr sha256]
puts "Fingerprint: $fp"
if {![regexp {^[a-f0-9:]+$} $fp]} {
    puts "FAIL: Fingerprint format invalid: $fp"
    exit 1
}

# Test: Explicit hash algorithm (sha256)
set fp2 [tossl::csr::fingerprint $csr sha256]
puts "Fingerprint (sha256): $fp2"
if {![regexp {^[a-f0-9:]+$} $fp2]} {
    puts "FAIL: Fingerprint (sha256) format invalid: $fp2"
    exit 1
}

# Test: Error on missing argument
set errorCaught 0
if {[catch {tossl::csr::fingerprint} err]} {
    set errorCaught 1
}
if {!$errorCaught} {
    puts "FAIL: Missing argument did not error"
    exit 1
}

# Test: Error on invalid CSR
set errorCaught 0
if {[catch {tossl::csr::fingerprint "not-a-csr"} err]} {
    set errorCaught 1
}
if {!$errorCaught} {
    puts "FAIL: Invalid CSR did not error"
    exit 1
}

puts "PASS: All tests passed"
exit 0 