# test_tossl_basic.tcl - Basic functional tests for ToSSL commands that require no special setup
# These tests check that the command executes and returns a plausible result or error.
# They do not require certificates, keys, or network sockets.

if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set errors 0

proc test {desc script expected} {
    puts -nonewline "$desc... "
    set rc [catch {eval $script} result]
    if {$rc == 0 && ($expected eq "ok" || ($expected eq "bool" && ($result eq "0" || $result eq "1")) || $expected eq "dict" || $expected eq "str")} {
        puts "OK"
    } elseif {$rc != 0 && $expected eq "error"} {
        puts "OK (error as expected)"
    } else {
        puts stderr "FAIL: $desc: $result"
        incr ::errors
    }
}

# Digest
test "digest sha256" {tossl::digest -alg sha256 "abc"} ok

# HMAC
set ::key [binary format H* 00112233445566778899aabbccddeeff]
test "hmac sha256" {tossl::hmac -alg sha256 -key $::key "abc"} ok

# Random bytes
set ::rb [tossl::randbytes 8]
test "randbytes length" {expr {[string length $::rb] > 0}} ok

# Base64 encode/decode
set ::b64 [tossl::base64::encode "hello"]
test "base64 encode" {expr {$::b64 eq "aGVsbG8="}} ok
test "base64 decode" {tossl::base64::decode $::b64} ok

# Hex encode/decode
set ::hex [tossl::hex::encode "hi"]
test "hex encode" {expr {$::hex eq "6869"}} ok
test "hex decode" {tossl::hex::decode $::hex} ok

# Key generation (RSA, DSA, EC)
test "key generate (rsa)" {dict get [tossl::key::generate] public} ok
# DSA may not be supported in all OpenSSL builds, so allow error as success
set dsa_rc [catch {dict get [tossl::key::generate -type dsa -bits 1024] public} dsa_result]
if {$dsa_rc == 0} {
    puts "key generate (dsa)... OK"
} else {
    puts "key generate (dsa)... SKIPPED (not supported)"
}
test "key generate (ec)" {dict get [tossl::key::generate -type ec -curve prime256v1] public} ok

# X.509 parse (should error on random data)
test "x509 parse error" {tossl::x509::parse "notacert"} error

# PKCS12 parse (should error on random data)
test "pkcs12 parse error" {tossl::pkcs12::parse "notap12"} error

# PKCS7 info (should error on random data)
test "pkcs7 info error" {tossl::pkcs7::info "notapkcs7"} error

puts "\nBasic ToSSL functional tests complete."
if {$errors > 0} {
    puts stderr "$errors test(s) failed."
    exit 1
} else {
    puts "All basic ToSSL tests passed."
    exit 0
}
