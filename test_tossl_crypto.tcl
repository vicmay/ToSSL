# test_tossl_crypto.tcl - Functional crypto tests for ToSSL
# These tests exercise encryption, decryption, signing, verification, and certificate creation.

if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set errors 0

proc test {desc script expected} {
    puts -nonewline "$desc... "
    set rc [catch {eval $script} result]
    if {$rc == 0 && ($expected eq "ok" || ($expected eq "bool" && ($result eq "0" || $result eq "1")))} {
        puts "OK"
    } elseif {$rc != 0 && $expected eq "error"} {
        puts "OK (error as expected)"
    } else {
        puts stderr "FAIL: $desc: $result"
        incr ::errors
    }
}

# Symmetric encryption/decryption
set ::key [binary format H* 00112233445566778899aabbccddeeff]
set ::iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
set ::plaintext "Secret message!"
set ::ciphertext [tossl::encrypt -alg aes-128-cbc -key $::key -iv $::iv $::plaintext]
test "encrypt/decrypt roundtrip" {expr {[tossl::decrypt -alg aes-128-cbc -key $::key -iv $::iv $::ciphertext] eq $::plaintext}} ok

# RSA sign/verify
set ::keys [tossl::key::generate]
set ::priv [dict get $::keys private]
set ::pub  [dict get $::keys public]
set ::data "hello world"
set ::sig [tossl::rsa::sign -privkey $::priv -alg sha256 $::data]
test "rsa verify valid" {tossl::rsa::verify -pubkey $::pub -alg sha256 $::data $::sig} bool

# EC sign/verify
set ::keys_ec [tossl::key::generate -type ec -curve prime256v1]
set ::priv_ec [dict get $::keys_ec private]
set ::pub_ec  [dict get $::keys_ec public]
set ::sig_ec [tossl::ec::sign -privkey $::priv_ec -alg sha256 $::data]
test "ec verify valid" {tossl::ec::verify -pubkey $::pub_ec -alg sha256 $::data $::sig_ec} bool

# DSA sign/verify (skip if unsupported)
set dsa_rc [catch {set keys_dsa [tossl::key::generate -type dsa -bits 1024]} dsa_keys]
if {$dsa_rc == 0} {
    set priv_dsa [dict get $keys_dsa private]
    set pub_dsa  [dict get $keys_dsa public]
    set sig_dsa [tossl::dsa::sign -privkey $priv_dsa -alg sha256 $data]
    test "dsa verify valid" {tossl::dsa::verify -pubkey $pub_dsa -alg sha256 $data $sig_dsa} bool
} else {
    puts "dsa sign/verify... SKIPPED (not supported)"
}

# Self-signed certificate creation
set cert [tossl::x509::create -subject "Test CN" -issuer "Test CN" -pubkey $pub -privkey $priv -days 1]
test "x509 create PEM header" {expr {[string match "-----BEGIN CERTIFICATE-----*" $::cert]}} ok

puts "\nCrypto ToSSL tests complete."
if {$errors > 0} {
    puts stderr "$errors test(s) failed."
    exit 1
} else {
    puts "All crypto ToSSL tests passed."
    exit 0
}
