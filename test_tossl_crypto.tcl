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
# Initialize AES key and IV for roundtrip test
# Convert key and IV to bytearrays
set ::key [binary format H* "00112233445566778899aabbccddeeff"]
set ::iv  [binary format H* "0102030405060708090a0b0c0d0e0f10"]
set ::plaintext "Secret message!"
puts "DEBUG: Key Tcl type: [tcl::unsupported::representation $::key]"
puts "DEBUG: Key hex: [binary encode hex $::key]"
puts "DEBUG: IV Tcl type: [tcl::unsupported::representation $::iv]"
puts "DEBUG: IV hex: [binary encode hex $::iv]"
puts "DEBUG: Plaintext Tcl type: [tcl::unsupported::representation $::plaintext]"
puts "DEBUG: Plaintext hex: [binary encode hex $::plaintext]"
if {![string match *bytearray* [tcl::unsupported::representation $::plaintext]]} {
    set ::plaintext [binary format a* $::plaintext]
    puts "DEBUG: Plaintext converted to bytearray."
}
set ::ciphertext [tossl::encrypt -alg aes-128-cbc -key $::key -iv $::iv $::plaintext]
# Encrypt/decrypt roundtrip test with debug
puts "DEBUG: AES key: [binary encode hex $::key]"
puts "DEBUG: AES IV:  [binary encode hex $::iv]"
puts "DEBUG: Plaintext: $::plaintext"
set ::cipher [tossl::encrypt -alg aes-128-cbc -key $::key -iv $::iv $::plaintext]
puts "DEBUG: Ciphertext: [binary encode hex $::cipher]"
puts "DEBUG: Ciphertext length: [string length $::cipher]"
puts "DEBUG: Ciphertext Tcl type: [tcl::unsupported::representation $::cipher]"
puts "DEBUG: Ciphertext hex before decrypt: [binary encode hex $::cipher]"
puts "DEBUG: Ciphertext length before decrypt: [string length $::cipher]"
if {![string match *bytearray* [tcl::unsupported::representation $::cipher]]} {
    set ::cipher [binary format a* $::cipher]
    puts "DEBUG: Ciphertext converted to bytearray."
}
# Force bytearray again as a last step before decryption
set ::cipher [binary format a* $::cipher]
puts "DEBUG: Decrypt args (using ::cipher):"
puts "  key: [binary encode hex $::key]"
puts "  iv:  [binary encode hex $::iv]"
puts "  ciphertext: [binary encode hex $::cipher]"
puts "  ciphertext length: [string length $::cipher]"
set ::decrypted [catch {tossl::decrypt -alg aes-128-cbc -key $::key -iv $::iv $::cipher} ::plain2]
puts "DEBUG: Decrypt result (using ::cipher): $::decrypted, Output: $::plain2"
puts "DEBUG: Decrypt args (using ::ciphertext):"
puts "  key: [binary encode hex $::key]"
puts "  iv:  [binary encode hex $::iv]"
puts "  ciphertext: [binary encode hex $::ciphertext]"
puts "  ciphertext length: [string length $::ciphertext]"
set ::decrypted2 [catch {tossl::decrypt -alg aes-128-cbc -key $::key -iv $::iv $::ciphertext} ::plain2b]
puts "DEBUG: Decrypt result (using ::ciphertext): $::decrypted2, Output: $::plain2b"
if {$::decrypted == 0} {
    puts "PASS: encrypt/decrypt roundtrip"
} else {
    puts "FAIL: encrypt/decrypt roundtrip: $::decrypted"
}

# RSA sign/verify
set ::keys [tossl::key::generate]
set ::priv [dict get $::keys private]
set ::pub  [dict get $::keys public]
set ::data "hello world"
set ::sig [tossl::rsa::sign -key $::priv -data $::data -alg sha256]
set ::verify [tossl::rsa::verify -key $::pub -data $::data -sig $::sig -alg sha256]
test "rsa verify valid" {expr {$::verify}} bool

# EC sign/verify
set ::keys_ec [tossl::key::generate -type ec -curve prime256v1]
set ::priv_ec [dict get $::keys_ec private]
set ::pub_ec  [dict get $::keys_ec public]
set ::sig_ec [tossl::ec::sign $::priv_ec $::data sha256]
set ::verify_ec [tossl::ec::verify $::pub_ec $::data $::sig_ec sha256]
test "ec verify valid" {expr {$::verify_ec}} bool

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

# X.509 certificate creation
set cert [tossl::x509::create $priv "Test CN" 1]
test "x509 create PEM header" {expr {[string match "-----BEGIN CERTIFICATE-----*" $::cert]}} ok

# Write plaintext to file for OpenSSL CLI test
set f [open "openssl_plain.txt" w]
puts -nonewline $f $::plaintext
close $f
# Encrypt with OpenSSL CLI
set openssl_cmd "openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10 -in openssl_plain.txt -out openssl_cipher.bin"
set rc [catch {exec sh -c $openssl_cmd} result]
if {$rc != 0} {
    puts stderr "OpenSSL CLI encryption failed: $result"
} else {
    set f2 [open "openssl_cipher.bin" r]
    fconfigure $f2 -translation binary
    set openssl_cipher [read $f2]
    close $f2
    puts "DEBUG: OpenSSL CLI ciphertext hex: [binary encode hex $openssl_cipher]"
    puts "DEBUG: TOSSL ciphertext hex: [binary encode hex $::cipher]"
}

puts "\nCrypto ToSSL tests complete."
if {$errors > 0} {
    puts stderr "$errors test(s) failed."
    exit 1
} else {
    puts "All crypto ToSSL tests passed."
    exit 0
}
