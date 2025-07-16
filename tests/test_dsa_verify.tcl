# tests/test_dsa_verify.tcl ;# Test for ::tossl::dsa::verify

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Generate DSA key
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "The quick brown fox jumps over the lazy dog"

# Sign data
set sig [tossl::dsa::sign -key $priv -data $data -alg sha256]

# Normal case: verify correct signature
set rc [catch {set result [tossl::dsa::verify -key $pub -data $data -sig $sig -alg sha256]} res]
if {$rc == 0 && $result == 1} {
    puts ";# PASS: verify correct signature"
} else {
    puts stderr ";# FAIL: verify correct signature: $res"
    exit 1
}

# Error: wrong data
set rc [catch {set result [tossl::dsa::verify -key $pub -data "wrong data" -sig $sig -alg sha256]} res]
if {$rc == 0 && $result == 0} {
    puts ";# PASS: verify fails on wrong data"
} else {
    puts stderr ";# FAIL: expected verify to fail on wrong data: $res"
    exit 2
}

# Error: wrong signature
set badsig [binary format H* 00]
set rc [catch {tossl::dsa::verify -key $pub -data $data -sig $badsig -alg sha256} res]
if {$rc == 0 && $result == 0} {
    puts ";# PASS: verify fails on bad signature"
} else {
    puts stderr ";# FAIL: expected verify to fail on bad signature: $res"
    exit 3
}

# Error: invalid key
set rc [catch {tossl::dsa::verify -key "notakey" -data $data -sig $sig -alg sha256} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid key"
} else {
    puts stderr ";# FAIL: expected error on invalid key"
    exit 4
}

# Error: missing arguments
set rc [catch {tossl::dsa::verify -key $pub -data $data} res]
if {$rc != 0} {
    puts ";# PASS: error on missing arguments"
} else {
    puts stderr ";# FAIL: expected error on missing arguments"
    exit 5
}

puts ";# All tests passed."
exit 0 