# tests/test_dsa_sign.tcl ;# Test for ::tossl::dsa::sign

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Generate DSA key
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set data "The quick brown fox jumps over the lazy dog"

# Normal case: sign data
set rc [catch {set sig [tossl::dsa::sign -key $priv -data $data -alg sha256]} res]
if {$rc == 0 && [string length $sig] > 0} {
    puts ";# PASS: sign normal case"
} else {
    puts stderr ";# FAIL: sign normal case: $res"
    exit 1
}

# Error: invalid key
set rc [catch {tossl::dsa::sign -key "notakey" -data $data -alg sha256} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid key"
} else {
    puts stderr ";# FAIL: expected error on invalid key"
    exit 2
}

# Error: missing data
set rc [catch {tossl::dsa::sign -key $priv} res]
if {$rc != 0} {
    puts ";# PASS: error on missing data"
} else {
    puts stderr ";# FAIL: expected error on missing data"
    exit 3
}

# Error: unknown digest
set rc [catch {tossl::dsa::sign -key $priv -data $data -alg notadigest} res]
if {$rc != 0} {
    puts ";# PASS: error on unknown digest"
} else {
    puts stderr ";# FAIL: expected error on unknown digest"
    exit 4
}

puts ";# All tests passed."
exit 0 