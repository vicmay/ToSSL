# tests/test_ec_sign.tcl ;# Test for ::tossl::ec::sign

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate EC key
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set data "test message"

# Sign the data (should succeed)
set rc [catch {set sig [tossl::ec::sign $priv $data sha256]} result]
if {$rc == 0} {
    puts ";# PASS: sign normal case"
} else {
    puts stderr ";# FAIL: sign normal case: $result"
    exit 1
}

# Verify the signature
set pub [dict get $keys public]
set rc [catch {set ok [tossl::ec::verify $pub $data $sig sha256]} result]
if {$rc == 0 && $ok} {
    puts ";# PASS: signature verifies"
} else {
    puts stderr ";# FAIL: signature does not verify: $result"
    exit 2
}

# Error: invalid private key
set rc [catch {tossl::ec::sign "notapem" $data sha256} result]
if {$rc != 0} {
    puts ";# PASS: error on invalid private key"
} else {
    puts stderr ";# FAIL: expected error on invalid private key"
    exit 3
}

# Error: invalid digest
set rc [catch {tossl::ec::sign $priv $data "notadigest"} result]
if {$rc != 0} {
    puts ";# PASS: error on invalid digest"
} else {
    puts stderr ";# FAIL: expected error on invalid digest"
    exit 4
}

puts ";# All tests passed."
exit 0 