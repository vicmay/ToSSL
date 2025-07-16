# tests/test_ec_verify.tcl ;# Test for ::tossl::ec::verify

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate EC key
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set pub  [dict get $keys public]
set data "test message"

# Sign the data
set rc [catch {set sig [tossl::ec::sign $priv $data sha256]} result]
if {$rc != 0} {
    puts stderr ";# FAIL: could not sign: $result"
    exit 1
}

# Verify the signature (should succeed)
set rc [catch {set ok [tossl::ec::verify $pub $data $sig sha256]} result]
if {$rc == 0 && $ok} {
    puts ";# PASS: verify valid signature"
} else {
    puts stderr ";# FAIL: verify valid signature: $result"
    exit 2
}

# Tamper with the signature
set tampered [string range $sig 0 end-1]A
set rc [catch {set ok [tossl::ec::verify $pub $data $tampered sha256]} result]
if {$rc == 0 && !$ok} {
    puts ";# PASS: verify detects tampered signature"
} else {
    puts stderr ";# FAIL: verify does not detect tampered signature: $result"
    exit 3
}

# Tamper with the data
set rc [catch {set ok [tossl::ec::verify $pub "wrong message" $sig sha256]} result]
if {$rc == 0 && !$ok} {
    puts ";# PASS: verify detects tampered data"
} else {
    puts stderr ";# FAIL: verify does not detect tampered data: $result"
    exit 4
}

# Error: invalid public key
set rc [catch {tossl::ec::verify "notapem" $data $sig sha256} result]
if {$rc != 0} {
    puts ";# PASS: error on invalid public key"
} else {
    puts stderr ";# FAIL: expected error on invalid public key"
    exit 5
}

# Error: invalid digest
set rc [catch {tossl::ec::verify $pub $data $sig "notadigest"} result]
if {$rc != 0} {
    puts ";# PASS: error on invalid digest"
} else {
    puts stderr ";# FAIL: expected error on invalid digest"
    exit 6
}

puts ";# All tests passed."
exit 0 