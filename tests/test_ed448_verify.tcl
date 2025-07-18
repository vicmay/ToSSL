# Test for ::tossl::ed448::verify
load ./libtossl.so

puts ";# Generating Ed448 private key..."
set rc [catch {set priv [tossl::ed448::generate]} err]
if {$rc != 0} {
    puts stderr ";# FAIL: could not generate Ed448 private key: $err"
    exit 1
}
set rc [catch {set pub [tossl::key::getpub -key $priv]} err]
if {$rc != 0} {
    puts stderr ";# FAIL: could not extract Ed448 public key: $err"
    exit 2
}
puts ";# DEBUG: Public key PEM:\n$pub"
set rc [catch {set pubinfo [tossl::key::parse $pub]} err]
if {$rc == 0} {
    puts ";# DEBUG: Parsed public key info: $pubinfo"
} else {
    puts ";# DEBUG: Could not parse public key: $err"
}
set data "test message"

puts ";# Signing data..."
set rc [catch {set sig [tossl::ed448::sign $priv $data]} err]
if {$rc != 0} {
    puts stderr ";# FAIL: could not sign: $err"
    exit 3
}
puts ";# DEBUG: Signature (hex): [binary encode hex $sig]"
puts ";# DEBUG: Signature Tcl type: [tcl::unsupported::representation $sig]"

puts ";# Verifying valid signature..."
set rc [catch {set ok [tossl::ed448::verify $pub $data $sig]} err]
puts ";# DEBUG: verify rc=$rc ok=$ok err=$err"
if {$rc == 0 && $ok} {
    puts ";# PASS: verify valid signature"
} else {
    puts stderr ";# FAIL: verify valid signature: $err"
    exit 4
}

puts ";# Verifying tampered signature..."
set tampered [string range $sig 0 end-1]A
set rc [catch {set ok [tossl::ed448::verify $pub $data $tampered]} err]
if {$rc == 0 && !$ok} {
    puts ";# PASS: verify detects tampered signature"
} else {
    puts stderr ";# FAIL: verify does not detect tampered signature: $err"
    exit 5
}

puts ";# Verifying tampered data..."
set rc [catch {set ok [tossl::ed448::verify $pub "wrong message" $sig]} err]
if {$rc == 0 && !$ok} {
    puts ";# PASS: verify detects tampered data"
} else {
    puts stderr ";# FAIL: verify does not detect tampered data: $err"
    exit 6
}

puts ";# Error: invalid public key..."
set rc [catch {tossl::ed448::verify "notapem" $data $sig} err]
if {$rc != 0} {
    puts ";# PASS: error on invalid public key"
} else {
    puts stderr ";# FAIL: expected error on invalid public key"
    exit 7
}

puts ";# Error: missing arguments..."
set rc [catch {tossl::ed448::verify $pub $data} err]
if {$rc != 0} {
    puts ";# PASS: error on missing arguments"
} else {
    puts stderr ";# FAIL: expected error on missing arguments"
    exit 8
}

puts ";# All tests passed."
exit 0 