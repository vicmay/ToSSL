# Test for ::tossl::ed448::generate
load ./libtossl.so

puts ";# Generating Ed448 private key..."
set rc [catch {set priv [tossl::ed448::generate]} err]
if {$rc == 0 && [string match "*BEGIN PRIVATE KEY*" $priv]} {
    puts ";# PASS: generate outputs PEM private key"
} else {
    puts stderr ";# FAIL: generate PEM output: $err"
    puts stderr ";# DEBUG: priv = $priv"
    exit 1
}

puts ";# Extracting public key..."
set rc [catch {set pub [tossl::key::getpub -key $priv]} err]
if {$rc == 0 && [string match "*BEGIN PUBLIC KEY*" $pub]} {
    puts ";# PASS: getpub outputs PEM public key"
} else {
    puts stderr ";# FAIL: getpub PEM output: $err"
    puts stderr ";# DEBUG: pub = $pub"
    exit 2
}

puts ";# Signing and verifying..."
set data "test message"
set rc [catch {set sig [tossl::ed448::sign $priv $data]} err]
if {$rc != 0} {
    puts stderr ";# FAIL: could not sign: $err"
    exit 3
}
set rc [catch {set ok [tossl::ed448::verify $pub $data $sig]} err]
if {$rc == 0 && $ok} {
    puts ";# PASS: sign/verify roundtrip"
} else {
    puts stderr ";# FAIL: sign/verify roundtrip: $err"
    exit 4
}

puts ";# Error: extra argument..."
set rc [catch {tossl::ed448::generate extra} err]
if {$rc != 0} {
    puts ";# PASS: error on extra argument"
} else {
    puts stderr ";# FAIL: expected error on extra argument"
    exit 5
}

puts ";# All tests passed."
exit 0 