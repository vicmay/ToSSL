# Test for ::tossl::ed448::sign
load ./libtossl.so

puts ";# Generating Ed448 private key..."
set rc [catch {set priv [tossl::ed448::generate]} err]
if {$rc != 0} {
    puts stderr ";# FAIL: could not generate Ed448 private key: $err"
    exit 1
}
set data "test message"

puts ";# Signing data..."
set rc [catch {set sig [tossl::ed448::sign $priv $data]} err]
if {$rc == 0 && [string length $sig] > 0} {
    puts ";# PASS: sign basic functionality"
} else {
    puts stderr ";# FAIL: sign basic functionality: $err"
    exit 2
}

puts ";# Verifying signature..."
set pub [tossl::key::getpub -key $priv]
set rc [catch {set ok [tossl::ed448::verify $pub $data $sig]} err]
if {$rc == 0 && $ok} {
    puts ";# PASS: verify valid signature"
} else {
    puts stderr ";# FAIL: verify valid signature: $err"
    exit 3
}

puts ";# Error: invalid private key..."
set rc [catch {tossl::ed448::sign "notapem" $data} err]
if {$rc != 0} {
    puts ";# PASS: error on invalid private key"
} else {
    puts stderr ";# FAIL: expected error on invalid private key"
    exit 4
}

puts ";# Error: missing arguments..."
set rc [catch {tossl::ed448::sign $priv} err]
if {$rc != 0} {
    puts ";# PASS: error on missing arguments"
} else {
    puts stderr ";# FAIL: expected error on missing arguments"
    exit 5
}

puts ";# All tests passed."
exit 0 