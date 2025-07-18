# Test for ::tossl::base64url::decode
load ./libtossl.so

set errors 0

# Basic roundtrip
set data "hello world!"
set b64url "aGVsbG8gd29ybGQh"
set decoded [tossl::base64url::decode $b64url]
if {$decoded eq $data} {
    puts "base64url decode (simple)... OK"
} else {
    puts stderr "FAIL: base64url decode (simple): $decoded"
    incr ::errors
}

set b64url "aGVsbG8gd29ybGQh"
set decoded [tossl::base64url::decode $b64url]
set tcl_decoded [binary decode base64 $b64url]
if {$decoded eq $tcl_decoded} {
    puts "base64url decode matches Tcl base64... OK"
} else {
    puts stderr "FAIL: base64url decode matches Tcl base64: $decoded"
    incr ::errors
}

set b64url "SGVsbG8tX3dvcmxkIQ"
set decoded [tossl::base64url::decode $b64url]
set expected "Hello-_world!"
set decoded_hex [binary encode hex $decoded]
set expected_hex [binary encode hex $expected]
puts "Decoded (with - and _) hex: $decoded_hex"
puts "Expected hex: $expected_hex"
if {$decoded_hex eq $expected_hex} {
    puts "base64url decode (with - and _)... OK"
} else {
    puts stderr "FAIL: base64url decode (with - and _): $decoded_hex"
    incr ::errors
}

# Padding edge cases
set b64url_nopad "aGVsbG8gd29ybGQh"
set decoded [tossl::base64url::decode $b64url_nopad]
set expected "hello world!"
set decoded_hex [binary encode hex $decoded]
set expected_hex [binary encode hex $expected]
puts "Decoded (no padding) hex: $decoded_hex"
puts "Expected hex: $expected_hex"
if {$decoded_hex eq $expected_hex} {
    puts "base64url decode (no padding)... OK"
} else {
    puts stderr "FAIL: base64url decode (no padding): $decoded_hex"
    incr ::errors
}

set b64url_1pad "aGVsbG8gd29ybGQh="
set decoded [tossl::base64url::decode $b64url_1pad]
set expected "hello world!"
set decoded_hex [binary encode hex $decoded]
set expected_hex [binary encode hex $expected]
puts "Decoded (1 padding) hex: $decoded_hex"
puts "Expected hex: $expected_hex"
if {$decoded_hex eq $expected_hex} {
    puts "base64url decode (1 padding)... OK"
} else {
    puts stderr "FAIL: base64url decode (1 padding): $decoded_hex"
    incr ::errors
}

set b64url_2pad "aGVsbG8gd29ybGQh=="
set decoded [tossl::base64url::decode $b64url_2pad]
set expected "hello world!"
set decoded_hex [binary encode hex $decoded]
set expected_hex [binary encode hex $expected]
puts "Decoded (2 padding) hex: $decoded_hex"
puts "Expected hex: $expected_hex"
if {$decoded_hex eq $expected_hex} {
    puts "base64url decode (2 padding)... OK"
} else {
    puts stderr "FAIL: base64url decode (2 padding): $decoded_hex"
    incr ::errors
}

set decoded [tossl::base64url::decode ""]
if {$decoded eq ""} {
    puts "base64url decode (empty string)... OK"
} else {
    puts stderr "FAIL: base64url decode (empty string): $decoded"
    incr ::errors
}

if {[catch {tossl::base64url::decode "!!!"}]} {
    puts "base64url decode (invalid chars)... OK"
} else {
    puts stderr "FAIL: base64url decode (invalid chars) did not error"
    incr ::errors
}

if {[catch {tossl::base64url::decode}]} {
    puts "base64url decode (wrong arg count)... OK"
} else {
    puts stderr "FAIL: base64url decode (wrong arg count) did not error"
    incr ::errors
}

if {[catch {tossl::base64url::decode foo bar}]} {
    puts "base64url decode (extra arg)... OK"
} else {
    puts stderr "FAIL: base64url decode (extra arg) did not error"
    incr ::errors
}

puts "All ::tossl::base64url::decode tests complete"
if {$::errors > 0} {
    puts stderr "$::errors errors in ::tossl::base64url::decode tests"
    exit 1
} 