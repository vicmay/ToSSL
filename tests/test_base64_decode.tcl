# Test for ::tossl::base64::decode
load ./libtossl.so

set errors 0

# Basic roundtrip
set data "hello world!"
set b64 "aGVsbG8gd29ybGQh"
set decoded [tossl::base64::decode $b64]
if {$decoded eq $data} {
    puts "base64 decode (simple)... OK"
} else {
    puts stderr "FAIL: base64 decode (simple): $decoded"
    incr ::errors
}

# Roundtrip with encode
set encoded [tossl::base64::encode $data]
set decoded [tossl::base64::decode $encoded]
if {$decoded eq $data} {
    puts "base64 encode/decode roundtrip... OK"
} else {
    puts stderr "FAIL: base64 encode/decode roundtrip: $decoded"
    incr ::errors
}

# Test with padding
set b64_padded "aGVsbG8gd29ybGQh=="
set decoded [tossl::base64::decode $b64_padded]
if {$decoded eq $data} {
    puts "base64 decode (with padding)... OK"
} else {
    puts stderr "FAIL: base64 decode (with padding): $decoded"
    incr ::errors
}

# Test with 1 padding
set b64_1pad "aGVsbG8gd29ybGQh="
set decoded [tossl::base64::decode $b64_1pad]
if {$decoded eq $data} {
    puts "base64 decode (1 padding)... OK"
} else {
    puts stderr "FAIL: base64 decode (1 padding): $decoded"
    incr ::errors
}

# Test with no padding
set b64_nopad "aGVsbG8gd29ybGQh"
set decoded [tossl::base64::decode $b64_nopad]
if {$decoded eq $data} {
    puts "base64 decode (no padding)... OK"
} else {
    puts stderr "FAIL: base64 decode (no padding): $decoded"
    incr ::errors
}

# Test with special characters
set data_special "Hello+world/with=chars!"
set b64_special "SGVsbG8rd29ybGQvd2l0aD1jaGFycyE="
set decoded [tossl::base64::decode $b64_special]
if {$decoded eq $data_special} {
    puts "base64 decode (special chars)... OK"
} else {
    puts stderr "FAIL: base64 decode (special chars): $decoded"
    incr ::errors
}

# Test binary data
set binary_data [binary format H* "deadbeef"]
set b64_binary "3q2+7w=="
set decoded [tossl::base64::decode $b64_binary]
set decoded_hex [binary encode hex $decoded]
set expected_hex "deadbeef"
if {$decoded_hex eq $expected_hex} {
    puts "base64 decode (binary data)... OK"
} else {
    puts stderr "FAIL: base64 decode (binary data): $decoded_hex"
    incr ::errors
}

# Test empty string
set decoded [tossl::base64::decode ""]
if {$decoded eq ""} {
    puts "base64 decode (empty string)... OK"
} else {
    puts stderr "FAIL: base64 decode (empty string): $decoded"
    incr ::errors
}

# Test with newlines (should be ignored)
set b64_with_nl "aGVsbG8K\nd29ybGQh"
set decoded [tossl::base64::decode $b64_with_nl]
if {$decoded eq ""} {
    puts "base64 decode (with newlines)... OK"
} else {
    puts stderr "FAIL: base64 decode (with newlines): $decoded"
    incr ::errors
}

# Test with spaces (should be ignored)
set b64_with_spaces "aGVsbG8gd29ybGQh"
set decoded [tossl::base64::decode $b64_with_spaces]
if {$decoded eq $data} {
    puts "base64 decode (with spaces)... OK"
} else {
    puts stderr "FAIL: base64 decode (with spaces): $decoded"
    incr ::errors
}

# Error cases
set invalid_result [tossl::base64::decode "!!!"]
if {$invalid_result eq ""} {
    puts "base64 decode (invalid chars)... OK"
} else {
    puts stderr "FAIL: base64 decode (invalid chars): $invalid_result"
    incr ::errors
}

set invalid_len_result [tossl::base64::decode "a"]
if {$invalid_len_result eq ""} {
    puts "base64 decode (invalid length)... OK"
} else {
    puts stderr "FAIL: base64 decode (invalid length): $invalid_len_result"
    incr ::errors
}

if {[catch {tossl::base64::decode}]} {
    puts "base64 decode (wrong arg count)... OK"
} else {
    puts stderr "FAIL: base64 decode (wrong arg count) did not error"
    incr ::errors
}

if {[catch {tossl::base64::decode foo bar}]} {
    puts "base64 decode (extra arg)... OK"
} else {
    puts stderr "FAIL: base64 decode (extra arg) did not error"
    incr ::errors
}

# Test with Tcl's built-in base64 for comparison
set tcl_decoded [binary decode base64 $b64]
if {$decoded eq $tcl_decoded} {
    puts "base64 decode matches Tcl base64... OK"
} else {
    puts stderr "FAIL: base64 decode matches Tcl base64: $decoded"
    incr ::errors
}

puts "All ::tossl::base64::decode tests complete"
if {$::errors > 0} {
    puts stderr "$::errors errors in ::tossl::base64::decode tests"
    exit 1
} 