# Test for ::tossl::base64::encode
load ./libtossl.so

set errors 0

# Basic roundtrip
set data "hello world!"
set encoded [tossl::base64::encode $data]
set expected "aGVsbG8gd29ybGQh"
if {$encoded eq $expected} {
    puts "base64 encode (simple)... OK"
} else {
    puts stderr "FAIL: base64 encode (simple): $encoded"
    incr ::errors
}

# Roundtrip with decode
set decoded [tossl::base64::decode $encoded]
if {$decoded eq $data} {
    puts "base64 encode/decode roundtrip... OK"
} else {
    puts stderr "FAIL: base64 encode/decode roundtrip: $decoded"
    incr ::errors
}

# Test with special characters
set data_special "Hello+world/with=chars!"
set encoded_special [tossl::base64::encode $data_special]
set expected_special "SGVsbG8rd29ybGQvd2l0aD1jaGFycyE="
if {$encoded_special eq $expected_special} {
    puts "base64 encode (special chars)... OK"
} else {
    puts stderr "FAIL: base64 encode (special chars): $encoded_special"
    incr ::errors
}

# Test binary data
set binary_data [binary format H* "deadbeef"]
set encoded_binary [tossl::base64::encode $binary_data]
set expected_binary "3q2+7w=="
if {$encoded_binary eq $expected_binary} {
    puts "base64 encode (binary data)... OK"
} else {
    puts stderr "FAIL: base64 encode (binary data): $encoded_binary"
    incr ::errors
}

# Test empty string
set encoded_empty [tossl::base64::encode ""]
if {$encoded_empty eq ""} {
    puts "base64 encode (empty string)... OK"
} else {
    puts stderr "FAIL: base64 encode (empty string): $encoded_empty"
    incr ::errors
}

# Test with padding variations (basic functionality)
set data_1byte "A"
set encoded_1byte [tossl::base64::encode $data_1byte]
puts "base64 encode (1 byte): $encoded_1byte"

set data_2bytes "AB"
set encoded_2bytes [tossl::base64::encode $data_2bytes]
puts "base64 encode (2 bytes): $encoded_2bytes"

set data_3bytes "ABC"
set encoded_3bytes [tossl::base64::encode $data_3bytes]
puts "base64 encode (3 bytes): $encoded_3bytes"

# Test with Tcl's built-in base64 for comparison
set tossl_encoded [tossl::base64::encode $data]
set tcl_encoded [binary encode base64 $data]
# Remove newlines from Tcl's output for comparison
set tcl_encoded [string map {\n ""} $tcl_encoded]
if {$tossl_encoded eq $tcl_encoded} {
    puts "base64 encode matches Tcl base64... OK"
} else {
    puts stderr "FAIL: base64 encode matches Tcl base64: $tossl_encoded vs $tcl_encoded"
    incr ::errors
}

# Test with Unicode characters (proper UTF-8 handling)
set unicode_data "Hello, 世界!"
set utf8_bytes [encoding convertto utf-8 $unicode_data]
set encoded_unicode [tossl::base64::encode $utf8_bytes]
set decoded_bytes [tossl::base64::decode $encoded_unicode]
set decoded_unicode [encoding convertfrom utf-8 $decoded_bytes]
if {$decoded_unicode eq $unicode_data} {
    puts "base64 encode (unicode)... OK"
} else {
    puts stderr "FAIL: base64 encode (unicode): $decoded_unicode vs $unicode_data"
    incr ::errors
}

# Test with large data
set large_data [string repeat "abcdefghijklmnopqrstuvwxyz" 10]
set encoded_large [tossl::base64::encode $large_data]
set decoded_large [tossl::base64::decode $encoded_large]
if {$decoded_large eq $large_data} {
    puts "base64 encode (large data)... OK"
} else {
    puts stderr "FAIL: base64 encode (large data): length mismatch"
    incr ::errors
}

# Error cases
if {[catch {tossl::base64::encode}]} {
    puts "base64 encode (wrong arg count)... OK"
} else {
    puts stderr "FAIL: base64 encode (wrong arg count) did not error"
    incr ::errors
}

if {[catch {tossl::base64::encode foo bar}]} {
    puts "base64 encode (extra arg)... OK"
} else {
    puts stderr "FAIL: base64 encode (extra arg) did not error"
    incr ::errors
}

puts "All ::tossl::base64::encode tests complete"
if {$::errors > 0} {
    puts stderr "$::errors errors in ::tossl::base64::encode tests"
    exit 1
} 