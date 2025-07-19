# Test for ::tossl::hex::encode
load ./libtossl.so

set errors 0

# Basic encoding
set data "hello world!"
set expected "68656c6c6f20776f726c6421"
set encoded [tossl::hex::encode $data]
if {$encoded eq $expected} {
    puts "hex encode (simple)... OK"
} else {
    puts stderr "FAIL: hex encode (simple): $encoded"
    incr ::errors
}

# Roundtrip with decode
set decoded [tossl::hex::decode $encoded]
if {$decoded eq $data} {
    puts "hex encode/decode roundtrip... OK"
} else {
    puts stderr "FAIL: hex encode/decode roundtrip: $decoded"
    incr ::errors
}

# Test with binary data
set binary_data [binary format H* "deadbeef"]
set encoded_binary [tossl::hex::encode $binary_data]
set expected_binary "deadbeef"
if {$encoded_binary eq $expected_binary} {
    puts "hex encode (binary data)... OK"
} else {
    puts stderr "FAIL: hex encode (binary data): $encoded_binary"
    incr ::errors
}

# Test empty string
set encoded_empty [tossl::hex::encode ""]
if {$encoded_empty eq ""} {
    puts "hex encode (empty string)... OK"
} else {
    puts stderr "FAIL: hex encode (empty string): $encoded_empty"
    incr ::errors
}

# Test single byte
set encoded_single [tossl::hex::encode "A"]
if {$encoded_single eq "41"} {
    puts "hex encode (single byte)... OK"
} else {
    puts stderr "FAIL: hex encode (single byte): $encoded_single"
    incr ::errors
}

# Test two bytes
set encoded_two [tossl::hex::encode "AB"]
if {$encoded_two eq "4142"} {
    puts "hex encode (two bytes)... OK"
} else {
    puts stderr "FAIL: hex encode (two bytes): $encoded_two"
    incr ::errors
}

# Test with zeros
set encoded_zeros [tossl::hex::encode "\x00\x00\x00"]
if {$encoded_zeros eq "000000"} {
    puts "hex encode (zeros)... OK"
} else {
    puts stderr "FAIL: hex encode (zeros): $encoded_zeros"
    incr ::errors
}

# Test with all F's
set encoded_ffs [tossl::hex::encode "\xFF\xFF"]
if {$encoded_ffs eq "ffff"} {
    puts "hex encode (all F's)... OK"
} else {
    puts stderr "FAIL: hex encode (all F's): $encoded_ffs"
    incr ::errors
}

# Test Unicode data (byte-level roundtrip)
set unicode_data "\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440!"
set encoded_unicode [tossl::hex::encode $unicode_data]
set decoded_unicode [tossl::hex::decode $encoded_unicode]
set decoded_hex [tossl::hex::encode $decoded_unicode]
if {$decoded_hex eq $encoded_unicode} {
    puts "hex encode (unicode roundtrip, byte-level)... OK"
} else {
    puts stderr "FAIL: hex encode (unicode roundtrip, byte-level): expected $encoded_unicode, got $decoded_hex"
    incr ::errors
}

# Test large data
set large_data [string repeat "A" 1000]
set encoded_large [tossl::hex::encode $large_data]
set decoded_large [tossl::hex::decode $encoded_large]
if {$decoded_large eq $large_data} {
    puts "hex encode (large data)... OK"
} else {
    puts stderr "FAIL: hex encode (large data): length mismatch"
    incr ::errors
}

# Error handling: wrong number of arguments
if {[catch {tossl::hex::encode} err]} {
    puts "hex encode (no args error)... OK"
} else {
    puts stderr "FAIL: hex encode (no args) should have failed"
    incr ::errors
}
if {[catch {tossl::hex::encode "foo" "bar"} err]} {
    puts "hex encode (too many args error)... OK"
} else {
    puts stderr "FAIL: hex encode (too many args) should have failed"
    incr ::errors
}

# Performance test
set start_time [clock clicks -milliseconds]
for {set i 0} {$i < 1000} {incr i} {
    tossl::hex::encode "ABCDEFGHIJKLMNOP"
}
set end_time [clock clicks -milliseconds]
set duration [expr $end_time - $start_time]
puts "hex encode (performance: $duration ms for 1000 iterations)... OK"

# Security test - ensure no buffer overflow with large input
set large_bin [binary format H* [string repeat "41" 10000]]
if {[catch {tossl::hex::encode $large_bin} err]} {
    puts stderr "FAIL: hex encode (large input) failed: $err"
    incr ::errors
} else {
    puts "hex encode (large input security)... OK"
}

puts "Total errors: $::errors"
if {$::errors > 0} {
    exit 1
} else {
    puts "All ::tossl::hex::encode tests passed"
} 