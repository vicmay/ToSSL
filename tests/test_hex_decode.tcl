# Test for ::tossl::hex::decode
load ./libtossl.so

set errors 0

# Basic roundtrip test
set data "hello world!"
set hex "68656c6c6f20776f726c6421"
set decoded [tossl::hex::decode $hex]
if {$decoded eq $data} {
    puts "hex decode (simple)... OK"
} else {
    puts stderr "FAIL: hex decode (simple): expected '$data', got '$decoded'"
    incr ::errors
}

# Roundtrip with encode
set encoded [tossl::hex::encode $data]
set decoded [tossl::hex::decode $encoded]
if {$decoded eq $data} {
    puts "hex encode/decode roundtrip... OK"
} else {
    puts stderr "FAIL: hex encode/decode roundtrip: expected '$data', got '$decoded'"
    incr ::errors
}

# Test with uppercase hex
set hex_upper "68656C6C6F20776F726C6421"
set decoded [tossl::hex::decode $hex_upper]
if {$decoded eq $data} {
    puts "hex decode (uppercase)... OK"
} else {
    puts stderr "FAIL: hex decode (uppercase): expected '$data', got '$decoded'"
    incr ::errors
}

# Test with mixed case hex
set hex_mixed "68656c6C6F20776F726C6421"
set decoded [tossl::hex::decode $hex_mixed]
if {$decoded eq $data} {
    puts "hex decode (mixed case)... OK"
} else {
    puts stderr "FAIL: hex decode (mixed case): expected '$data', got '$decoded'"
    incr ::errors
}

# Test binary data
set binary_data [binary format H* "deadbeef"]
set hex_binary "deadbeef"
set decoded [tossl::hex::decode $hex_binary]
set decoded_hex [binary encode hex $decoded]
if {$decoded_hex eq $hex_binary} {
    puts "hex decode (binary data)... OK"
} else {
    puts stderr "FAIL: hex decode (binary data): expected '$hex_binary', got '$decoded_hex'"
    incr ::errors
}

# Test empty string
set decoded [tossl::hex::decode ""]
if {$decoded eq ""} {
    puts "hex decode (empty string)... OK"
} else {
    puts stderr "FAIL: hex decode (empty string): expected empty, got '$decoded'"
    incr ::errors
}

# Test single byte
set hex_single "41"
set decoded [tossl::hex::decode $hex_single]
if {$decoded eq "A"} {
    puts "hex decode (single byte)... OK"
} else {
    puts stderr "FAIL: hex decode (single byte): expected 'A', got '$decoded'"
    incr ::errors
}

# Test two bytes
set hex_two "4142"
set decoded [tossl::hex::decode $hex_two]
if {$decoded eq "AB"} {
    puts "hex decode (two bytes)... OK"
} else {
    puts stderr "FAIL: hex decode (two bytes): expected 'AB', got '$decoded'"
    incr ::errors
}

# Test with zeros
set hex_zeros "000000"
set decoded [tossl::hex::decode $hex_zeros]
set decoded_hex [binary encode hex $decoded]
if {$decoded_hex eq "000000"} {
    puts "hex decode (zeros)... OK"
} else {
    puts stderr "FAIL: hex decode (zeros): expected '000000', got '$decoded_hex'"
    incr ::errors
}

# Test with all F's
set hex_ffs "ffff"
set decoded [tossl::hex::decode $hex_ffs]
set decoded_hex [binary encode hex $decoded]
if {$decoded_hex eq "ffff"} {
    puts "hex decode (all F's)... OK"
} else {
    puts stderr "FAIL: hex decode (all F's): expected 'ffff', got '$decoded_hex'"
    incr ::errors
}

# Test Unicode data (simplified)
set unicode_data "Hello World!"
set unicode_hex [tossl::hex::encode $unicode_data]
set decoded [tossl::hex::decode $unicode_hex]
if {$decoded eq $unicode_data} {
    puts "hex decode (unicode roundtrip)... OK"
} else {
    puts stderr "FAIL: hex decode (unicode roundtrip): expected '$unicode_data', got '$decoded'"
    incr ::errors
}

# Test large data
set large_data [string repeat "A" 1000]
set large_hex [tossl::hex::encode $large_data]
set decoded [tossl::hex::decode $large_hex]
if {$decoded eq $large_data} {
    puts "hex decode (large data)... OK"
} else {
    puts stderr "FAIL: hex decode (large data): length mismatch"
    incr ::errors
}

# Error handling tests

# Test odd length hex string
if {[catch {tossl::hex::decode "123"} err]} {
    puts "hex decode (odd length error)... OK"
} else {
    puts stderr "FAIL: hex decode (odd length) should have failed"
    incr ::errors
}

# Test invalid hex characters
if {[catch {tossl::hex::decode "12g3"} err]} {
    puts "hex decode (invalid hex error)... OK"
} else {
    puts stderr "FAIL: hex decode (invalid hex) should have failed"
    incr ::errors
}

# Test invalid hex characters at end
if {[catch {tossl::hex::decode "123g"} err]} {
    puts "hex decode (invalid hex at end error)... OK"
} else {
    puts stderr "FAIL: hex decode (invalid hex at end) should have failed"
    incr ::errors
}

# Test wrong number of arguments
if {[catch {tossl::hex::decode} err]} {
    puts "hex decode (no args error)... OK"
} else {
    puts stderr "FAIL: hex decode (no args) should have failed"
    incr ::errors
}

if {[catch {tossl::hex::decode "1234" "5678"} err]} {
    puts "hex decode (too many args error)... OK"
} else {
    puts stderr "FAIL: hex decode (too many args) should have failed"
    incr ::errors
}

# Performance test
set start_time [clock clicks -milliseconds]
for {set i 0} {$i < 1000} {incr i} {
    tossl::hex::decode "4142434445464748494a4b4c4d4e4f50"
}
set end_time [clock clicks -milliseconds]
set duration [expr $end_time - $start_time]
puts "hex decode (performance: $duration ms for 1000 iterations)... OK"

# Security test - ensure no buffer overflow with large input
set large_hex [string repeat "41" 10000]
if {[catch {tossl::hex::decode $large_hex} err]} {
    puts stderr "FAIL: hex decode (large input) failed: $err"
    incr ::errors
} else {
    puts "hex decode (large input security)... OK"
}

puts "Total errors: $::errors"
if {$::errors > 0} {
    exit 1
} else {
    puts "All ::tossl::hex::decode tests passed"
} 