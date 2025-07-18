# Test for ::tossl::base64url::encode
load ./libtossl.so

set errors 0

# Basic roundtrip
set data "hello world!"
set b64url [tossl::base64url::encode $data]
set expected "aGVsbG8gd29ybGQh"
if {$b64url eq $expected} {
    puts "base64url encode (simple)... OK"
} else {
    puts stderr "FAIL: base64url encode (simple): $b64url"
    incr ::errors
}

# Roundtrip with decode
set decoded [tossl::base64url::decode $b64url]
if {$decoded eq $data} {
    puts "base64url encode/decode roundtrip... OK"
} else {
    puts stderr "FAIL: base64url encode/decode roundtrip: $decoded"
    incr ::errors
}

# Test with - and _
set data "Hello-_world!"
set b64url [tossl::base64url::encode $data]
set expected "SGVsbG8tX3dvcmxkIQ"
if {$b64url eq $expected} {
    puts "base64url encode (with - and _)... OK"
} else {
    puts stderr "FAIL: base64url encode (with - and _): $b64url"
    incr ::errors
}

# Padding edge cases
set data "hello world!"
set b64url [tossl::base64url::encode $data]
if {[string first = $b64url] == -1} {
    puts "base64url encode (no padding)... OK"
} else {
    puts stderr "FAIL: base64url encode (no padding): $b64url"
    incr ::errors
}

# Empty string
set b64url [tossl::base64url::encode ""]
if {$b64url eq ""} {
    puts "base64url encode (empty string)... OK"
} else {
    puts stderr "FAIL: base64url encode (empty string): $b64url"
    incr ::errors
}

# Binary data
set data [binary format H* "deadbeef"]
set b64url [tossl::base64url::encode $data]
set expected "3q2-7w"
if {$b64url eq $expected} {
    puts "base64url encode (binary)... OK"
} else {
    puts stderr "FAIL: base64url encode (binary): $b64url"
    incr ::errors
}

# Error: wrong arg count
if {[catch {tossl::base64url::encode}]} {
    puts "base64url encode (wrong arg count)... OK"
} else {
    puts stderr "FAIL: base64url encode (wrong arg count) did not error"
    incr ::errors
}
if {[catch {tossl::base64url::encode foo bar}]} {
    puts "base64url encode (extra arg)... OK"
} else {
    puts stderr "FAIL: base64url encode (extra arg) did not error"
    incr ::errors
}

puts "All ::tossl::base64url::encode tests complete"
if {$::errors > 0} {
    puts stderr "$::errors errors in ::tossl::base64url::encode tests"
    exit 1
} 