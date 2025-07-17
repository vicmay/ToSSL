# Test for ::tossl::url::decode
load ./libtossl.so

puts "Testing URL decode: simple encoding..."
set encoded "hello%20world"
set decoded [tossl::url::decode $encoded]
puts "Decoded: $decoded"
if {$decoded ne "hello world"} {
    puts "FAIL: Simple URL decode failed"
    exit 1
}
puts "Simple URL decode: OK"

puts "Testing URL decode: reserved characters..."
set encoded "%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D"
# Use list to avoid Tcl bracket parsing issues
set expected [join {! * ' ( ) ; : @ & = + $ , / ? # [ ]} ""]
set decoded [tossl::url::decode $encoded]
puts "Decoded: $decoded"
puts "Expected: $expected"
puts -nonewline "Decoded hex: "
foreach c [split $decoded {}] {puts -nonewline [format %02X [scan $c %c]]}
puts ""
puts -nonewline "Expected hex: "
foreach c [split $expected {}] {puts -nonewline [format %02X [scan $c %c]]}
puts ""
puts "Decoded length: [string length $decoded]"
puts "Expected length: [string length $expected]"
if {$decoded ne $expected} {
    puts "FAIL: Reserved characters decode failed"
    exit 1
}
puts "Reserved characters decode: OK"

puts "Testing URL decode: incomplete percent..."
set encoded "foo%2"
set decoded [tossl::url::decode $encoded]
puts "Decoded: $decoded"
if {$decoded ne "foo%2"} {
    puts "FAIL: Incomplete percent decode failed"
    exit 1
}
puts "Incomplete percent decode: OK"

puts "Testing URL decode: no encoding..."
set encoded "plainstring"
set decoded [tossl::url::decode $encoded]
if {$decoded ne "plainstring"} {
    puts "FAIL: No encoding decode failed"
    exit 1
}
puts "No encoding decode: OK"

puts "Testing error: wrong arg count..."
if {[catch {tossl::url::decode} err]} {
    puts "Error on missing arg: $err"
} else {
    puts "FAIL: Missing arg did not error"
    exit 1
}
if {[catch {tossl::url::decode a b} err]} {
    puts "Error on extra arg: $err"
} else {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::url::decode tests passed" 