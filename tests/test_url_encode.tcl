# Test for ::tossl::url::encode
load ./libtossl.so

puts "Testing URL encode: simple string..."
set input "hello world"
set encoded [tossl::url::encode $input]
puts "Encoded: $encoded"
if {$encoded ne "hello%20world"} {
    puts "FAIL: Simple URL encode failed"
    exit 1
}
puts "Simple URL encode: OK"

puts "Testing URL encode: reserved characters..."
set input [join {! * ' ( ) ; : @ & = + $ , / ? # [ ]} ""]
set encoded [tossl::url::encode $input]
puts "Encoded: $encoded"
set expected "%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D"
puts "Expected: $expected"
if {$encoded ne $expected} {
    puts "FAIL: Reserved characters encode failed"
    exit 1
}
puts "Reserved characters encode: OK"

puts "Testing URL encode: unreserved characters..."
set input "AZaz09-_.~"
set encoded [tossl::url::encode $input]
puts "Encoded: $encoded"
if {$encoded ne $input} {
    puts "FAIL: Unreserved characters should not be encoded"
    exit 1
}
puts "Unreserved characters encode: OK"

puts "Testing URL encode: empty string..."
set input ""
set encoded [tossl::url::encode $input]
if {$encoded ne ""} {
    puts "FAIL: Empty string encode failed"
    exit 1
}
puts "Empty string encode: OK"

puts "Testing error: wrong arg count..."
if {[catch {tossl::url::encode} err]} {
    puts "Error on missing arg: $err"
} else {
    puts "FAIL: Missing arg did not error"
    exit 1
}
if {[catch {tossl::url::encode a b} err]} {
    puts "Error on extra arg: $err"
} else {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::url::encode tests passed" 