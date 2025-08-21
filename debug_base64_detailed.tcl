#!/usr/bin/env tclsh

load ./libtossl.so

# Test the exact failing cases
set data "hello world!"
set b64_1pad "aGVsbG8gd29ybGQh="
set b64_2pad "aGVsbG8gd29ybGQh=="

puts "Testing 1 padding: '$b64_1pad'"
puts "Length: [string length $b64_1pad]"

# Test character by character
for {set i 0} {$i < [string length $b64_1pad]} {incr i} {
    set char [string index $b64_1pad $i]
    puts "Char $i: '$char' ([scan $char %c])"
}

puts ""
puts "Testing 2 padding: '$b64_2pad'"
puts "Length: [string length $b64_2pad]"

# Test character by character
for {set i 0} {$i < [string length $b64_2pad]} {incr i} {
    set char [string index $b64_2pad $i]
    puts "Char $i: '$char' ([scan $char %c])"
}
