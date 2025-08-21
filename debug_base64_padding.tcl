#!/usr/bin/env tclsh

load ./libtossl.so

set data "hello world!"
set b64_nopad "aGVsbG8gd29ybGQh"
set b64_1pad "aGVsbG8gd29ybGQh="
set b64_2pad "aGVsbG8gd29ybGQh=="

puts "Original data: '$data'"
puts "Length: [string length $data]"
puts ""

puts "No padding: '$b64_nopad'"
set decoded_nopad [tossl::base64::decode $b64_nopad]
puts "Decoded: '$decoded_nopad'"
puts "Match: [expr {$decoded_nopad eq $data}]"
puts ""

puts "1 padding: '$b64_1pad'"
set decoded_1pad [tossl::base64::decode $b64_1pad]
puts "Decoded: '$decoded_1pad'"
puts "Match: [expr {$decoded_1pad eq $data}]"
puts ""

puts "2 padding: '$b64_2pad'"
set decoded_2pad [tossl::base64::decode $b64_2pad]
puts "Decoded: '$decoded_2pad'"
puts "Match: [expr {$decoded_2pad eq $data}]"
puts ""

# Test with Tcl's built-in base64
puts "Tcl built-in decode of no padding: '[binary decode base64 $b64_nopad]'"
puts "Tcl built-in decode of 1 padding: '[binary decode base64 $b64_1pad]'"
puts "Tcl built-in decode of 2 padding: '[binary decode base64 $b64_2pad]'"
