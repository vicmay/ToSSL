#!/usr/bin/env tclsh
load ./libtossl.so

puts "Testing base64 decode step by step..."

# Test the failing cases
set data "hello world!"
set b64_padded "aGVsbG8gd29ybGQh=="
set b64_1pad "aGVsbG8gd29ybGQh="
set b64_with_nl "aGVsbG8K\nd29ybGQh"

puts "Original data: '$data'"
puts "Base64 padded: '$b64_padded'"
puts "Base64 1 pad: '$b64_1pad'"
puts "Base64 with newlines: '$b64_with_nl'"

puts "\nDecoding padded:"
set decoded [tossl::base64::decode $b64_padded]
puts "Result: '$decoded'"
puts "Length: [string length $decoded]"
puts "Expected: '$data'"
puts "Match: [expr {$decoded eq $data ? "YES" : "NO"}]"

puts "\nDecoding 1 pad:"
set decoded [tossl::base64::decode $b64_1pad]
puts "Result: '$decoded'"
puts "Length: [string length $decoded]"
puts "Expected: '$data'"
puts "Match: [expr {$decoded eq $data ? "YES" : "NO"}]"

puts "\nDecoding with newlines:"
set decoded [tossl::base64::decode $b64_with_nl]
puts "Result: '$decoded'"
puts "Length: [string length $decoded]"
puts "Expected: '' (empty)"
puts "Match: [expr {$decoded eq "" ? "YES" : "NO"}]"

puts "\nTesting Tcl's built-in base64 for comparison:"
set tcl_decoded [binary decode base64 $b64_padded]
puts "Tcl padded result: '$tcl_decoded'"
puts "Tcl 1 pad result: '[binary decode base64 $b64_1pad]'"
puts "Tcl newlines result: '[binary decode base64 $b64_with_nl]'"
