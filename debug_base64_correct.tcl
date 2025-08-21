#!/usr/bin/env tclsh

# Let's verify what the correct base64 encoding should be
set data "hello world!"

# Encode with Tcl
set encoded_tcl [binary encode base64 $data]
puts "Data: '$data'"
puts "Tcl encoded: '$encoded_tcl'"

# Test different paddings
set no_pad "aGVsbG8gd29ybGQh"
set one_pad "aGVsbG8gd29ybGQh="  
set two_pad "aGVsbG8gd29ybGQh=="

puts ""
puts "Testing with Tcl decode:"
puts "No pad '$no_pad': '[binary decode base64 $no_pad]'"
puts "One pad '$one_pad': '[binary decode base64 $one_pad]'"
puts "Two pad '$two_pad': '[binary decode base64 $two_pad]'"

# Let's also check the hex values
puts ""
puts "Hex values:"
puts "Data hex: [binary encode hex $data]"
puts "No pad decoded hex: [binary encode hex [binary decode base64 $no_pad]]"
puts "One pad decoded hex: [binary encode hex [binary decode base64 $one_pad]]"
puts "Two pad decoded hex: [binary encode hex [binary decode base64 $two_pad]]"
