#!/usr/bin/env tclsh

# Simple test to understand signature validation

# Load the TOSSL extension
if {[catch {load ./libtossl.so} err]} {
    puts "Error loading TOSSL extension: $err"
    exit 1
}

# Create a simple test case with known values
set test_data "test"

# Generate RSA key pair
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_private_key [dict get $rsa_keys private]
set rsa_public_key [dict get $rsa_keys public]

# Create signature using RSA sign
set signature_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha256]

# Convert to hex
binary scan $signature_binary H* signature_hex

puts "Test data: '$test_data'"
puts "Signature hex length: [string length $signature_hex]"
puts "First 20 chars of signature: [string range $signature_hex 0 19]"

# Try validation
set result [::tossl::signature::validate $rsa_public_key $test_data $signature_hex "sha256"]
puts "Validation result: $result"

# Let's also try with a different approach - use the RSA verify command
if {[catch {tossl::rsa::verify -key $rsa_public_key -data $test_data -sig $signature_binary -alg sha256} rsa_result]} {
    puts "RSA verify failed: $rsa_result"
} else {
    puts "RSA verify result: $rsa_result"
}

# Let's also check what happens if we create the signature differently
# Try to understand the data format issue
puts "\nDebugging data format:"
puts "Data as string: '[string length $test_data]' bytes"
puts "Data as binary: '[string length [encoding convertto utf-8 $test_data]]' bytes"
