#!/usr/bin/env tclsh

# Debug script to understand signature validation issues

# Load the TOSSL extension
if {[catch {load ./libtossl.so} err]} {
    puts "Error loading TOSSL extension: $err"
    exit 1
}

# Generate RSA key pair
puts "Generating RSA key pair..."
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_private_key [dict get $rsa_keys private]
set rsa_public_key [dict get $rsa_keys public]

# Test data
set test_data "Hello, World!"

# Create signature
puts "Creating signature..."
set signature_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha256]

# Convert binary signature to hex using binary scan
binary scan $signature_binary H* signature

puts "Private key (first 100 chars): [string range $rsa_private_key 0 100]..."
puts "Public key (first 100 chars): [string range $rsa_public_key 0 100]..."
puts "Test data: '$test_data'"
puts "Signature binary (first 10 bytes): [string range $signature_binary 0 9]"
puts "Signature hex (first 50 chars): [string range $signature 0 50]..."
puts "Signature binary length: [string length $signature_binary]"
puts "Signature hex length: [string length $signature]"

# Try to validate
puts "Validating signature..."
set result [::tossl::signature::validate $rsa_public_key $test_data $signature "sha256"]
puts "Validation result: $result"

# Try with RSA verify command for comparison
puts "Trying RSA verify command..."
if {[catch {tossl::rsa::verify -key $rsa_public_key -data $test_data -signature $signature -alg sha256} rsa_result]} {
    puts "RSA verify error: $rsa_result"
} else {
    puts "RSA verify result: $rsa_result"
}
