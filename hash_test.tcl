#!/usr/bin/env tclsh

# Test to see if signature validate expects pre-hashed data

# Load the TOSSL extension
if {[catch {load ./libtossl.so} err]} {
    puts "Error loading TOSSL extension: $err"
    exit 1
}

# Create a simple test case
set test_data "test"

# Generate RSA key pair
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_private_key [dict get $rsa_keys private]
set rsa_public_key [dict get $rsa_keys public]

# Hash the data first
set hashed_data [tossl::digest -alg sha256 $test_data]

puts "Original data: '$test_data'"
puts "Hashed data: '$hashed_data'"

# Create signature using RSA sign
set signature_binary [tossl::rsa::sign -key $rsa_private_key -data $test_data -alg sha256]

# Convert to hex
binary scan $signature_binary H* signature_hex

# Try validation with original data
set result1 [::tossl::signature::validate $rsa_public_key $test_data $signature_hex "sha256"]
puts "Validation with original data: $result1"

# Try validation with hashed data
set result2 [::tossl::signature::validate $rsa_public_key $hashed_data $signature_hex "sha256"]
puts "Validation with hashed data: $result2"

# Try validation with binary hashed data
set hashed_data_binary [binary decode hex $hashed_data]
set result3 [::tossl::signature::validate $rsa_public_key $hashed_data_binary $signature_hex "sha256"]
puts "Validation with binary hashed data: $result3"
