#!/usr/bin/env tclsh

# Test script for OpenPGP Signature Support
# Tests signature creation, verification, and parsing

package require tossl

puts "=== Testing OpenPGP Signature Support ==="

# Test 1: Generate RSA key pair for testing
puts "\n--- Test 1: Generate RSA Key Pair ---"

set private_key [tossl::pgp::key::generate_secret -type rsa -bits 2048 -userid "Test User <test@example.com>"]
puts "Generated private key, length: [string length $private_key] bytes"

# Extract public key from private key
set key_info [tossl::pgp::key::parse $private_key]
puts "Key info: $key_info"

# Test 2: Create signature
puts "\n--- Test 2: Create OpenPGP Signature ---"

set test_data "Hello, this is a test message for OpenPGP signature verification!"
puts "Test data: $test_data"

# Create signature (binary document signature)
set signature [tossl::pgp::signature::create $private_key $test_data 0 2]
puts "Created signature, length: [string length $signature] bytes"
puts "Signature hex: [binary encode hex $signature]"

# Test 3: Parse signature
puts "\n--- Test 3: Parse OpenPGP Signature ---"

set parsed_sig [tossl::pgp::signature::parse $signature]
puts "Parsed signature: $parsed_sig"

# Extract signature components
set sig_type [dict get $parsed_sig type]
set pubkey_algo [dict get $parsed_sig pubkey_algo]
set hash_algo [dict get $parsed_sig hash_algo]
set version [dict get $parsed_sig version]

puts "Signature type: $sig_type (should be 0 for binary document)"
puts "Public key algorithm: $pubkey_algo (should be 1 for RSA)"
puts "Hash algorithm: $hash_algo (should be 2 for SHA1)"
puts "Version: $version (should be 4)"

# Test 4: Verify OpenPGP Signature
puts "\n--- Test 4: Verify OpenPGP Signature ---"
puts "Key info: [tossl::pgp::key::parse $private_key]"

# Use private key directly for verification (extract_pgp_public_key handles both)
puts "Using private key for verification"
set verify_result [tossl::pgp::signature::verify $private_key $test_data $signature]
puts "Verification result: $verify_result"
if {$verify_result} {
    puts "✓ Signature verified successfully!"
} else {
    puts "✗ Signature verification failed!"
}

# Test 5: Test with different data (should fail)
puts "\n--- Test 5: Test Signature with Modified Data ---"

set modified_data "Hello, this is a modified test message for OpenPGP signature verification!"
set verify_modified [tossl::pgp::signature::verify $private_key $modified_data $signature]
puts "Verification with modified data: $verify_modified"

if {!$verify_modified} {
    puts "✓ Correctly rejected signature for modified data!"
} else {
    puts "✗ Incorrectly accepted signature for modified data!"
}

# Test 6: Test signature parsing with message format
puts "\n--- Test 6: Test Signature in Message Format ---"

# Create a message with literal data and signature
set literal_packet [tossl::pgp::message::create_literal $test_data "test.txt" "b"]
set message_with_sig "${literal_packet}${signature}"

puts "Created message with signature, length: [string length $message_with_sig] bytes"

# Parse the message
set parsed_message [tossl::pgp::message::parse $message_with_sig]
puts "Parsed message packets: $parsed_message"

# Extract signature packet
set sig_packet [lindex $parsed_message 1]
set sig_packet_tag [dict get $sig_packet tag]
puts "Signature packet tag: $sig_packet_tag (should be 2)"

if {$sig_packet_tag == 2} {
    puts "✓ Correctly identified signature packet in message!"
} else {
    puts "✗ Failed to identify signature packet in message!"
}

# Test 7: Test different signature types
puts "\n--- Test 7: Test Different Signature Types ---"

# Test canonical text signature (type 1)
set text_data "Hello, this is canonical text.\nLine 2.\n"
set text_sig [tossl::pgp::signature::create $private_key $text_data 1 2]
puts "Created canonical text signature, length: [string length $text_sig] bytes"
set verify_text [tossl::pgp::signature::verify $private_key $text_data $text_sig]
puts "Verification result for canonical text: $verify_text"
if {$verify_text} {
    puts "✓ Canonical text signature verified!"
} else {
    puts "✗ Canonical text signature verification failed!"
}

# Test detached signature
puts "\n--- Test 7b: Test Detached Signature ---"
set detached_sig [tossl::pgp::signature::create $private_key $test_data 0 2 -detached]
puts "Created detached signature, length: [string length $detached_sig] bytes"
set verify_detached [tossl::pgp::signature::verify $private_key $test_data $detached_sig]
puts "Verification result for detached signature: $verify_detached"
if {$verify_detached} {
    puts "✓ Detached signature verified!"
} else {
    puts "✗ Detached signature verification failed!"
}

# Test 8: Test different hash algorithms
puts "\n--- Test 8: Test Different Hash Algorithms ---"

# Test with SHA256 (algorithm 8)
set sha256_sig [tossl::pgp::signature::create $private_key $test_data 0 8]
puts "Created SHA256 signature, length: [string length $sha256_sig] bytes"

set parsed_sha256 [tossl::pgp::signature::parse $sha256_sig]
set sha256_hash_algo [dict get $parsed_sha256 hash_algo]
puts "SHA256 signature hash algorithm: $sha256_hash_algo (should be 8)"

# Test 9: Comprehensive signature verification test
puts "\n--- Test 9: Comprehensive Signature Verification ---"

set test_messages {
    "Short message"
    "This is a longer message with more content to test signature verification"
    "Message with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
    "Unicode message: 你好世界 🌍"
}

foreach msg $test_messages {
    set sig [tossl::pgp::signature::create $private_key $msg 0 2]
    set verify [tossl::pgp::signature::verify $private_key $msg $sig]
    
    if {$verify} {
        puts "✓ Verified signature for: [string range $msg 0 30]..."
    } else {
        puts "✗ Failed to verify signature for: [string range $msg 0 30]..."
    }
}

puts "\n=== OpenPGP Signature Tests Complete ===" 