#!/usr/bin/env tclsh

# Debug script for OpenPGP signature parsing issue

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Debug OpenPGP Signature Parsing ==="

# Generate a test key
set private_key [tossl::pgp::key::generate_secret -type rsa -bits 1024 -userid "Test User <test@example.com>"]

# Create a simple signature
set test_data "Hello, test!"
set signature [tossl::pgp::signature::create $private_key $test_data 0 2]

puts "Signature length: [string length $signature]"
puts "Signature hex: [binary encode hex $signature]"

# Try to parse the signature
puts "\nAttempting to parse signature..."
if {[catch {set parsed [tossl::pgp::signature::parse $signature]} err]} {
    puts "Error parsing signature: $err"
} else {
    puts "Successfully parsed signature: $parsed"
}

# Let's also try to parse just the signature packet body (skip packet header)
set sig_hex [binary encode hex $signature]
puts "\nFull signature hex: $sig_hex"

# Extract just the packet body for debugging
if {[string length $signature] > 3} {
    set packet_body [string range $signature 3 end]
    puts "Packet body length: [string length $packet_body]"
    puts "Packet body hex: [binary encode hex $packet_body]"
    
    # Check first few bytes
    set first_bytes [string range $packet_body 0 3]
    puts "First 4 bytes: [binary encode hex $first_bytes]"
    binary scan $first_bytes cccc version sig_type pubkey_algo hash_algo
    puts "Version: $version, Type: $sig_type, PubKeyAlgo: $pubkey_algo, HashAlgo: $hash_algo"
}

# Let's also check the packet header
if {[string length $signature] >= 3} {
    set packet_header [string range $signature 0 2]
    puts "\nPacket header hex: [binary encode hex $packet_header]"
    binary scan $packet_header ccc tag len1 len2
    puts "Packet header bytes: tag=$tag len1=$len1 len2=$len2"
    
    # Decode the packet header
    set new_format [expr {($tag & 0xC0) == 0xC0}]
    set packet_tag [expr {$tag & 0x3F}]
    puts "New format: $new_format, Packet tag: $packet_tag"
    
    if {$new_format} {
        if {$len1 < 192} {
            puts "Length: $len1"
        } elseif {$len1 >= 192 && $len1 <= 223} {
            set length [expr {($len1 - 192) * 256 + $len2 + 192}]
            puts "Length: $length"
        } elseif {$len1 == 255} {
            puts "Length: 5-byte format (not supported in this debug)"
        }
    }
} 