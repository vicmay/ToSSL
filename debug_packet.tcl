#!/usr/bin/env tclsh

# Debug script for packet header creation

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Debug Packet Header Creation ==="

# Generate a test key
set private_key [tossl::pgp::key::generate_secret -type rsa -bits 1024 -userid "Test User <test@example.com>"]

# Create a simple signature
set test_data "Hello, test!"
set signature [tossl::pgp::signature::create $private_key $test_data 0 2]

puts "Signature length: [string length $signature]"
puts "Signature hex: [binary encode hex $signature]"

# Parse the packet header manually
binary scan $signature "c" tag_byte
set tag [expr {$tag_byte & 0x3F}]
set new_format [expr {($tag_byte & 0x40) != 0}]

puts "Tag byte: [format "0x%02x" $tag_byte]"
puts "Tag: $tag"
puts "New format: $new_format"

if {$new_format} {
    binary scan $signature "@1c" len1
    puts "Length byte 1: [format "0x%02x" $len1]"
    
    if {$len1 < 192} {
        puts "Length: $len1 (1-byte format)"
    } elseif {$len1 < 224} {
        binary scan $signature "@2c" len2
        set len [expr {($len1 - 192) * 256 + $len2 + 192}]
        puts "Length: $len (2-byte format)"
    } else {
        binary scan $signature "@2cccc" len1 len2 len3 len4
        set len [expr {($len1 << 24) | ($len2 << 16) | ($len3 << 8) | $len4}]
        puts "Length: $len (4-byte format)"
    }
}

puts "Packet body starts with: [binary encode hex [string range $signature 3 6]]" 