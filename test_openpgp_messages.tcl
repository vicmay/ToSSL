#!/usr/bin/env tclsh

# Test script for RFC 4880 OpenPGP Message Format Support
# Tests literal data and compressed data packet creation and parsing

package require tossl

puts "=== Testing RFC 4880 OpenPGP Message Format Support ==="

# Test 1: Literal Data Packet Creation and Parsing
puts "\n--- Test 1: Literal Data Packet ---"

set test_data "Hello, OpenPGP world!"
set test_filename "test.txt"
set test_format "b"

puts "Creating literal data packet..."
set literal_packet [tossl::pgp::message::create_literal $test_data $test_filename $test_format]
puts "Literal packet created, length: [string length $literal_packet] bytes"
puts "Literal packet hex: [binary encode hex $literal_packet]"

puts "Parsing literal data packet..."
set parsed_packets [tossl::pgp::message::parse $literal_packet]
puts "Parsed packets: $parsed_packets"

# Extract the literal data packet
set literal_packet_dict [lindex $parsed_packets 0]
set packet_tag [dict get $literal_packet_dict tag]
puts "Packet tag: $packet_tag (should be 11 for literal data)"

if {$packet_tag == 11} {
    set packet_data [dict get $literal_packet_dict data]
    set format [dict get $packet_data format]
    set timestamp [dict get $packet_data timestamp]
    set data [dict get $packet_data data]
    set filename [dict get $packet_data filename]
    
    puts "Format: $format (should be 98 for 'b')"
    puts "Timestamp: $timestamp"
    puts "Filename: $filename"
    puts "Data: [encoding convertfrom utf-8 $data]"
    
    if {[string equal $data $test_data]} {
        puts "✓ Literal data roundtrip successful!"
    } else {
        puts "✗ Literal data roundtrip failed!"
    }
} else {
    puts "✗ Expected literal data packet (tag 11), got tag $packet_tag"
}

# Test 2: Compressed Data Packet Creation and Parsing
puts "\n--- Test 2: Compressed Data Packet ---"

set compressed_data "This is some data that would normally be compressed"
puts "Creating compressed data packet (uncompressed for now)..."
set compressed_packet [tossl::pgp::message::create_compressed $compressed_data 0]
puts "Compressed packet created, length: [string length $compressed_packet] bytes"

puts "Parsing compressed data packet..."
set parsed_compressed [tossl::pgp::message::parse $compressed_packet]
puts "Parsed compressed packets: $parsed_compressed"

# Extract the compressed data packet
set compressed_packet_dict [lindex $parsed_compressed 0]
set packet_tag [dict get $compressed_packet_dict tag]
puts "Packet tag: $packet_tag (should be 8 for compressed data)"

if {$packet_tag == 8} {
    set packet_data [dict get $compressed_packet_dict data]
    set algorithm [dict get $packet_data algorithm]
    set data [dict get $packet_data data]
    
    puts "Algorithm: $algorithm (should be 0 for uncompressed)"
    puts "Data: [encoding convertfrom utf-8 $data]"
    
    if {[string equal $data $compressed_data]} {
        puts "✓ Compressed data roundtrip successful!"
    } else {
        puts "✗ Compressed data roundtrip failed!"
    }
} else {
    puts "✗ Expected compressed data packet (tag 8), got tag $packet_tag"
}

# Test 3: Complex Message with Multiple Packets
puts "\n--- Test 3: Complex Message with Multiple Packets ---"

# Create a message with both literal and compressed packets
set literal1 [tossl::pgp::message::create_literal "First message" "msg1.txt" "t"]
set literal2 [tossl::pgp::message::create_literal "Second message" "msg2.txt" "b"]
set compressed1 [tossl::pgp::message::create_compressed "Compressed content" 0]

# Combine packets (in a real implementation, this would be done more carefully)
set complex_message "$literal1$literal2$compressed1"
puts "Complex message created, length: [string length $complex_message] bytes"

puts "Parsing complex message..."
set parsed_complex [tossl::pgp::message::parse $complex_message]
puts "Found [llength $parsed_complex] packets in complex message"

for {set i 0} {$i < [llength $parsed_complex]} {incr i} {
    set packet [lindex $parsed_complex $i]
    set tag [dict get $packet tag]
    puts "Packet $i: tag $tag"
    
    if {$tag == 11} {
        set data [dict get $packet data]
        set format [dict get $data format]
        set filename [dict get $data filename]
        puts "  Literal data: format=$format, filename=$filename"
    } elseif {$tag == 8} {
        set data [dict get $packet data]
        set algorithm [dict get $data algorithm]
        puts "  Compressed data: algorithm=$algorithm"
    }
}

puts "\n✓ All OpenPGP message format tests completed!"

# Test 4: Error Handling
puts "\n--- Test 4: Error Handling ---"

# Test with invalid data
catch {
    set result [tossl::pgp::message::parse "invalid data"]
    puts "✗ Should have failed with invalid data"
} err
puts "Expected error: $err"

# Test with unsupported compression algorithm
catch {
    set result [tossl::pgp::message::create_compressed "test" 99]
    puts "✗ Should have failed with unsupported algorithm"
} err
puts "Expected error: $err"

puts "\n=== OpenPGP Message Format Tests Complete ===" 