#!/usr/bin/env tclsh

package require tossl

puts "=== JWT Header Debug Test ==="

# Test JWT header
set test_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLWtleSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_signature"

puts "Test JWT: $test_jwt"

# Split the JWT
set parts [split $test_jwt "."]
puts "Number of parts: [llength $parts]"

if {[llength $parts] >= 1} {
    set header [lindex $parts 0]
    puts "Header (base64url): $header"
    
    # Try to decode the header
    set decoded [tossl::base64url_decode $header]
    puts "Decoded header: $decoded"
    
    # Try to parse as JSON
    set parsed [tossl::json::parse $decoded]
    puts "Parsed JSON: $parsed"
}

puts "=== Debug Complete ===" 