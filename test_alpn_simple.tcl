#!/usr/bin/env tclsh

# Simple test for basic SSL functionality
package require tossl

puts "Testing basic SSL functionality..."

# Create SSL context
set ssl_ctx [tossl::ssl::context create]
puts "SSL context created: $ssl_ctx"

# Test ALPN callback setting
puts "\n=== Testing ALPN callback setting ==="
set result [catch {
    tossl::ssl::set_alpn_callback -ctx $ssl_ctx -callback alpn_select
} err]
puts "ALPN callback setting result: $result"
puts "Error: $err"

if {$result == 0} {
    puts "✓ ALPN callback setting test passed"
} else {
    puts "✗ ALPN callback setting test failed"
}

puts "\n=== Test completed ===" 