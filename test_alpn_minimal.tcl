#!/usr/bin/env tclsh

# Minimal test for ALPN callback - no network operations
package require tossl

puts "Testing minimal ALPN functionality..."

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

# Test protocol version setting
puts "\n=== Testing protocol version setting ==="
set result [catch {
    tossl::ssl::set_protocol_version -ctx $ssl_ctx -min TLSv1.2 -max TLSv1.3
} err]
puts "Protocol version setting result: $result"
puts "Error: $err"

if {$result == 0} {
    puts "✓ Protocol version setting test passed"
} else {
    puts "✗ Protocol version setting test failed"
}

puts "\n=== All tests completed ===" 