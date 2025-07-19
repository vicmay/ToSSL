#!/usr/bin/env tclsh
# JWKS Test for TOSSL OIDC

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== JWKS Test ==="

# Test 1: Basic JWKS validation
puts "\nTest 1: Basic JWKS validation"
set jwks_data {
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "test-key-1",
      "n": "test-n-value",
      "e": "AQAB"
    }
  ]
}
}

puts "JWKS data: $jwks_data"

if {[catch {
    set result [tossl::oidc::validate_jwks -jwks $jwks_data]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 2: Get specific JWK
puts "\nTest 2: Get specific JWK"
if {[catch {
    set jwk [tossl::oidc::get_jwk -jwks $jwks_data -kid "test-key-1"]
    puts "Found JWK: $jwk"
} result]} {
    puts "Error: $result"
}

# Test 3: Test with invalid JSON
puts "\nTest 3: Invalid JSON"
if {[catch {
    set result [tossl::oidc::validate_jwks -jwks "invalid json"]
    puts "Result: $result"
} result]} {
    puts "Expected error: $result"
}

puts "\n=== JWKS Test Complete ===" 