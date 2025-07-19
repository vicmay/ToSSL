#!/usr/bin/env tclsh

package require tossl

puts "=== Simple JWT Verification Test ==="

# Test JWT header
set header_b64 "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLWtleSJ9"
puts "Header (base64url): $header_b64"

# Decode header
set header_json [tossl::base64url::decode $header_b64]
puts "Decoded header: $header_json"

# Parse JSON
set header_dict [tossl::json::parse $header_json]
puts "Parsed header: $header_dict"

# Extract alg and kid
set alg [dict get $header_dict alg]
set kid [dict get $header_dict kid]
puts "Algorithm: $alg"
puts "Key ID: $kid"

# Test JWKS data
set jwks_data {
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "test-rsa-key",
      "use": "sig",
      "alg": "RS256",
      "n": "AQAB",
      "e": "AQAB"
    }
  ]
}
}

# Test the verification command
set test_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLWtleSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_signature"

puts "\nTesting JWT verification:"
set result [tossl::oidc::verify_jwt_with_jwks -token $test_jwt -jwks $jwks_data]
puts "Result: $result"

puts "\n=== Test Complete ===" 