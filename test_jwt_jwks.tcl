#!/usr/bin/env tclsh

# Test JWT signature verification with JWKS
# This test demonstrates the new OIDC JWT verification functionality

package require tossl

puts "=== TOSSL JWT Signature Verification with JWKS Test ===\n"

# Test 1: Verify JWT with RSA JWK
puts "Test 1: JWT Signature Verification with RSA JWK"
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

# Create a test JWT (this is a mock JWT for testing)
set test_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLWtleSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_signature"

set result [tossl::oidc::verify_jwt_with_jwks -token $test_jwt -jwks $jwks_data]
puts "  Verification result: $result"

# Test 2: Verify JWT with EC JWK
puts "\nTest 2: JWT Signature Verification with EC JWK"
set ec_jwks_data {
{
  "keys": [
    {
      "kty": "EC",
      "kid": "test-ec-key",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "AQAB",
      "y": "AQAB"
    }
  ]
}
}

set ec_test_jwt "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtZWMta2V5In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_ec_signature"

set result [tossl::oidc::verify_jwt_with_jwks -token $ec_test_jwt -jwks $ec_jwks_data]
puts "  Verification result: $result"

# Test 3: Test with invalid JWT format
puts "\nTest 3: Invalid JWT Format"
set invalid_jwt "invalid.jwt.format"
set result [catch {tossl::oidc::verify_jwt_with_jwks -token $invalid_jwt -jwks $jwks_data} error]
puts "  Expected error: $error"

# Test 4: Test with missing kid in JWT header
puts "\nTest 4: Missing kid in JWT Header"
set no_kid_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_signature"
set result [catch {tossl::oidc::verify_jwt_with_jwks -token $no_kid_jwt -jwks $jwks_data} error]
puts "  Expected error: $error"

# Test 5: Test with missing key in JWKS
puts "\nTest 5: Missing Key in JWKS"
set missing_key_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1pc3Npbmcta2V5In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_signature"
set result [catch {tossl::oidc::verify_jwt_with_jwks -token $missing_key_jwt -jwks $jwks_data} error]
puts "  Expected error: $error"

# Test 6: Test with unsupported key type
puts "\nTest 6: Unsupported Key Type"
set unsupported_jwks {
{
  "keys": [
    {
      "kty": "OCT",
      "kid": "test-oct-key",
      "use": "sig",
      "alg": "HS256",
      "k": "AQAB"
    }
  ]
}
}

set oct_test_jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qtb2N0LWtleSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.test_oct_signature"

set result [catch {tossl::oidc::verify_jwt_with_jwks -token $oct_test_jwt -jwks $unsupported_jwks} error]
puts "  Expected error: $error"

# Test 7: Test command availability
puts "\nTest 7: Command Availability"
if {[info commands tossl::oidc::verify_jwt_with_jwks] ne ""} {
    puts "  ✅ tossl::oidc::verify_jwt_with_jwks command is available"
} else {
    puts "  ❌ tossl::oidc::verify_jwt_with_jwks command is not available"
}

puts "\n=== JWT Signature Verification Test Complete ==="
puts "\nNote: These tests use mock JWTs and JWKS data."
puts "Real verification would require valid cryptographic signatures."
puts "The tests demonstrate the API functionality and error handling." 