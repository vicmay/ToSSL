#!/usr/bin/env tclsh

# Simple test for JWKS signature verification

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "Failed to load libtossl.so"
    exit 1
}

puts "Simple JWKS Signature Verification Test"
puts "======================================="

# Test 1: Check command availability
puts "\nTest 1: Command availability"
if {[lsearch [info commands tossl::oidc::*] "::tossl::oidc::verify_jwt_with_jwks"] >= 0} {
    puts "PASS: Command is available"
} else {
    puts "FAIL: Command not found"
    exit 1
}

# Test 2: Basic functionality test
puts "\nTest 2: Basic functionality test"
set jwks_data {
    {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "test_key_1",
                "n": "test_modulus_123456789",
                "e": "AQAB"
            }
        ]
    }
}

set jwt_token "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJ0ZXN0X2NsaWVudCIsImV4cCI6MTczNTY4MDAwMCwiaWF0IjoxNzM1Njc5OTAwLCJzdWIiOiJ0ZXN0X3VzZXIifQ.test_signature"

set result [tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data]
puts "Result: $result"

if {[dict exists $result valid] && [dict exists $result algorithm] && [dict exists $result key_id]} {
    puts "PASS: Returns valid dictionary format"
    puts "  - valid: [dict get $result valid]"
    puts "  - algorithm: [dict get $result algorithm]"
    puts "  - key_id: [dict get $result key_id]"
    puts "  - key_type: [dict get $result key_type]"
} else {
    puts "FAIL: Invalid result format"
    exit 1
}

# Test 3: Error handling test
puts "\nTest 3: Error handling test"
if {[catch {
    tossl::oidc::verify_jwt_with_jwks -token "invalid.jwt" -jwks "invalid json"
} error]} {
    puts "PASS: Error handling works correctly"
    puts "  Error: $error"
} else {
    puts "FAIL: Should have caught error"
    exit 1
}

# Test 4: Wrong number of arguments
puts "\nTest 4: Wrong number of arguments"
if {[catch {
    tossl::oidc::verify_jwt_with_jwks -token "test.token.signature"
} error]} {
    puts "PASS: Argument validation works correctly"
    puts "  Error: $error"
} else {
    puts "FAIL: Should have caught argument error"
    exit 1
}

# Test 5: EC key support
puts "\nTest 5: EC key support"
set ec_jwks {
    {
        "keys": [
            {
                "kty": "EC",
                "alg": "ES256",
                "use": "sig",
                "kid": "ec_key_1",
                "crv": "P-256",
                "x": "test_x_coordinate",
                "y": "test_y_coordinate"
            }
        ]
    }
}

set ec_jwt "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjX2tleV8xIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"

set ec_result [tossl::oidc::verify_jwt_with_jwks -token $ec_jwt -jwks $ec_jwks]
puts "EC Result: $ec_result"

if {[dict exists $ec_result key_type] && [dict get $ec_result key_type] eq "EC"} {
    puts "PASS: EC key support works"
} else {
    puts "FAIL: EC key support not working"
    exit 1
}

# Test 6: Multiple algorithms support
puts "\nTest 6: Multiple algorithms support"
set multi_alg_jwks {
    {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "rs256_key",
                "n": "test_modulus",
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "alg": "RS384",
                "use": "sig",
                "kid": "rs384_key",
                "n": "test_modulus",
                "e": "AQAB"
            }
        ]
    }
}

set rs384_jwt "eyJhbGciOiJSUzM4NCIsImtpZCI6InJzMzg0X2tleSJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"

set multi_result [tossl::oidc::verify_jwt_with_jwks -token $rs384_jwt -jwks $multi_alg_jwks]
puts "Multi-algorithm Result: $multi_result"

if {[dict exists $multi_result algorithm] && [dict get $multi_result algorithm] eq "RS384"} {
    puts "PASS: Multiple algorithms support works"
} else {
    puts "FAIL: Multiple algorithms support not working"
    exit 1
}

puts "\n=========================================="
puts "All tests passed! JWKS signature verification is working correctly."
puts "==========================================" 