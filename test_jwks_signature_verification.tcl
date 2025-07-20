#!/usr/bin/env tclsh

# Comprehensive test for JWKS signature verification

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "Failed to load libtossl.so"
    exit 1
}

puts "Testing JWKS Signature Verification"
puts "==================================="

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

# Test function
proc test {name script expected_result} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "\n=== Test $test_count: $name ==="
    
    if {[catch {set result [eval $script]} error]} {
        puts "ERROR: $error"
        if {$expected_result eq "ERROR"} {
            puts "PASS: Expected error occurred"
            incr passed_count
        } else {
            puts "FAIL: Unexpected error, expected: $expected_result"
            incr failed_count
        }
    } else {
        puts "Result: $result"
        if {$result eq $expected_result} {
            puts "PASS: Result matches expected"
            incr passed_count
        } else {
            puts "FAIL: Result '$result' doesn't match expected '$expected_result'"
            incr failed_count
        }
    }
}

# Test summary function
proc print_summary {} {
    global test_count passed_count failed_count
    puts "\n" 
    puts "=========================================="
    puts "Test Summary:"
    puts "Total tests: $test_count"
    puts "Passed: $passed_count"
    puts "Failed: $failed_count"
    puts "=========================================="
    
    if {$failed_count == 0} {
        puts "All tests passed!"
        exit 0
    } else {
        puts "Some tests failed!"
        exit 1
    }
}

# Test 1: Basic JWKS signature verification with mock data
test "Basic JWKS signature verification" {
    # Mock JWKS data
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
    
    # Mock JWT token (this would be a real signed token in practice)
    set jwt_token "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJ0ZXN0X2NsaWVudCIsImV4cCI6MTczNTY4MDAwMCwiaWF0IjoxNzM1Njc5OTAwLCJzdWIiOiJ0ZXN0X3VzZXIifQ.test_signature"
    
    # Verify the JWT (this will fail with mock data, but should return a dictionary)
    set result [tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data]
    
    # Check if result is a dictionary with expected keys
    if {[dict exists $result valid] && [dict exists $result algorithm] && [dict exists $result key_id]} {
        return "VALID_DICT_FORMAT"
    } else {
        return "INVALID_FORMAT"
    }
} "VALID_DICT_FORMAT"

# Test 2: JWKS parsing validation
test "JWKS parsing validation" {
    # Invalid JWKS data
    set invalid_jwks "invalid json data"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token "test.token.signature" -jwks $invalid_jwks
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 3: Missing key ID in JWT header
test "Missing key ID in JWT header" {
    # JWKS with a key
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "test_key_1",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
    }
    
    # JWT without kid in header
    set jwt_token "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 4: Key not found in JWKS
test "Key not found in JWKS" {
    # JWKS with one key
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "key_1",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
    }
    
    # JWT with different kid
    set jwt_token "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleV8yIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 5: Unsupported key type
test "Unsupported key type" {
    # JWKS with unsupported key type
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "OCT",
                    "alg": "HS256",
                    "use": "sig",
                    "kid": "test_key_1",
                    "k": "test_key"
                }
            ]
        }
    }
    
    set jwt_token "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 6: Missing required JWK parameters
test "Missing required JWK parameters" {
    # JWKS with missing RSA parameters
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "test_key_1"
                }
            ]
        }
    }
    
    set jwt_token "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 7: Invalid JWT format
test "Invalid JWT format" {
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "test_key_1",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
    }
    
    # Invalid JWT format (missing parts)
    set invalid_jwt "invalid.jwt"
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token $invalid_jwt -jwks $jwks_data
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 8: Wrong number of arguments
test "Wrong number of arguments" {
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token "test.token.signature"
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 9: Command availability
test "Command availability" {
    if {[lsearch [info commands tossl::oidc::*] "tossl::oidc::verify_jwt_with_jwks"] >= 0} {
        return "AVAILABLE"
    } else {
        return "NOT_AVAILABLE"
    }
} "AVAILABLE"

# Test 10: JWKS structure validation
test "JWKS structure validation" {
    # JWKS without keys array
    set invalid_jwks {
        {
            "invalid": "structure"
        }
    }
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token "test.token.signature" -jwks $invalid_jwks
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 11: Empty JWKS
test "Empty JWKS" {
    # JWKS with empty keys array
    set empty_jwks {
        {
            "keys": []
        }
    }
    
    if {[catch {
        tossl::oidc::verify_jwt_with_jwks -token "test.token.signature" -jwks $empty_jwks
    } result]} {
        return "ERROR_HANDLED"
    } else {
        return "UNEXPECTED_SUCCESS"
    }
} "ERROR_HANDLED"

# Test 12: EC key support (structure test)
test "EC key support structure" {
    # JWKS with EC key
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
    
    set jwt_token "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjX2tleV8xIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    # This should return a dictionary even if verification fails
    set result [tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $ec_jwks]
    
    if {[dict exists $result valid] && [dict exists $result key_type] && [dict get $result key_type] eq "EC"} {
        return "EC_SUPPORTED"
    } else {
        return "EC_NOT_SUPPORTED"
    }
} "EC_SUPPORTED"

# Test 13: Multiple algorithms support
test "Multiple algorithms support" {
    # JWKS with multiple algorithms
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
    
    set jwt_token "eyJhbGciOiJSUzM4NCIsImtpZCI6InJzMzg0X2tleSJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature"
    
    set result [tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $multi_alg_jwks]
    
    if {[dict exists $result valid] && [dict exists $result algorithm] && [dict get $result algorithm] eq "RS384"} {
        return "MULTI_ALG_SUPPORTED"
    } else {
        return "MULTI_ALG_NOT_SUPPORTED"
    }
} "MULTI_ALG_SUPPORTED"

# Test 14: Verification result format
test "Verification result format" {
    set jwks_data {
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "test_key_1",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
    }
    
    set jwt_token "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.test.payload.signature"
    
    set result [tossl::oidc::verify_jwt_with_jwks -token $jwt_token -jwks $jwks_data]
    
    # Check all required fields are present
    set required_fields {valid algorithm key_id key_type}
    set all_fields_present 1
    
    foreach field $required_fields {
        if {![dict exists $result $field]} {
            set all_fields_present 0
            break
        }
    }
    
    if {$all_fields_present} {
        return "CORRECT_FORMAT"
    } else {
        return "INCORRECT_FORMAT"
    }
} "CORRECT_FORMAT"

# Print summary
print_summary 