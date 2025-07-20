#!/usr/bin/env tclsh

# Simple OIDC Test - Just run commands and report results

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "❌ Failed to load libtossl.so"
    exit 1
}

puts "🔍 SIMPLE OIDC TEST"
puts "==================="
puts ""

set passed 0
set total 0

# Simple test - just run the command and see if it works
proc simple_test {name command} {
    global passed total
    incr total
    
    puts "Testing: $name"
    if {[catch {eval $command} result]} {
        puts "❌ FAILED: $result"
        return 0
    } else {
        puts "✅ PASSED: $result"
        incr passed
        return 1
    }
}

# Test 1: Nonce generation
simple_test "Nonce Generation" {
    tossl::oidc::generate_nonce
}

# Test 2: State generation  
simple_test "State Generation" {
    tossl::oauth2::generate_state
}

# Test 3: Google provider preset
simple_test "Google Provider Preset" {
    tossl::oidc::provider::google -client_id test -client_secret test
}

# Test 4: OIDC authorization URL
simple_test "OIDC Authorization URL" {
    tossl::oauth2::authorization_url_oidc -client_id test -redirect_uri https://example.com -scope openid -state test -authorization_url https://example.com -nonce test
}

# Test 5: JWKS validation
simple_test "JWKS Validation" {
    tossl::oidc::validate_jwks -jwks { {"keys":[{"kty":"RSA","kid":"test","n":"test","e":"AQAB"}]} }
}

# Test 6: JWT verification
simple_test "JWT Verification" {
    tossl::oidc::verify_jwt_with_jwks -token eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2V5XzEifQ.test.signature -jwks { {"keys":[{"kty":"RSA","kid":"test_key_1","n":"test","e":"AQAB"}]} }
}

# Test 7: ID token validation
simple_test "ID Token Validation" {
    tossl::oidc::validate_id_token -token eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.test_signature -issuer https://accounts.google.com -audience test_client
}

# Test 8: UserInfo validation
simple_test "UserInfo Validation" {
    tossl::oidc::validate_userinfo -userinfo { {"sub":"test_user_123","name":"Test User","email":"test@example.com"} } -expected_subject test_user_123
}

# Test 9: Claims extraction
simple_test "Claims Extraction" {
    tossl::oidc::extract_user_claims -userinfo { {"sub":"test_user_123","name":"Test User","email":"test@example.com"} } -claims {name email}
}

# Test 10: Logout URL generation
simple_test "Logout URL Generation" {
    tossl::oidc::logout_url -id_token_hint test_token -end_session_endpoint https://example.com/logout -post_logout_redirect_uri https://example.com/redirect -state test_state
}

puts ""
puts "==================="
puts "RESULTS: $passed / $total tests passed"
puts "==================="

if {$passed == $total} {
    puts "🎉 ALL TESTS PASSED!"
    exit 0
} else {
    puts "❌ SOME TESTS FAILED!"
    exit 1
} 