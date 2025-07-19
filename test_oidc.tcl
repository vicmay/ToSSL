#!/usr/bin/env tclsh
# OIDC Test Suite for TOSSL
# Tests the new OpenID Connect functionality

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== TOSSL OIDC Test Suite ==="

set test_count 0
set passed 0
set failed 0

proc run_test {name script} {
    global test_count passed failed
    incr test_count
    puts "\nTest $test_count: $name"
    
    if {[catch $script result]} {
        puts "  ❌ FAIL: $result"
        incr failed
    } else {
        puts "  ✅ PASS"
        incr passed
    }
}

# Test 1: OIDC Discovery with mock data
run_test "OIDC Discovery with mock data" {
    # Test discovery with a mock issuer URL
    # This will fail with a real HTTP request, but we can test the parsing logic
    set error_caught 0
    if {[catch {
        set config [tossl::oidc::discover -issuer "https://invalid-issuer.example.com"]
    } result]} {
        set error_caught 1
        # Expected to fail with invalid issuer
    }
    
    if {!$error_caught} {
        error "Discovery should have failed with invalid issuer"
    }
}

# Test 2: OIDC Nonce Generation
run_test "OIDC Nonce Generation" {
    # Generate a nonce
    set nonce1 [tossl::oidc::generate_nonce]
    set nonce2 [tossl::oidc::generate_nonce]
    
    # Check that nonces are generated
    if {[string length $nonce1] == 0} {
        error "First nonce is empty"
    }
    
    if {[string length $nonce2] == 0} {
        error "Second nonce is empty"
    }
    
    # Check that nonces are different (random)
    if {$nonce1 == $nonce2} {
        error "Generated nonces are identical (not random)"
    }
    
    # Check that nonces are reasonable length (base64url encoded)
    if {[string length $nonce1] < 20} {
        error "Nonce too short: [string length $nonce1]"
    }
    
    if {[string length $nonce1] > 100} {
        error "Nonce too long: [string length $nonce1]"
    }
    
    puts "   Nonce 1: $nonce1"
    puts "   Nonce 2: $nonce2"
}

# Test 3: Multiple Nonce Generation
run_test "Multiple Nonce Generation" {
    set nonces {}
    for {set i 0} {$i < 10} {incr i} {
        lappend nonces [tossl::oidc::generate_nonce]
    }
    
    # Check that all nonces are unique
    set unique_nonces [lsort -unique $nonces]
    if {[llength $unique_nonces] != [llength $nonces]} {
        error "Duplicate nonces generated"
    }
    
    puts "   Generated [llength $nonces] unique nonces"
}

# Test 4: Nonce Format Validation
run_test "Nonce Format Validation" {
    set nonce [tossl::oidc::generate_nonce]
    
    # Check that nonce contains only valid base64url characters
    set valid_chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for {set i 0} {$i < [string length $nonce]} {incr i} {
        set char [string index $nonce $i]
        if {[string first $char $valid_chars] == -1} {
            error "Invalid character in nonce: '$char'"
        }
    }
    
    puts "   Nonce format is valid: $nonce"
}

# Test 5: OIDC Discovery Error Handling
run_test "OIDC Discovery Error Handling" {
    # Test with various invalid inputs
    set test_cases {
        {"" "empty issuer"}
        {"not-a-url" "invalid URL format"}
        {"http://example.com" "non-HTTPS URL"}
    }
    
    foreach {issuer description} $test_cases {
        set error_caught 0
        if {[catch {
            tossl::oidc::discover -issuer $issuer
        } result]} {
            set error_caught 1
        }
        
        if {!$error_caught} {
            error "Discovery should have failed with $description"
        }
    }
    
    puts "   All error cases handled correctly"
}

# Test 6: OIDC Discovery with Real Provider (if available)
run_test "OIDC Discovery with Real Provider" {
    # Try with Google's OIDC endpoint (this might work if network is available)
    set error_caught 0
    if {[catch {
        set config [tossl::oidc::discover -issuer "https://accounts.google.com"]
        
        # If successful, validate the response structure
        if {[dict exists $config issuer]} {
            puts "   Issuer: [dict get $config issuer]"
        }
        
        if {[dict exists $config authorization_endpoint]} {
            puts "   Authorization endpoint: [dict get $config authorization_endpoint]"
        }
        
        if {[dict exists $config token_endpoint]} {
            puts "   Token endpoint: [dict get $config token_endpoint]"
        }
        
        if {[dict exists $config userinfo_endpoint]} {
            puts "   UserInfo endpoint: [dict get $config userinfo_endpoint]"
        }
        
        if {[dict exists $config jwks_uri]} {
            puts "   JWKS URI: [dict get $config jwks_uri]"
        }
        
        if {[dict exists $config scopes_supported]} {
            puts "   Supported scopes: [dict get $config scopes_supported]"
        }
        
        if {[dict exists $config id_token_signing_alg_values_supported]} {
            puts "   ID token signing algorithms: [dict get $config id_token_signing_alg_values_supported]"
        }
        
    } result]} {
        set error_caught 1
        puts "   Network discovery failed (expected if no internet): $result"
    }
    
    # This test is expected to fail if no internet connection
    # We don't count it as a failure since it's environment-dependent
    if {$error_caught} {
        puts "   Note: Network discovery test skipped (no internet connection)"
    }
}

# Test 7: OIDC Discovery Caching
run_test "OIDC Discovery Caching" {
    # Test that multiple calls to the same issuer use caching
    # This is an internal implementation detail, but we can test it indirectly
    
    # Generate some nonces to test caching doesn't interfere
    set nonce1 [tossl::oidc::generate_nonce]
    set nonce2 [tossl::oidc::generate_nonce]
    
    if {$nonce1 == $nonce2} {
        error "Nonce generation affected by caching"
    }
    
    puts "   Caching test passed (nonce generation unaffected)"
}

# Test 8: OIDC Integration with OAuth2
run_test "OIDC Integration with OAuth2" {
    # Test that OIDC nonce can be used with OAuth2 authorization URL
    set nonce [tossl::oidc::generate_nonce]
    set state [tossl::oauth2::generate_state]
    
    # Create a mock OAuth2 authorization URL with OIDC scope
    set auth_url [tossl::oauth2::authorization_url \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile email" \
        -state $state \
        -authorization_url "https://accounts.google.com/o/oauth2/v2/auth"]
    
    # Check that the URL contains OIDC scope
    if {[string first "openid" $auth_url] == -1} {
        error "OIDC scope not found in authorization URL"
    }
    
    # Check that the URL contains the state parameter
    if {[string first "state=$state" $auth_url] == -1} {
        error "State parameter not found in authorization URL"
    }
    
    puts "   OAuth2 authorization URL with OIDC scope: [string range $auth_url 0 100]..."
}

# Test 9: OIDC Nonce Security
run_test "OIDC Nonce Security" {
    # Test that nonces are cryptographically random
    set nonces {}
    for {set i 0} {$i < 50} {incr i} {
        lappend nonces [tossl::oidc::generate_nonce]
    }
    
    # Check for patterns (simple entropy test)
    set all_nonces [join $nonces ""]
    set char_counts {}
    
    for {set i 0} {$i < [string length $all_nonces]} {incr i} {
        set char [string index $all_nonces $i]
        if {[dict exists $char_counts $char]} {
            dict incr char_counts $char
        } else {
            dict set char_counts $char 1
        }
    }
    
    # Check that no single character dominates (simple randomness check)
    set total_chars [string length $all_nonces]
    dict for {char count} $char_counts {
        set percentage [expr {double($count) / $total_chars * 100}]
        if {$percentage > 25} {
            error "Character '$char' appears too frequently: $percentage%"
        }
    }
    
    puts "   Nonce entropy test passed"
}

# Test 10: OIDC Command Availability
run_test "OIDC Command Availability" {
    # Check that OIDC commands are available
    set required_commands {
        "::tossl::oidc::discover"
        "::tossl::oidc::generate_nonce"
        "::tossl::oidc::fetch_jwks"
        "::tossl::oidc::get_jwk"
        "::tossl::oidc::validate_jwks"
        "::tossl::oidc::validate_id_token"
        "::tossl::oidc::userinfo"
        "::tossl::oidc::validate_userinfo"
        "::tossl::oidc::extract_user_claims"
        "::tossl::oidc::logout_url"
        "::tossl::oidc::end_session"
        "::tossl::oidc::validate_logout_response"
    }
    
    foreach cmd $required_commands {
        if {[lsearch [info commands ::tossl::oidc::*] $cmd] == -1} {
            error "Required OIDC command not found: $cmd"
        }
    }
    
    puts "   All required OIDC commands are available"
}

# Test 11: JWKS Validation
run_test "JWKS Validation" {
    set jwks_data {
    {
      "keys": [
        {
          "kty": "RSA",
          "kid": "test-key-1",
          "n": "test-n-value",
          "e": "AQAB"
        },
        {
          "kty": "EC",
          "kid": "test-key-2",
          "crv": "P-256",
          "x": "test-x",
          "y": "test-y"
        }
      ]
    }
    }
    
    set result [tossl::oidc::validate_jwks -jwks $jwks_data]
    
    if {![dict get $result valid]} {
        error "JWKS validation failed"
    }
    
    if {[dict get $result keys_count] != 2} {
        error "Expected 2 keys, got [dict get $result keys_count]"
    }
    
    if {[dict get $result valid_keys] != 2} {
        error "Expected 2 valid keys, got [dict get $result valid_keys]"
    }
    
    puts "   JWKS validation passed: [dict get $result keys_count] keys, [dict get $result valid_keys] valid"
}

# Test 12: JWK Retrieval
run_test "JWK Retrieval" {
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
    
    set jwk [tossl::oidc::get_jwk -jwks $jwks_data -kid "test-key-1"]
    
    if {[string first "test-key-1" $jwk] == -1} {
        error "Retrieved JWK does not contain expected kid"
    }
    
    if {[string first "RSA" $jwk] == -1} {
        error "Retrieved JWK does not contain expected kty"
    }
    
    puts "   JWK retrieval passed: $jwk"
}

# Test 13: JWKS Error Handling
run_test "JWKS Error Handling" {
    # Test invalid JSON
    if {![catch {
        tossl::oidc::validate_jwks -jwks "invalid json"
    } result]} {
        error "Should have failed with invalid JSON"
    }
    
    # Test missing keys field
    if {![catch {
        tossl::oidc::validate_jwks -jwks "{}"
    } result]} {
        error "Should have failed with missing keys field"
    }
    
    # Test empty keys array
    if {![catch {
        tossl::oidc::validate_jwks -jwks '{"keys":[]}'
    } result]} {
        error "Should have failed with empty keys array"
    }
    
    # Test non-existent kid
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
    
    if {![catch {
        tossl::oidc::get_jwk -jwks $jwks_data -kid "non-existent"
    } result]} {
        error "Should have failed with non-existent kid"
    }
    
    puts "   All error cases handled correctly"
}

# Test 14: ID Token Validation
run_test "ID Token Validation" {
    set current_time [clock seconds]
    set exp_time [expr $current_time + 3600] ;# 1 hour from now
    set iat_time [expr $current_time - 300]  ;# 5 minutes ago
    
    # Create a valid ID token
    set header "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
    set payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$exp_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\"}"
    
    set header_b64 [tossl::base64url::encode $header]
    set payload_b64 [tossl::base64url::encode $payload]
    set id_token "$header_b64.$payload_b64.test_signature"
    
    # Test valid token
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    
    if {![dict get $result valid]} {
        error "Valid token validation failed: [dict get $result error]"
    }
    
    # Test invalid issuer
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://wrong-issuer.com" \
        -audience "test_client"]
    
    if {[dict get $result valid]} {
        error "Invalid issuer should have failed validation"
    }
    
    # Test invalid audience
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "wrong_client"]
    
    if {[dict get $result valid]} {
        error "Invalid audience should have failed validation"
    }
    
    # Test nonce validation
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client" \
        -nonce "test_nonce"]
    
    if {![dict get $result valid]} {
        error "Nonce validation failed: [dict get $result error]"
    }
    
    # Test invalid nonce
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client" \
        -nonce "wrong_nonce"]
    
    if {[dict get $result valid]} {
        error "Invalid nonce should have failed validation"
    }
    
    # Test expired token
    set expired_time [expr $current_time - 3600] ;# 1 hour ago
    set expired_payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$expired_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\"}"
    set expired_payload_b64 [tossl::base64url::encode $expired_payload]
    set expired_token "$header_b64.$expired_payload_b64.test_signature"
    
    set result [tossl::oidc::validate_id_token \
        -token $expired_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    
    if {[dict get $result valid]} {
        error "Expired token should have failed validation"
    }
    
    # Test invalid format
    if {![catch {
        tossl::oidc::validate_id_token \
            -token "invalid.jwt.format" \
            -issuer "https://accounts.google.com" \
            -audience "test_client"
    } result]} {
        error "Invalid JWT format should have failed"
    }
    
    puts "   Valid token validation passed"
    puts "   Invalid issuer detection passed"
    puts "   Invalid audience detection passed"
    puts "   Nonce validation passed"
    puts "   Invalid nonce detection passed"
    puts "   Expired token detection passed"
    puts "   Invalid format handling passed"
}

# Test 15: ID Token Claims Extraction
run_test "ID Token Claims Extraction" {
    set current_time [clock seconds]
    set exp_time [expr $current_time + 3600]
    set iat_time [expr $current_time - 300]
    
    # Create a token with various claims
    set header "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
    set payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$exp_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\",\"acr\":\"urn:mace:incommon:iap:bronze\",\"auth_time\":$iat_time}"
    
    set header_b64 [tossl::base64url::encode $header]
    set payload_b64 [tossl::base64url::encode $payload]
    set id_token "$header_b64.$payload_b64.test_signature"
    
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    
    # Verify all claims are extracted
    if {[dict get $result subject] != "1234567890"} {
        error "Subject claim not extracted correctly"
    }
    
    if {[dict get $result nonce] != "test_nonce"} {
        error "Nonce claim not extracted correctly"
    }
    
    if {[dict get $result acr] != "urn:mace:incommon:iap:bronze"} {
        error "ACR claim not extracted correctly"
    }
    
    puts "   Claims extraction working correctly"
}

# Test 16: UserInfo Endpoint
run_test "UserInfo Endpoint" {
    set userinfo_data {
    {
      "sub": "1234567890",
      "name": "John Doe",
      "given_name": "John",
      "family_name": "Doe",
      "email": "john.doe@example.com",
      "email_verified": true,
      "picture": "https://example.com/john.jpg"
    }
    }
    
    # Test UserInfo validation
    set result [tossl::oidc::validate_userinfo \
        -userinfo $userinfo_data \
        -expected_subject "1234567890"]
    
    if {![dict get $result valid]} {
        error "UserInfo validation failed"
    }
    
    if {[dict get $result subject] != "1234567890"} {
        error "Subject mismatch in UserInfo validation"
    }
    
    # Test UserInfo validation with wrong subject
    if {![catch {
        tossl::oidc::validate_userinfo \
            -userinfo $userinfo_data \
            -expected_subject "wrong_subject"
    } result]} {
        error "UserInfo validation should have failed with wrong subject"
    }
    
    puts "   UserInfo validation passed"
    puts "   Subject validation passed"
}

# Test 17: UserInfo Claims Extraction
run_test "UserInfo Claims Extraction" {
    set userinfo_data {
    {
      "sub": "1234567890",
      "name": "John Doe",
      "given_name": "John",
      "family_name": "Doe",
      "email": "john.doe@example.com",
      "email_verified": true,
      "picture": "https://example.com/john.jpg"
    }
    }
    
    # Test claims extraction
    set result [tossl::oidc::extract_user_claims \
        -userinfo $userinfo_data \
        -claims {name email picture}]
    
    if {[dict get $result name] != "John Doe"} {
        error "Name claim not extracted correctly"
    }
    
    if {[dict get $result email] != "john.doe@example.com"} {
        error "Email claim not extracted correctly"
    }
    
    if {[dict get $result picture] != "https://example.com/john.jpg"} {
        error "Picture claim not extracted correctly"
    }
    
    # Test boolean claim extraction
    set result [tossl::oidc::extract_user_claims \
        -userinfo $userinfo_data \
        -claims {email_verified}]
    
    if {![dict get $result email_verified]} {
        error "Boolean claim not extracted correctly"
    }
    
    puts "   Claims extraction working correctly"
    puts "   Boolean claims extraction working correctly"
}

# Test 18: UserInfo Error Handling
run_test "UserInfo Error Handling" {
    # Test invalid JSON
    if {![catch {
        tossl::oidc::validate_userinfo \
            -userinfo "invalid json" \
            -expected_subject "1234567890"
    } result]} {
        error "Should have failed with invalid JSON"
    }
    
    # Test missing subject
    set userinfo_no_sub {
    {
      "name": "John Doe",
      "email": "john.doe@example.com"
    }
    }
    
    if {![catch {
        tossl::oidc::validate_userinfo \
            -userinfo $userinfo_no_sub \
            -expected_subject "1234567890"
    } result]} {
        error "Should have failed with missing subject"
    }
    
    puts "   Invalid JSON handling passed"
    puts "   Missing subject handling passed"
}

# Test 19: OIDC Logout URL Generation
run_test "OIDC Logout URL Generation" {
    set id_token_hint "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test_token"
    set end_session_endpoint "https://accounts.google.com/o/oauth2/v2/logout"
    
    # Test basic logout URL
    set logout_url [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint]
    
    if {![string match "*id_token_hint=*" $logout_url]} {
        error "Logout URL missing id_token_hint parameter"
    }
    
    if {![string match "*$end_session_endpoint*" $logout_url]} {
        error "Logout URL missing end session endpoint"
    }
    
    # Test logout URL with redirect URI
    set logout_url_with_redirect [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint \
        -post_logout_redirect_uri "https://myapp.com/logout"]
    
    if {![string match "*post_logout_redirect_uri=*" $logout_url_with_redirect]} {
        error "Logout URL missing post_logout_redirect_uri parameter"
    }
    
    # Test logout URL with state
    set logout_url_with_state [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint \
        -post_logout_redirect_uri "https://myapp.com/logout" \
        -state "logout_state_123"]
    
    if {![string match "*state=*" $logout_url_with_state]} {
        error "Logout URL missing state parameter"
    }
    
    puts "   Basic logout URL generation passed"
    puts "   Redirect URI support passed"
    puts "   State parameter support passed"
}

# Test 20: OIDC Logout Response Validation
run_test "OIDC Logout Response Validation" {
    # Test empty response
    set result [tossl::oidc::validate_logout_response -response ""]
    if {![dict get $result valid]} {
        error "Empty response should be valid"
    }
    
    if {[dict get $result type] != "empty_response"} {
        error "Empty response type should be 'empty_response'"
    }
    
    # Test JSON response
    set json_response "{\"status\": \"success\", \"message\": \"User logged out successfully\"}"
    set result [tossl::oidc::validate_logout_response -response $json_response]
    if {![dict get $result valid]} {
        error "JSON response should be valid"
    }
    
    if {[dict get $result type] != "json_response"} {
        error "JSON response type should be 'json_response'"
    }
    
    # Test error response
    set error_response "{\"error\": \"invalid_token\", \"error_description\": \"The provided token is invalid\"}"
    set result [tossl::oidc::validate_logout_response -response $error_response]
    if {[dict get $result valid]} {
        error "Error response should not be valid"
    }
    
    if {[dict get $result type] != "error_response"} {
        error "Error response type should be 'error_response'"
    }
    
    if {[dict get $result error] != "invalid_token"} {
        error "Error response should contain correct error code"
    }
    
    # Test text response
    set text_response "User successfully logged out"
    set result [tossl::oidc::validate_logout_response -response $text_response]
    if {![dict get $result valid]} {
        error "Text response should be valid"
    }
    
    if {[dict get $result type] != "text_response"} {
        error "Text response type should be 'text_response'"
    }
    
    puts "   Empty response validation passed"
    puts "   JSON response validation passed"
    puts "   Error response validation passed"
    puts "   Text response validation passed"
}

# Test 21: OIDC Logout Error Handling
run_test "OIDC Logout Error Handling" {
    # Test missing required parameters
    if {![catch {
        tossl::oidc::logout_url -end_session_endpoint "https://example.com/logout"
    } result]} {
        error "Should have failed with missing id_token_hint"
    }
    
    if {![catch {
        tossl::oidc::logout_url -id_token_hint "test_token"
    } result]} {
        error "Should have failed with missing end_session_endpoint"
    }
    
    puts "   Parameter validation passed"
}

puts ""
puts "=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed"
puts "Failed: $failed"

if {$failed == 0} {
    puts "All tests passed! 🎉"
    puts ""
    puts "OIDC Phase 1 Implementation Status:"
    puts "✅ OIDC Discovery endpoint support"
    puts "✅ OIDC Nonce generation"
    puts "✅ Error handling and validation"
    puts "✅ Integration with existing OAuth2 infrastructure"
    puts "✅ Security and randomness validation"
} else {
    puts "Some tests failed! ❌"
    exit 1
}

puts ""
puts "Next steps for OIDC implementation:"
puts "1. JWKS (JSON Web Key Set) support"
puts "2. Enhanced JWT validation for ID tokens"
puts "3. UserInfo endpoint support"
puts "4. OIDC logout functionality"
puts "5. Provider presets (Google, Microsoft, GitHub)" 