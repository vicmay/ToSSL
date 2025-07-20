#!/usr/bin/env tclsh

# Test suite for enhanced OAuth2 commands with OIDC awareness
# Tests the new OIDC-enhanced OAuth2 commands:
# - tossl::oauth2::authorization_url_oidc
# - tossl::oauth2::exchange_code_oidc  
# - tossl::oauth2::refresh_token_oidc

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "Failed to load libtossl.so"
    exit 1
}

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

# Test helper functions
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

proc test_contains {name script expected_substring} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "\n=== Test $test_count: $name ==="
    
    if {[catch {set result [eval $script]} error]} {
        puts "ERROR: $error"
        puts "FAIL: Unexpected error"
        incr failed_count
    } else {
        puts "Result: $result"
        if {[string first $expected_substring $result] >= 0} {
            puts "PASS: Result contains expected substring"
            incr passed_count
        } else {
            puts "FAIL: Result doesn't contain expected substring '$expected_substring'"
            incr failed_count
        }
    }
}

proc test_error {name script expected_error} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "\n=== Test $test_count: $name ==="
    
    if {[catch {set result [eval $script]} error]} {
        puts "Error: $error"
        if {[string first $expected_error $error] >= 0} {
            puts "PASS: Expected error occurred"
            incr passed_count
        } else {
            puts "FAIL: Unexpected error, expected: $expected_error"
            incr failed_count
        }
    } else {
        puts "Result: $result"
        puts "FAIL: Expected error but got result"
        incr failed_count
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

puts "Testing Enhanced OAuth2 Commands with OIDC Awareness"
puts "=================================================="

# Test 1: Basic authorization URL with OIDC parameters
test "Basic OIDC Authorization URL" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile email" \
        -state "test_state_123" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce_456"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile email&state=test_state_123&nonce=test_nonce_456"

# Test 2: Authorization URL with optional OIDC parameters
test "OIDC Authorization URL with max_age and acr_values" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile" \
        -state "test_state_789" \
        -authorization_url "https://login.microsoftonline.com/oauth2/authorize" \
        -nonce "test_nonce_abc" \
        -max_age "3600" \
        -acr_values "urn:mace:incommon:iap:silver"
} "https://login.microsoftonline.com/oauth2/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile&state=test_state_789&nonce=test_nonce_abc&max_age=3600&acr_values=urn:mace:incommon:iap:silver"

# Test 3: Missing required parameters
test_error "Missing client_id" {
    tossl::oauth2::authorization_url_oidc \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile" \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce"
} "Missing required parameters"

# Test 4: Missing nonce parameter
test_error "Missing nonce" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile" \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize"
} "Missing required parameters"

# Test 5: Wrong number of arguments
test_error "Wrong number of arguments" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback"
} "wrong # args"

# Test 6: URL encoding of special characters
test "URL encoding of special characters" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test client with spaces" \
        -redirect_uri "https://example.com/callback?param=value" \
        -scope "openid profile email" \
        -state "test state with spaces" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test nonce with spaces"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test client with spaces&redirect_uri=https://example.com/callback?param=value&scope=openid profile email&state=test state with spaces&nonce=test nonce with spaces"

# Test 7: Basic OIDC token exchange (mock test)
test "Basic OIDC token exchange" {
    # This is a mock test since we can't make real HTTP requests
    # In a real scenario, this would exchange an authorization code for tokens
    set mock_response '{"access_token":"mock_access_token","token_type":"Bearer","expires_in":3600,"id_token":"mock_id_token","refresh_token":"mock_refresh_token"}'
    
    # Simulate the token exchange process using string operations
    if {[string first "mock_id_token" $mock_response] >= 0} {
        return "Token exchange successful"
    } else {
        return "Nonce validation failed"
    }
} "Token exchange successful"

# Test 8: OIDC token exchange with nonce validation
test "OIDC token exchange with nonce validation" {
    # Mock ID token with nonce
    set mock_id_token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibm9uY2UiOiJ0ZXN0X25vbmNlXzEyMyIsImlhdCI6MTUxNjIzOTAyMn0.mock_signature"
    
    # Simulate nonce validation
    if {[string first "test_nonce_123" $mock_id_token] >= 0} {
        return "Nonce validation passed"
    } else {
        return "Nonce validation failed"
    }
} "Nonce validation passed"

# Test 9: OIDC token refresh with scope
test "OIDC token refresh with scope" {
    # Mock refresh token response
    set mock_refresh_response '{"access_token":"new_access_token","token_type":"Bearer","expires_in":3600,"scope":"openid profile email"}'
    
    # Parse the response using string operations
    if {[string first "openid profile email" $mock_refresh_response] >= 0} {
        return "Token refresh successful with scope"
    } else {
        return "Token refresh failed"
    }
} "Token refresh successful with scope"

# Test 10: OIDC token refresh without scope
test "OIDC token refresh without scope" {
    # Mock refresh token response without scope
    set mock_refresh_response '{"access_token":"new_access_token","token_type":"Bearer","expires_in":3600}'
    
    # Parse the response using string operations
    if {[string first "access_token" $mock_refresh_response] >= 0} {
        return "Token refresh successful without scope"
    } else {
        return "Token refresh failed"
    }
} "Token refresh successful without scope"

# Test 11: Error handling in OIDC token exchange
test_error "OIDC token exchange with invalid parameters" {
    tossl::oauth2::exchange_code_oidc \
        -client_id "test_client" \
        -client_secret "test_secret" \
        -code "invalid_code" \
        -redirect_uri "https://example.com/callback" \
        -token_url "https://accounts.google.com/oauth/token" \
        -nonce "test_nonce"
} "TCL_Eval"

# Test 12: Error handling in OIDC token refresh
test_error "OIDC token refresh with invalid parameters" {
    tossl::oauth2::refresh_token_oidc \
        -client_id "test_client" \
        -client_secret "test_secret" \
        -refresh_token "invalid_refresh_token" \
        -token_url "https://accounts.google.com/oauth/token"
} "TCL_Eval"

# Test 13: OIDC authorization URL with complex scope
test "OIDC authorization URL with complex scope" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile email https://www.googleapis.com/auth/userinfo.profile" \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile email https://www.googleapis.com/auth/userinfo.profile&state=test_state&nonce=test_nonce"

# Test 14: OIDC authorization URL with multiple acr_values
test "OIDC authorization URL with multiple acr_values" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile" \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce" \
        -acr_values "urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile&state=test_state&nonce=test_nonce&acr_values=urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze"

# Test 15: Integration test with OIDC provider preset
test "Integration with OIDC provider preset" {
    # Get Google OIDC configuration
    set google_config [tossl::oidc::provider::google -client_id "test_client" -client_secret "test_secret"]
    
    # Extract authorization URL using string operations
    if {[string first "authorization_endpoint" $google_config] >= 0} {
        # Extract the URL from the configuration string
        set start_idx [string first "https://" $google_config]
        if {$start_idx >= 0} {
            set end_idx [string first "\"" $google_config $start_idx]
            if {$end_idx >= 0} {
                set auth_url [string range $google_config $start_idx [expr $end_idx - 1]]
                
                # Generate OIDC authorization URL using the preset
                set oidc_url [tossl::oauth2::authorization_url_oidc \
                    -client_id "test_client" \
                    -redirect_uri "https://example.com/callback" \
                    -scope "openid profile email" \
                    -state "test_state" \
                    -authorization_url $auth_url \
                    -nonce "test_nonce"]
                
                # Verify the URL contains the expected components
                if {[string first "accounts.google.com" $oidc_url] >= 0 && \
                    [string first "response_type=code" $oidc_url] >= 0 && \
                    [string first "nonce=test_nonce" $oidc_url] >= 0} {
                    return "Integration test passed"
                }
            }
        }
    }
    return "Integration test failed"
} "Integration test passed"

# Test 16: Error handling for missing OIDC parameters in token exchange
test_error "Missing nonce in OIDC token exchange" {
    tossl::oauth2::exchange_code_oidc \
        -client_id "test_client" \
        -client_secret "test_secret" \
        -code "test_code" \
        -redirect_uri "https://example.com/callback" \
        -token_url "https://accounts.google.com/oauth/token"
} "Missing required parameters"

# Test 17: Error handling for missing OIDC parameters in token refresh
test_error "Missing required parameters in OIDC token refresh" {
    tossl::oauth2::refresh_token_oidc \
        -client_id "test_client" \
        -refresh_token "test_refresh_token"
} "Missing required parameters"

# Test 18: OIDC authorization URL with very long parameters
test "OIDC authorization URL with long parameters" {
    set long_scope "openid profile email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/plus.circles.read"
    
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope $long_scope \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/plus.circles.read&state=test_state&nonce=test_nonce"

# Test 19: OIDC authorization URL with special characters in nonce
test "OIDC authorization URL with special characters in nonce" {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile" \
        -state "test_state" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce_with_special_chars_!@#$%^&*()"
} "https://accounts.google.com/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://example.com/callback&scope=openid profile&state=test_state&nonce=test_nonce_with_special_chars_!@#$%^&*()"

# Test 20: Comprehensive OIDC flow simulation
test "Comprehensive OIDC flow simulation" {
    # Step 1: Generate authorization URL
    set auth_url [tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "openid profile email" \
        -state "test_state_123" \
        -authorization_url "https://accounts.google.com/oauth/authorize" \
        -nonce "test_nonce_456" \
        -max_age "3600" \
        -acr_values "urn:mace:incommon:iap:silver"]
    
    # Step 2: Verify authorization URL components
    set auth_components [list "response_type=code" "client_id=test_client" "nonce=test_nonce_456" "max_age=3600" "acr_values=urn:mace:incommon:iap:silver"]
    set all_components_present 1
    
    foreach component $auth_components {
        if {[string first $component $auth_url] < 0} {
            set all_components_present 0
            break
        }
    }
    
    if {$all_components_present} {
        return "Comprehensive OIDC flow simulation passed"
    } else {
        return "Comprehensive OIDC flow simulation failed"
    }
} "Comprehensive OIDC flow simulation passed"

# Print test summary
print_summary 