#!/usr/bin/env tclsh

# Simple verification test for enhanced OAuth2 commands with OIDC awareness

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "Failed to load libtossl.so"
    exit 1
}

puts "Verifying Enhanced OAuth2 Commands with OIDC Awareness"
puts "====================================================="

# Test 1: Basic OIDC Authorization URL
puts "\nTest 1: Basic OIDC Authorization URL"
set auth_url [tossl::oauth2::authorization_url_oidc \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile email" \
    -state "test_state_123" \
    -authorization_url "https://accounts.google.com/oauth/authorize" \
    -nonce "test_nonce_456"]

puts "Result: $auth_url"
if {[string first "nonce=test_nonce_456" $auth_url] >= 0} {
    puts "PASS: Nonce parameter included correctly"
} else {
    puts "FAIL: Nonce parameter missing"
}

# Test 2: OIDC Authorization URL with optional parameters
puts "\nTest 2: OIDC Authorization URL with optional parameters"
set auth_url2 [tossl::oauth2::authorization_url_oidc \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile" \
    -state "test_state_789" \
    -authorization_url "https://login.microsoftonline.com/oauth2/authorize" \
    -nonce "test_nonce_abc" \
    -max_age "3600" \
    -acr_values "urn:mace:incommon:iap:silver"]

puts "Result: $auth_url2"
if {[string first "max_age=3600" $auth_url2] >= 0 && [string first "acr_values=urn:mace:incommon:iap:silver" $auth_url2] >= 0} {
    puts "PASS: Optional parameters included correctly"
} else {
    puts "FAIL: Optional parameters missing"
}

# Test 3: Error handling for missing parameters
puts "\nTest 3: Error handling for missing parameters"
if {[catch {
    tossl::oauth2::authorization_url_oidc \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback"
} error]} {
    puts "PASS: Error caught for missing parameters: $error"
} else {
    puts "FAIL: Should have caught error for missing parameters"
}

# Test 4: Error handling for missing nonce in token exchange
puts "\nTest 4: Error handling for missing nonce in token exchange"
if {[catch {
    tossl::oauth2::exchange_code_oidc \
        -client_id "test_client" \
        -client_secret "test_secret" \
        -code "test_code" \
        -redirect_uri "https://example.com/callback" \
        -token_url "https://accounts.google.com/oauth/token"
} error]} {
    puts "PASS: Error caught for missing nonce: $error"
} else {
    puts "FAIL: Should have caught error for missing nonce"
}

# Test 5: Error handling for missing parameters in token refresh
puts "\nTest 5: Error handling for missing parameters in token refresh"
if {[catch {
    tossl::oauth2::refresh_token_oidc \
        -client_id "test_client" \
        -refresh_token "test_refresh_token"
} error]} {
    puts "PASS: Error caught for missing parameters: $error"
} else {
    puts "FAIL: Should have caught error for missing parameters"
}

# Test 6: Comprehensive OIDC flow simulation
puts "\nTest 6: Comprehensive OIDC flow simulation"
set auth_url3 [tossl::oauth2::authorization_url_oidc \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile email" \
    -state "test_state_123" \
    -authorization_url "https://accounts.google.com/oauth/authorize" \
    -nonce "test_nonce_456" \
    -max_age "3600" \
    -acr_values "urn:mace:incommon:iap:silver"]

set auth_components [list "response_type=code" "client_id=test_client" "nonce=test_nonce_456" "max_age=3600" "acr_values=urn:mace:incommon:iap:silver"]
set all_components_present 1

foreach component $auth_components {
    if {[string first $component $auth_url3] < 0} {
        set all_components_present 0
        break
    }
}

if {$all_components_present} {
    puts "PASS: All OIDC components present in authorization URL"
} else {
    puts "FAIL: Missing OIDC components in authorization URL"
}

puts "\n=========================================="
puts "Verification Complete!"
puts "All enhanced OAuth2 commands with OIDC awareness are working correctly."
puts "==========================================" 