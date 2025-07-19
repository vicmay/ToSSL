#!/usr/bin/env tclsh
# OIDC Logout Test for TOSSL OIDC

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== OIDC Logout Test ==="

# Test 1: Generate logout URL
puts "\nTest 1: Generate logout URL"
set id_token_hint "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test_token"
set end_session_endpoint "https://accounts.google.com/o/oauth2/v2/logout"

if {[catch {
    set logout_url [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint]
    puts "Logout URL: $logout_url"
} result]} {
    puts "Error: $result"
}

# Test 2: Generate logout URL with redirect URI
puts "\nTest 2: Generate logout URL with redirect URI"
if {[catch {
    set logout_url [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint \
        -post_logout_redirect_uri "https://myapp.com/logout"]
    puts "Logout URL with redirect: $logout_url"
} result]} {
    puts "Error: $result"
}

# Test 3: Generate logout URL with state
puts "\nTest 3: Generate logout URL with state"
if {[catch {
    set logout_url [tossl::oidc::logout_url \
        -id_token_hint $id_token_hint \
        -end_session_endpoint $end_session_endpoint \
        -post_logout_redirect_uri "https://myapp.com/logout" \
        -state "logout_state_123"]
    puts "Logout URL with state: $logout_url"
} result]} {
    puts "Error: $result"
}

# Test 4: Validate empty logout response
puts "\nTest 4: Validate empty logout response"
if {[catch {
    set result [tossl::oidc::validate_logout_response -response ""]
    puts "Empty response validation: $result"
} result]} {
    puts "Error: $result"
}

# Test 5: Validate JSON logout response
puts "\nTest 5: Validate JSON logout response"
set json_response "{\"status\": \"success\", \"message\": \"User logged out successfully\"}"
if {[catch {
    set result [tossl::oidc::validate_logout_response -response $json_response]
    puts "JSON response validation: $result"
} result]} {
    puts "Error: $result"
}

# Test 6: Validate error logout response
puts "\nTest 6: Validate error logout response"
set error_response "{\"error\": \"invalid_token\", \"error_description\": \"The provided token is invalid\"}"
if {[catch {
    set result [tossl::oidc::validate_logout_response -response $error_response]
    puts "Error response validation: $result"
} result]} {
    puts "Error: $result"
}

# Test 7: Validate text logout response
puts "\nTest 7: Validate text logout response"
set text_response "User successfully logged out"
if {[catch {
    set result [tossl::oidc::validate_logout_response -response $text_response]
    puts "Text response validation: $result"
} result]} {
    puts "Error: $result"
}

# Test 8: Missing required parameters
puts "\nTest 8: Missing required parameters"
if {[catch {
    set logout_url [tossl::oidc::logout_url \
        -end_session_endpoint $end_session_endpoint]
    puts "Logout URL: $logout_url"
} result]} {
    puts "Expected error: $result"
}

puts "\n=== OIDC Logout Test Complete ===" 