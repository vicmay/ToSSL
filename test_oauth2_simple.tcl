#!/usr/bin/env tclsh
# Simple OAuth2 Test for TOSSL
# Basic test to debug segmentation fault

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Simple OAuth2 Test ==="

# Test 1: Basic OAuth2 state generation
puts "\n1. Testing OAuth2 State Generation..."
if {[catch {
    set state [tossl::oauth2::generate_state]
    puts "   ✓ State generated: [string range $state 0 16]..."
} err]} {
    puts "   ✗ State generation failed: $err"
}

# Test 2: OAuth2 authorization URL
puts "\n2. Testing OAuth2 Authorization URL..."
if {[catch {
    set auth_url [tossl::oauth2::authorization_url \
        -client_id "test_client" \
        -redirect_uri "https://example.com/callback" \
        -scope "read" \
        -state "test_state" \
        -authorization_url "https://auth.example.com/oauth/authorize"]
    puts "   ✓ Authorization URL: $auth_url"
} err]} {
    puts "   ✗ Authorization URL failed: $err"
}

# Test 3: OAuth2 token parsing
puts "\n3. Testing OAuth2 Token Parsing..."
if {[catch {
    set response "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
    set parsed [tossl::oauth2::parse_token $response]
    puts "   ✓ Token parsed successfully"
    puts "   Parsed result type: [llength $parsed]"
    puts "   Parsed result: $parsed"
    puts "   Access token: [dict get $parsed access_token]"
} err]} {
    puts "   ✗ Token parsing failed: $err"
}

# Test 4: State validation
puts "\n4. Testing State Validation..."
if {[catch {
    set valid [tossl::oauth2::validate_state "state1" "state1"]
    puts "   ✓ State validation result: $valid"
} err]} {
    puts "   ✗ State validation failed: $err"
}

puts "\n=== Simple OAuth2 Test Complete ===" 