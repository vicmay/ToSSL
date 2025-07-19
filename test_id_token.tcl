#!/usr/bin/env tclsh
# ID Token Validation Test for TOSSL OIDC

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== ID Token Validation Test ==="

# Test 1: Valid ID token with proper base64url encoding
puts "\nTest 1: Valid ID token"
set current_time [clock seconds]
set exp_time [expr $current_time + 3600] ;# 1 hour from now
set iat_time [expr $current_time - 300]  ;# 5 minutes ago

# Create a simple JWT with proper base64url encoding
set header "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
set payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$exp_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\"}"

# Use TOSSL base64url encoding
set header_b64 [tossl::base64url::encode $header]
set payload_b64 [tossl::base64url::encode $payload]

set id_token "$header_b64.$payload_b64.test_signature"

if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 2: Invalid issuer
puts "\nTest 2: Invalid issuer"
if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://wrong-issuer.com" \
        -audience "test_client"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 3: Invalid audience
puts "\nTest 3: Invalid audience"
if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "wrong_client"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 4: Nonce validation
puts "\nTest 4: Nonce validation"
if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client" \
        -nonce "test_nonce"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 5: Invalid nonce
puts "\nTest 5: Invalid nonce"
if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $id_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client" \
        -nonce "wrong_nonce"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 6: Expired token
puts "\nTest 6: Expired token"
set expired_time [expr $current_time - 3600] ;# 1 hour ago
set expired_payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$expired_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\"}"
set expired_payload_b64 [tossl::base64url::encode $expired_payload]
set expired_token "$header_b64.$expired_payload_b64.test_signature"

if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token $expired_token \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 7: Invalid JWT format
puts "\nTest 7: Invalid JWT format"
if {[catch {
    set result [tossl::oidc::validate_id_token \
        -token "invalid.jwt.format" \
        -issuer "https://accounts.google.com" \
        -audience "test_client"]
    puts "Validation result: $result"
} result]} {
    puts "Expected error: $result"
}

puts "\n=== ID Token Validation Test Complete ===" 