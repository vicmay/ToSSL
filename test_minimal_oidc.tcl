#!/usr/bin/env tclsh
# Minimal OIDC Test

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Minimal OIDC Test ==="

# Test ID token validation
set current_time [clock seconds]
set exp_time [expr $current_time + 3600]
set iat_time [expr $current_time - 300]

set header "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
set payload "{\"iss\":\"https://accounts.google.com\",\"aud\":\"test_client\",\"sub\":\"1234567890\",\"exp\":$exp_time,\"iat\":$iat_time,\"nonce\":\"test_nonce\"}"

set header_b64 [tossl::base64url::encode $header]
set payload_b64 [tossl::base64url::encode $payload]
set id_token "$header_b64.$payload_b64.test_signature"

set result [tossl::oidc::validate_id_token \
    -token $id_token \
    -issuer "https://accounts.google.com" \
    -audience "test_client"]

puts "Validation result: $result"

puts "=== Test Complete ===" 