#!/usr/bin/env tclsh

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Debug JWT None Algorithm ==="

# Create JWT with none algorithm
set header [dict create alg none typ JWT]
set payload [dict create sub user_none iss test.com]

set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

puts "Header JSON: $header_json"
puts "Payload JSON: $payload_json"

set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "" -alg none]

puts "Created JWT: $jwt"
puts "JWT length: [string length $jwt]"

# Split the JWT to see its parts
lassign [split $jwt "."] header_part payload_part signature_part
puts "Header part: $header_part"
puts "Payload part: $payload_part"
puts "Signature part: '$signature_part'"
puts "Signature part length: [string length $signature_part]"

# Try to verify
puts "\nAttempting verification..."
set verify_result [tossl::jwt::verify -token $jwt -key "" -alg none]
puts "Verify result: $verify_result"

# Try to decode
puts "\nAttempting decode..."
set decoded [tossl::jwt::decode -token $jwt]
puts "Decode result: $decoded" 