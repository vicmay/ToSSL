#!/usr/bin/env tclsh

package require tossl

puts "=== OAuth2 Debug Test ==="

# Test 1: Authorization URL with scope
puts "Testing authorization URL generation..."
set auth_url [tossl::oauth2::authorization_url \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "read write" \
    -state "test_state" \
    -authorization_url "https://auth.example.com/oauth/authorize"]

puts "Generated URL: $auth_url"

if {[string match "*scope=*" $auth_url]} {
    puts "✅ Scope parameter found"
} else {
    puts "❌ Scope parameter missing"
}

# Test 2: RSA key generation
puts "\nTesting RSA key generation..."
if {[catch {
    set key_data [tossl::rsa::generate -bits 2048]
    puts "RSA key generation result: $key_data"
    
    if {[dict exists $key_data private_key]} {
        puts "✅ RSA private key generated"
    } else {
        puts "❌ RSA private key missing"
        puts "Available keys: [dict keys $key_data]"
    }
} result]} {
    puts "❌ RSA key generation failed: $result"
}

# Test 3: EC key generation
puts "\nTesting EC key generation..."
if {[catch {
    set key_data [tossl::key::generate -type ec -curve prime256v1]
    puts "EC key generation result: $key_data"
    
    if {[dict exists $key_data private]} {
        puts "✅ EC private key generated"
    } else {
        puts "❌ EC private key missing"
        puts "Available keys: [dict keys $key_data]"
    }
} result]} {
    puts "❌ EC key generation failed: $result"
    puts "Available key commands: [info commands tossl::key::*]"
}

# Test 4: JWT decode
puts "\nTesting JWT decode..."
set header [dict create alg HS256 typ JWT]
set payload [dict create iss "test_issuer" aud "test_audience"]
set header_json [tossl::json::generate $header]
set payload_json [tossl::json::generate $payload]

if {[catch {
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    puts "Created JWT: $jwt"
    
    set decoded [tossl::jwt::decode -token $jwt]
    puts "Decoded JWT: $decoded"
} result]} {
    puts "❌ JWT decode failed: $result"
}

# Test 5: Error handling
puts "\nTesting error handling..."
if {[catch {tossl::jwt::decode -token "invalid.jwt.format"} result]} {
    puts "✅ Invalid JWT format correctly rejected: $result"
} else {
    puts "❌ Invalid JWT format should have been rejected"
}

# Test 6: Token storage
puts "\nTesting token storage..."
set token_data [dict create access_token "test_token" expires_in 3600]
set token_json [tossl::json::generate $token_data]

if {[catch {
    set encrypted [tossl::oauth2::store_token -token_data $token_json -encryption_key "test_key"]
    puts "Encrypted token: $encrypted"
    
    set decrypted [tossl::oauth2::load_token -encrypted_data $encrypted -encryption_key "test_key"]
    puts "Decrypted token: $decrypted"
    
    if {$decrypted == $token_json} {
        puts "✅ Token storage/loading works correctly"
    } else {
        puts "❌ Token storage/loading failed"
    }
} result]} {
    puts "❌ Token storage failed: $result"
}

puts "\n=== Debug Test Complete ===" 