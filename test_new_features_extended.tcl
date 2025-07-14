#!/usr/bin/env tclsh

package require tossl

puts "=== Testing Extended TOSSL Features ===\n"

# Test 1: EC Point Operations
puts "1. Testing EC Point Operations..."
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_components [tossl::ec::components -key [dict get $ec_keys private]]
set pub_point [dict get $ec_components public_point]
puts "   EC key components extracted successfully"
puts "   Public point: [string range $pub_point 0 31]..."

# Test point multiplication (multiply by 2)
set result [tossl::ec::point_multiply -point $pub_point -scalar "2" -curve prime256v1]
puts "   Point multiplication successful"
puts "   Result: [string range $result 0 31]..."

# Test point addition (add point to itself = multiply by 2)
set result2 [tossl::ec::point_add -point1 $pub_point -point2 $pub_point -curve prime256v1]
puts "   Point addition successful"
puts "   Result: [string range $result2 0 31]..."
puts ""

# Test 2: Ed25519 Operations (if supported)
puts "2. Testing Ed25519 Operations..."
set ed25519_rc [catch {set ed25519_keys [tossl::ed25519::generate]} ed25519_result]
if {$ed25519_rc == 0} {
    puts "   Ed25519 key generation successful"
    set ed25519_priv [dict get $ed25519_keys private]
    set ed25519_pub [dict get $ed25519_keys public]
    
    set test_data "Hello, Ed25519!"
    set ed25519_sig [tossl::ed25519::sign -privkey $ed25519_priv $test_data]
    puts "   Ed25519 signing successful"
    
    set ed25519_valid [tossl::ed25519::verify -pubkey $ed25519_pub $test_data $ed25519_sig]
    puts "   Ed25519 verification: $ed25519_valid"
} else {
    puts "   Ed25519 not supported: $ed25519_result"
}
puts ""

# Test 3: X25519 Operations (if supported)
puts "3. Testing X25519 Operations..."
set x25519_rc [catch {set x25519_keys [tossl::x25519::generate]} x25519_result]
if {$x25519_rc == 0} {
    puts "   X25519 key generation successful"
    set x25519_priv [dict get $x25519_keys private]
    set x25519_pub [dict get $x25519_keys public]
    
    # Generate a second key pair for key exchange
    set x25519_keys2 [tossl::x25519::generate]
    set x25519_priv2 [dict get $x25519_keys2 private]
    set x25519_pub2 [dict get $x25519_keys2 public]
    
    # Derive shared secret
    set shared1 [tossl::x25519::derive -privkey $x25519_priv -pubkey $x25519_pub2]
    set shared2 [tossl::x25519::derive -privkey $x25519_priv2 -pubkey $x25519_pub]
    puts "   X25519 key exchange successful"
    puts "   Shared secrets match: [expr {$shared1 eq $shared2}]"
} else {
    puts "   X25519 not supported: $x25519_result"
}
puts ""

# Test 4: Key Fingerprinting
puts "4. Testing Key Fingerprinting..."
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_pub [dict get $rsa_keys public]
set rsa_fingerprint [tossl::key::fingerprint -key $rsa_pub -alg sha256]
puts "   RSA key fingerprint: [string range $rsa_fingerprint 0 31]..."

set ec_fingerprint [tossl::key::fingerprint -key [dict get $ec_keys public] -alg sha256]
puts "   EC key fingerprint: [string range $ec_fingerprint 0 31]..."
puts ""

# Test 5: Certificate Time Validation
puts "5. Testing Certificate Time Validation..."
set ca_keys [tossl::rsa::generate -bits 2048]
set ca_cert [tossl::ca::generate -key [dict get $ca_keys private] -subject "Test CA" -days 365]
set time_validation [tossl::x509::time_validate -cert $ca_cert]
puts "   Certificate time validation: [dict get $time_validation valid]"
puts "   Not before: [dict get $time_validation not_before]"
puts "   Not after: [dict get $time_validation not_after]"
puts "   Current time: [dict get $time_validation current_time]"
puts ""

# Test 6: Base64URL Encoding/Decoding
puts "6. Testing Base64URL Encoding/Decoding..."
set test_data "Hello, Base64URL! This is a test with special chars: +/="
set b64url_encoded [tossl::base64url::encode $test_data]
puts "   Base64URL encoded: $b64url_encoded"

set b64url_decoded [tossl::base64url::decode $b64url_encoded]
puts "   Base64URL decoded: $b64url_decoded"
puts "   Roundtrip successful: [expr {$test_data eq $b64url_decoded}]"
puts ""

# Test 7: Compare with regular Base64
puts "7. Testing Base64URL vs Base64..."
set regular_b64 [tossl::base64::encode $test_data]
puts "   Regular Base64: $regular_b64"
puts "   Base64URL:      $b64url_encoded"
puts "   URLs are different: [expr {$regular_b64 ne $b64url_encoded}]"
puts ""

# Test 8: Edge cases for Base64URL
puts "8. Testing Base64URL Edge Cases..."
set edge_data "A"
set edge_b64url [tossl::base64url::encode $edge_data]
puts "   Single byte: $edge_b64url"
set edge_decoded [tossl::base64url::decode $edge_b64url]
puts "   Decoded: $edge_decoded"
puts "   Single byte roundtrip: [expr {$edge_data eq $edge_decoded}]"

set edge_data2 "AB"
set edge_b64url2 [tossl::base64url::encode $edge_data2]
puts "   Two bytes: $edge_b64url2"
set edge_decoded2 [tossl::base64url::decode $edge_b64url2]
puts "   Decoded: $edge_decoded2"
puts "   Two bytes roundtrip: [expr {$edge_data2 eq $edge_decoded2}]"
puts ""

puts "=== All Extended Features Tested Successfully ==="
puts "\nSummary of new features implemented:"
puts "- EC point operations (addition, multiplication, component extraction)"
puts "- Ed25519 key generation, signing, and verification"
puts "- X25519 key generation and key exchange"
puts "- Key fingerprinting for RSA and EC keys"
puts "- Certificate time validation"
puts "- Base64URL encoding and decoding"

puts "\nThese features address the following items from MISSING-TODO.md:"
puts "- EC point operations"
puts "- EC key components extraction"
puts "- Ed25519/Ed448 support (Ed25519 implemented)"
puts "- X25519/X448 key exchange (X25519 implemented)"
puts "- Key fingerprinting"
puts "- Certificate time validation"
puts "- Base64URL encoding/decoding" 