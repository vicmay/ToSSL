#!/usr/bin/env tclsh
# Test script for ACME functionality with DNS-01 challenge support

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ACME functionality with DNS-01 challenge support..."
puts "========================================================"

# Test 1: HTTP functionality (prerequisite for ACME)
puts "\n1. Testing HTTP functionality..."
if {[catch {
    set response [tossl::http::get "https://acme-staging-v02.api.letsencrypt.org/directory"]
    puts "   Status: [dict get $response status_code]"
    puts "   ✓ HTTP functionality working"
} err]} {
    puts "   ✗ HTTP functionality failed: $err"
    exit 1
}

# Test 2: ACME directory fetch
puts "\n2. Testing ACME directory fetch..."
if {[catch {
    set directory [tossl::acme::directory "https://acme-staging-v02.api.letsencrypt.org/directory"]
    puts "   Directory keys: [dict keys $directory]"
    puts "   ✓ ACME directory fetch working"
} err]} {
    puts "   ✗ ACME directory fetch failed: $err"
}

# Test 3: Generate account key
puts "\n3. Testing account key generation..."
if {[catch {
    set account_keys [tossl::key::generate -type rsa -bits 2048]
    set account_private [dict get $account_keys private]
    puts "   ✓ Account key generated"
} err]} {
    puts "   ✗ Account key generation failed: $err"
}

# Test 4: ACME account creation (simulated)
puts "\n4. Testing ACME account creation..."
if {[catch {
    set result [tossl::acme::create_account "https://acme-staging-v02.api.letsencrypt.org/directory" $account_private "test@example.com"]
    puts "   Result: $result"
    puts "   ✓ ACME account creation working"
} err]} {
    puts "   ✗ ACME account creation failed: $err"
}

# Test 5: ACME order creation (simulated)
puts "\n5. Testing ACME order creation..."
if {[catch {
    set domains "example.com"
    set result [tossl::acme::create_order "https://acme-staging-v02.api.letsencrypt.org/directory" $account_private $domains]
    puts "   Result: $result"
    puts "   ✓ ACME order creation working"
} err]} {
    puts "   ✗ ACME order creation failed: $err"
}

# Test 6: DNS-01 challenge preparation
puts "\n6. Testing DNS-01 challenge preparation..."
if {[catch {
    set domain "example.com"
    set token "test-token-12345"
    set provider "cloudflare"
    set api_key "test-api-key"
    set zone_id "test-zone-id"
    
    set challenge [tossl::acme::dns01_challenge $domain $token $account_private $provider $api_key $zone_id]
    puts "   Challenge type: [dict get $challenge type]"
    puts "   DNS record name: [dict get $challenge dns_record_name]"
    puts "   DNS record value: [dict get $challenge dns_record_value]"
    puts "   ✓ DNS-01 challenge preparation working"
} err]} {
    puts "   ✗ DNS-01 challenge preparation failed: $err"
}

# Test 7: DNS cleanup (simulated)
puts "\n7. Testing DNS cleanup..."
if {[catch {
    set domain "example.com"
    set record_name "_acme-challenge.example.com"
    set provider "cloudflare"
    set api_key "test-api-key"
    set zone_id "test-zone-id"
    
    set result [tossl::acme::cleanup_dns $domain $record_name $provider $api_key $zone_id]
    puts "   Result: $result"
    puts "   ✓ DNS cleanup working"
} err]} {
    puts "   ✗ DNS cleanup failed: $err"
}

puts "\n========================================================"
puts "ACME integration test completed."
puts "Note: Some tests are simulated since they require real API credentials."
puts "To test with real credentials, you would need:"
puts "  - Cloudflare API key and zone ID"
puts "  - A domain you control"
puts "  - Network access to ACME servers" 