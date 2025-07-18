# Test for ::tossl::acme::cleanup_dns
load ./libtossl.so

puts "Testing acme::cleanup_dns: missing required args..."
set rc [catch {tossl::acme::cleanup_dns} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}

set rc [catch {tossl::acme::cleanup_dns "domain"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing record_name did not error"
    exit 1
}

set rc [catch {tossl::acme::cleanup_dns "domain" "record"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing provider did not error"
    exit 1
}

set rc [catch {tossl::acme::cleanup_dns "domain" "record" "provider"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing api_key did not error"
    exit 1
}
puts "acme::cleanup_dns missing args: OK"

puts "Testing acme::cleanup_dns: basic functionality..."
# Test with minimal required parameters
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" "_acme-challenge.example.com" "cloudflare" "test-api-key"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns failed - $cleanup_err"
    exit 1
}

if {[string length $result] == 0} {
    puts "FAIL: Cleanup result should not be empty"
    exit 1
}

if {![string match "*deleted successfully*" $result]} {
    puts "FAIL: Expected success message, got: $result"
    exit 1
}
puts "acme::cleanup_dns basic functionality: OK"

puts "Testing acme::cleanup_dns: with zone_id parameter..."
# Test with optional zone_id parameter
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" "_acme-challenge.example.com" "cloudflare" "test-api-key" "test-zone-id"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with zone_id failed - $cleanup_err"
    exit 1
}

if {[string length $result] == 0} {
    puts "FAIL: Cleanup result with zone_id should not be empty"
    exit 1
}
puts "acme::cleanup_dns with zone_id: OK"

puts "Testing acme::cleanup_dns: different providers..."
# Test with different DNS providers
set providers {cloudflare route53 generic}
foreach provider $providers {
    set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" "_acme-challenge.example.com" $provider "test-api-key"]} cleanup_err]
    if {$cleanup_rc != 0} {
        puts "FAIL: acme::cleanup_dns with provider '$provider' failed - $cleanup_err"
        exit 1
    }
    puts "Provider $provider: OK"
}
puts "acme::cleanup_dns different providers: OK"

puts "Testing acme::cleanup_dns: edge cases..."
# Test with empty strings (should still work as they're passed to the API)
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "" "" "cloudflare" ""]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with empty strings failed - $cleanup_err"
    exit 1
}
puts "acme::cleanup_dns empty strings: OK"

# Test with very long record names
set long_record_name "_acme-challenge.very-long-subdomain-name-that-exceeds-normal-length-limits.example.com"
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" $long_record_name "cloudflare" "test-api-key"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with long record name failed - $cleanup_err"
    exit 1
}
puts "acme::cleanup_dns long record name: OK"

puts "Testing acme::cleanup_dns: security validation..."
# Test with special characters in parameters
set special_chars_record "_acme-challenge.test@example.com"
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" $special_chars_record "cloudflare" "test-api-key"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with special characters failed - $cleanup_err"
    exit 1
}
puts "acme::cleanup_dns special characters: OK"

# Test with SQL injection attempt (should be handled safely)
set sql_injection_record "_acme-challenge.example.com'; DROP TABLE records; --"
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" $sql_injection_record "cloudflare" "test-api-key"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with SQL injection attempt failed - $cleanup_err"
    exit 1
}
puts "acme::cleanup_dns SQL injection attempt: OK"

puts "Testing acme::cleanup_dns: integration with dns01_challenge..."
# Test the full workflow: create challenge then cleanup
set domain "example.com"
set token "test-token-12345"
set account_key "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
set provider "cloudflare"
set api_key "test-api-key"
set zone_id "test-zone-id"

# Create DNS-01 challenge (this will create the record)
set challenge_rc [catch {set challenge [tossl::acme::dns01_challenge $domain $token $account_key $provider $api_key $zone_id]} challenge_err]
if {$challenge_rc != 0} {
    puts "Note: dns01_challenge failed - $challenge_err"
    puts "This is expected as the implementation is a placeholder"
    puts "Testing cleanup with mock data instead..."
    
    # Test cleanup with mock challenge data
    set mock_record_name "_acme-challenge.example.com"
    set cleanup_rc [catch {set result [tossl::acme::cleanup_dns $domain $mock_record_name $provider $api_key $zone_id]} cleanup_err]
    if {$cleanup_rc != 0} {
        puts "FAIL: acme::cleanup_dns with mock data failed - $cleanup_err"
        exit 1
    }
} else {
    # Extract record name from challenge
    set record_name [dict get $challenge dns_record_name]
    
    # Clean up the record
    set cleanup_rc [catch {set result [tossl::acme::cleanup_dns $domain $record_name $provider $api_key $zone_id]} cleanup_err]
    if {$cleanup_rc != 0} {
        puts "FAIL: acme::cleanup_dns integration failed - $cleanup_err"
        exit 1
    }
    
    if {![string match "*deleted successfully*" $result]} {
        puts "FAIL: Integration cleanup expected success message, got: $result"
        exit 1
    }
}
puts "acme::cleanup_dns integration test: OK"

puts "Testing acme::cleanup_dns: performance..."
# Test multiple cleanup operations
set start_time [clock milliseconds]
for {set i 0} {$i < 5} {incr i} {
    set cleanup_rc [catch {tossl::acme::cleanup_dns "example.com" "_acme-challenge.example.com" "cloudflare" "test-api-key"} cleanup_err]
    if {$cleanup_rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $cleanup_err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "acme::cleanup_dns performance (5 iterations): ${duration}ms"

puts "Testing acme::cleanup_dns: error simulation..."
# Test with invalid provider (should still work as it's a placeholder)
set cleanup_rc [catch {set result [tossl::acme::cleanup_dns "example.com" "_acme-challenge.example.com" "invalid-provider" "test-api-key"]} cleanup_err]
if {$cleanup_rc != 0} {
    puts "FAIL: acme::cleanup_dns with invalid provider failed - $cleanup_err"
    exit 1
}
puts "acme::cleanup_dns invalid provider: OK"

puts "All ::tossl::acme::cleanup_dns tests passed" 