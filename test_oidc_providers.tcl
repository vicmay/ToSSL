#!/usr/bin/env tclsh

# Test OIDC Provider Preset Functionality
# Tests the convenience functions for Google, Microsoft, GitHub, and custom OIDC providers

package require tossl

# Test setup
set test_count 0
set passed_count 0
set failed_count 0

proc test {name test_script} {
    global test_count passed_count failed_count
    incr test_count
    puts "Test $test_count: $name"
    
    if {[catch {eval $test_script} result]} {
        puts "  FAILED: $result"
        incr failed_count
        return 0
    } else {
        puts "  PASSED"
        incr passed_count
        return 1
    }
}

proc assert {condition message} {
    if {![expr $condition]} {
        error "Assertion failed: $message"
    }
}

proc assert_dict_contains {dict key message} {
    if {![dict exists $dict $key]} {
        error "Assertion failed: $message - key '$key' not found in dict"
    }
}

proc assert_dict_equals {dict key expected message} {
    if {[dict get $dict $key] ne $expected} {
        error "Assertion failed: $message - expected '$expected', got '[dict get $dict $key]'"
    }
}

puts "=== OIDC Provider Preset Tests ==="
puts ""

# Test 1: Google OIDC Provider Configuration
test "Google OIDC Provider Configuration" {
    set config [tossl::oidc::provider::google -client_id "test-client-id" -client_secret "test-client-secret"]
    
    # Check required fields
    assert_dict_contains $config "provider" "Provider field missing"
    assert_dict_equals $config "provider" "google" "Provider should be 'google'"
    assert_dict_contains $config "issuer" "Issuer field missing"
    assert_dict_equals $config "issuer" "https://accounts.google.com" "Issuer should be Google's issuer"
    assert_dict_contains $config "client_id" "Client ID field missing"
    assert_dict_equals $config "client_id" "test-client-id" "Client ID should match input"
    assert_dict_contains $config "client_secret" "Client secret field missing"
    assert_dict_equals $config "client_secret" "test-client-secret" "Client secret should match input"
    assert_dict_contains $config "default_scopes" "Default scopes field missing"
    assert_dict_equals $config "default_scopes" "openid profile email" "Default scopes should be correct"
    
    # Check that discovery was performed (should have endpoints)
    assert_dict_contains $config "authorization_endpoint" "Authorization endpoint missing from discovery"
    assert_dict_contains $config "token_endpoint" "Token endpoint missing from discovery"
    assert_dict_contains $config "userinfo_endpoint" "UserInfo endpoint missing from discovery"
    assert_dict_contains $config "jwks_uri" "JWKS URI missing from discovery"
    
    puts "    Google config: [dict get $config provider] provider with [dict get $config issuer] issuer"
}

# Test 2: Google OIDC Provider with Redirect URI
test "Google OIDC Provider with Redirect URI" {
    set config [tossl::oidc::provider::google -client_id "test-client-id" -client_secret "test-client-secret" -redirect_uri "https://example.com/callback"]
    
    assert_dict_contains $config "redirect_uri" "Redirect URI field missing"
    assert_dict_equals $config "redirect_uri" "https://example.com/callback" "Redirect URI should match input"
    
    puts "    Google config with redirect URI: [dict get $config redirect_uri]"
}

# Test 3: Microsoft OIDC Provider Configuration
test "Microsoft OIDC Provider Configuration" {
    set config [tossl::oidc::provider::microsoft -client_id "test-client-id" -client_secret "test-client-secret"]
    
    # Check required fields
    assert_dict_contains $config "provider" "Provider field missing"
    assert_dict_equals $config "provider" "microsoft" "Provider should be 'microsoft'"
    assert_dict_contains $config "issuer" "Issuer field missing"
    assert_dict_equals $config "issuer" "https://login.microsoftonline.com/common/v2.0" "Issuer should be Microsoft's issuer"
    assert_dict_contains $config "client_id" "Client ID field missing"
    assert_dict_equals $config "client_id" "test-client-id" "Client ID should match input"
    assert_dict_contains $config "client_secret" "Client secret field missing"
    assert_dict_equals $config "client_secret" "test-client-secret" "Client secret should match input"
    assert_dict_contains $config "default_scopes" "Default scopes field missing"
    assert_dict_equals $config "default_scopes" "openid profile email" "Default scopes should be correct"
    
    # Check that discovery was performed (should have endpoints)
    assert_dict_contains $config "authorization_endpoint" "Authorization endpoint missing from discovery"
    assert_dict_contains $config "token_endpoint" "Token endpoint missing from discovery"
    assert_dict_contains $config "userinfo_endpoint" "UserInfo endpoint missing from discovery"
    assert_dict_contains $config "jwks_uri" "JWKS URI missing from discovery"
    
    puts "    Microsoft config: [dict get $config provider] provider with [dict get $config issuer] issuer"
}

# Test 4: GitHub OIDC Provider Configuration
test "GitHub OIDC Provider Configuration" {
    set config [tossl::oidc::provider::github -client_id "test-client-id" -client_secret "test-client-secret"]
    
    # Check required fields
    assert_dict_contains $config "provider" "Provider field missing"
    assert_dict_equals $config "provider" "github" "Provider should be 'github'"
    assert_dict_contains $config "issuer" "Issuer field missing"
    assert_dict_equals $config "issuer" "https://token.actions.githubusercontent.com" "Issuer should be GitHub's issuer"
    assert_dict_contains $config "client_id" "Client ID field missing"
    assert_dict_equals $config "client_id" "test-client-id" "Client ID should match input"
    assert_dict_contains $config "client_secret" "Client secret field missing"
    assert_dict_equals $config "client_secret" "test-client-secret" "Client secret should match input"
    assert_dict_contains $config "default_scopes" "Default scopes field missing"
    assert_dict_equals $config "default_scopes" "openid profile email" "Default scopes should be correct"
    
    # GitHub uses hardcoded endpoints (doesn't support full OIDC discovery)
    assert_dict_contains $config "authorization_endpoint" "Authorization endpoint missing"
    assert_dict_equals $config "authorization_endpoint" "https://github.com/login/oauth/authorize" "GitHub authorization endpoint should be correct"
    assert_dict_contains $config "token_endpoint" "Token endpoint missing"
    assert_dict_equals $config "token_endpoint" "https://github.com/login/oauth/access_token" "GitHub token endpoint should be correct"
    assert_dict_contains $config "userinfo_endpoint" "UserInfo endpoint missing"
    assert_dict_equals $config "userinfo_endpoint" "https://api.github.com/user" "GitHub UserInfo endpoint should be correct"
    
    puts "    GitHub config: [dict get $config provider] provider with [dict get $config issuer] issuer"
}

# Test 5: Custom OIDC Provider Configuration
test "Custom OIDC Provider Configuration" {
    set config [tossl::oidc::provider::custom -issuer "https://custom.example.com" -client_id "test-client-id" -client_secret "test-client-secret"]
    
    # Check required fields
    assert_dict_contains $config "provider" "Provider field missing"
    assert_dict_equals $config "provider" "custom" "Provider should be 'custom'"
    assert_dict_contains $config "issuer" "Issuer field missing"
    assert_dict_equals $config "issuer" "https://custom.example.com" "Issuer should match input"
    assert_dict_contains $config "client_id" "Client ID field missing"
    assert_dict_equals $config "client_id" "test-client-id" "Client ID should match input"
    assert_dict_contains $config "client_secret" "Client secret field missing"
    assert_dict_equals $config "client_secret" "test-client-secret" "Client secret should match input"
    assert_dict_contains $config "default_scopes" "Default scopes field missing"
    assert_dict_equals $config "default_scopes" "openid profile email" "Default scopes should be correct"
    
    puts "    Custom config: [dict get $config provider] provider with [dict get $config issuer] issuer"
}

# Test 6: Custom OIDC Provider with Redirect URI
test "Custom OIDC Provider with Redirect URI" {
    set config [tossl::oidc::provider::custom -issuer "https://custom.example.com" -client_id "test-client-id" -client_secret "test-client-secret" -redirect_uri "https://example.com/callback"]
    
    assert_dict_contains $config "redirect_uri" "Redirect URI field missing"
    assert_dict_equals $config "redirect_uri" "https://example.com/callback" "Redirect URI should match input"
    
    puts "    Custom config with redirect URI: [dict get $config redirect_uri]"
}

# Test 7: Error Handling - Missing Required Parameters
test "Error Handling - Missing Client ID" {
    if {[catch {tossl::oidc::provider::google -client_secret "test-secret"} result]} {
        assert [string match "*wrong # args*" $result] "Should return error about wrong number of arguments"
        puts "    Correctly caught missing client_id error"
    } else {
        error "Should have failed with missing client_id"
    }
}

# Test 8: Error Handling - Missing Client Secret
test "Error Handling - Missing Client Secret" {
    if {[catch {tossl::oidc::provider::google -client_id "test-id"} result]} {
        assert [string match "*wrong # args*" $result] "Should return error about wrong number of arguments"
        puts "    Correctly caught missing client_secret error"
    } else {
        error "Should have failed with missing client_secret"
    }
}

# Test 9: Error Handling - Missing Issuer for Custom Provider
test "Error Handling - Missing Issuer for Custom Provider" {
    if {[catch {tossl::oidc::provider::custom -client_id "test-id" -client_secret "test-secret"} result]} {
        assert [string match "*wrong # args*" $result] "Should return error about wrong number of arguments"
        puts "    Correctly caught missing issuer error"
    } else {
        error "Should have failed with missing issuer"
    }
}

# Test 10: Provider Configuration Integration Test
test "Provider Configuration Integration Test" {
    # Test that we can use the provider config with other OIDC commands
    set config [tossl::oidc::provider::google -client_id "test-client-id" -client_secret "test-client-secret"]
    
    # Generate nonce using the provider config
    set nonce [tossl::oidc::generate_nonce]
    assert [string length $nonce] "Nonce should be generated"
    
    # Test that we can access provider endpoints
    set auth_endpoint [dict get $config authorization_endpoint]
    assert [string length $auth_endpoint] "Authorization endpoint should be available"
    assert [string match "*google*" $auth_endpoint] "Authorization endpoint should be Google's"
    
    puts "    Integration test: Generated nonce '$nonce' and got auth endpoint '$auth_endpoint'"
}

puts ""
puts "=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "Some tests failed!"
    exit 1
} else {
    puts "All tests passed!"
    exit 0
} 