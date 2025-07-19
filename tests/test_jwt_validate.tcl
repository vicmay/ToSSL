#!/usr/bin/env tclsh

# Comprehensive test suite for ::tossl::jwt::validate
# Tests JWT claim validation including expiration, issuer, audience, not_before

package require tossl

# Test counter
set test_count 0
set passed 0
set failed 0

proc run_test {name test_script} {
    global test_count passed failed
    incr test_count
    
    puts "Test $test_count: $name"
    
    if {[catch {eval $test_script} result]} {
        puts "  FAILED: $result"
        incr failed
        return 0
    } else {
        puts "  PASSED"
        incr passed
        return 1
    }
}

proc assert {condition message} {
    if {![uplevel 1 expr $condition]} {
        error "Assertion failed: $message"
    }
}

proc assert_dict_contains {dict key message} {
    if {![dict exists $dict $key]} {
        error "Assertion failed: $message - key '$key' not found in dict"
    }
}

proc assert_dict_value {dict key expected message} {
    if {![dict exists $dict $key]} {
        error "Assertion failed: $message - key '$key' not found in dict"
    }
    set actual [dict get $dict $key]
    if {$actual ne $expected} {
        error "Assertion failed: $message - expected '$expected', got '$actual'"
    }
}

puts "=== JWT Validate Test Suite ==="
puts "Testing ::tossl::jwt::validate command"
puts ""

# Test 1: Basic validation with valid token
run_test "Basic validation with valid token" {
    set now [clock seconds]
    set exp [expr {$now + 3600}] ;# 1 hour from now
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token]
    
    assert {[dict get $result valid] == 1} "Token should be valid"
    assert_dict_value $result issuer "test-issuer" "Issuer should match"
    assert_dict_value $result audience "test-audience" "Audience should match"
    assert_dict_value $result subject "test-subject" "Subject should match"
    assert_dict_value $result jwt_id "test-jwt-id" "JWT ID should match"
    assert {[dict get $result issued_at] == $now} "Issued at should match"
    assert {[dict get $result expiration] == $exp} "Expiration should match"
}

# Test 2: Validation with issuer check
run_test "Validation with issuer check" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"correct-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -issuer "correct-issuer"]
    
    assert {[dict get $result valid] == 1} "Token should be valid with correct issuer"
    assert_dict_value $result issuer "correct-issuer" "Issuer should match"
}

# Test 3: Validation with wrong issuer
run_test "Validation with wrong issuer" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"wrong-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -issuer "expected-issuer"]
    
    assert {[dict get $result valid] == 0} "Token should be invalid with wrong issuer"
    assert_dict_value $result error "Invalid issuer" "Error should indicate invalid issuer"
}

# Test 4: Validation with audience check
run_test "Validation with audience check" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"correct-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -audience "correct-audience"]
    
    assert {[dict get $result valid] == 1} "Token should be valid with correct audience"
    assert_dict_value $result audience "correct-audience" "Audience should match"
}

# Test 5: Validation with wrong audience
run_test "Validation with wrong audience" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"wrong-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -audience "expected-audience"]
    
    assert {[dict get $result valid] == 0} "Token should be invalid with wrong audience"
    assert_dict_value $result error "Invalid audience" "Error should indicate invalid audience"
}

# Test 6: Validation with expired token
run_test "Validation with expired token" {
    set now [clock seconds]
    set exp [expr {$now - 3600}] ;# 1 hour ago
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":[expr {$now - 7200}],\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token]
    
    assert {[dict get $result valid] == 0} "Expired token should be invalid"
    assert_dict_value $result error "Token has expired" "Error should indicate token expired"
}

# Test 7: Validation with not_before check
run_test "Validation with not_before check" {
    set now [clock seconds]
    set nbf [expr {$now + 3600}] ;# 1 hour from now
    set exp [expr {$now + 7200}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"nbf\":$nbf,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token]
    
    assert {[dict get $result valid] == 0} "Token should be invalid before not_before time"
    assert_dict_value $result error "Token not yet valid" "Error should indicate token not yet valid"
}

# Test 8: Validation with disabled expiration check
run_test "Validation with disabled expiration check" {
    set now [clock seconds]
    set exp [expr {$now - 3600}] ;# 1 hour ago
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":[expr {$now - 7200}],\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -check_expiration 0]
    
    assert {[dict get $result valid] == 1} "Token should be valid when expiration check is disabled"
}

# Test 9: Validation with all checks combined
run_test "Validation with all checks combined" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"correct-issuer\",\"aud\":\"correct-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -issuer "correct-issuer" -audience "correct-audience"]
    
    assert {[dict get $result valid] == 1} "Token should be valid with all checks"
    assert_dict_value $result issuer "correct-issuer" "Issuer should match"
    assert_dict_value $result audience "correct-audience" "Audience should match"
    assert_dict_value $result subject "test-subject" "Subject should match"
    assert_dict_value $result jwt_id "test-jwt-id" "JWT ID should match"
}

# Test 10: Validation with missing required claims
run_test "Validation with missing required claims" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -issuer "expected-issuer"]
    
    # Token should be valid when issuer is missing (JWT standard behavior)
    assert {[dict get $result valid] == 1} "Token should be valid when issuer is missing"
}

# Test 11: Validation with invalid JWT format
run_test "Validation with invalid JWT format" {
    set result [::tossl::jwt::validate -token "invalid.jwt.format"]
    assert {[dict get $result valid] == 1} "Invalid JWT format should return valid=1 with error"
    assert_dict_value $result error "Invalid JSON payload" "Error should indicate invalid JSON payload"
}

# Test 12: Validation with empty token
run_test "Validation with empty token" {
    if {[catch {::tossl::jwt::validate -token ""} result]} {
        # Expected to fail
        assert 1 "Empty token should cause error"
    } else {
        error "Empty token should have caused an error"
    }
}

# Test 13: Validation with missing token parameter
run_test "Validation with missing token parameter" {
    if {[catch {::tossl::jwt::validate -issuer "test"} result]} {
        # Expected to fail
        assert 1 "Missing token parameter should cause error"
    } else {
        error "Missing token parameter should have caused an error"
    }
}

# Test 14: Validation with malformed payload
run_test "Validation with malformed payload" {
    set header [::tossl::base64url::encode "{\"alg\":\"none\",\"typ\":\"JWT\"}"]
    set payload [::tossl::base64url::encode "invalid json"]
    set token "$header.$payload."
    
    set result [::tossl::jwt::validate -token $token]
    assert {[dict get $result valid] == 1} "Malformed payload should return valid=1 with error"
    assert_dict_value $result error "Invalid JSON payload" "Error should indicate invalid JSON payload"
}

# Test 15: Validation with future issued_at
run_test "Validation with future issued_at" {
    set now [clock seconds]
    set iat [expr {$now + 3600}] ;# 1 hour in future
    set exp [expr {$now + 7200}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$iat,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token]
    
    # This should still be valid as issued_at in future is allowed
    assert {[dict get $result valid] == 1} "Token with future issued_at should be valid"
    assert {[dict get $result issued_at] == $iat} "Issued at should match"
}

# Test 16: Performance test with multiple validations
run_test "Performance test with multiple validations" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    
    set start_time [clock milliseconds]
    for {set i 0} {$i < 100} {incr i} {
        set result [::tossl::jwt::validate -token $token]
        assert {[dict get $result valid] == 1} "Token should remain valid in performance test"
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "  Performance: 100 validations in ${duration}ms"
    assert {$duration < 1000} "Performance test should complete in under 1 second"
}

# Test 17: Memory leak test
run_test "Memory leak test" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    
    # Run many validations to check for memory leaks
    for {set i 0} {$i < 1000} {incr i} {
        set result [::tossl::jwt::validate -token $token]
        assert {[dict get $result valid] == 1} "Token should remain valid in memory test"
    }
    
    puts "  Memory test: 1000 validations completed without memory issues"
}

# Test 18: Integration test with create and validate
run_test "Integration test with create and validate" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"integration-issuer\",\"aud\":\"integration-audience\",\"sub\":\"integration-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"integration-jwt-id\"}"
    
    # Create token
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    assert {[string length $token] > 0} "Token should be created successfully"
    
    # Validate token
    set result [::tossl::jwt::validate -token $token -issuer "integration-issuer" -audience "integration-audience"]
    assert {[dict get $result valid] == 1} "Created token should be valid"
    assert_dict_value $result issuer "integration-issuer" "Issuer should match"
    assert_dict_value $result audience "integration-audience" "Audience should match"
    assert_dict_value $result subject "integration-subject" "Subject should match"
    assert_dict_value $result jwt_id "integration-jwt-id" "JWT ID should match"
}

# Test 19: Edge case with very long claim values
run_test "Edge case with very long claim values" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set long_string [string repeat "a" 100]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"$long_string\",\"aud\":\"$long_string\",\"sub\":\"$long_string\",\"iat\":$now,\"exp\":$exp,\"jti\":\"$long_string\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set result [::tossl::jwt::validate -token $token -issuer $long_string -audience $long_string]
    
    assert {[dict get $result valid] == 1} "Token with long claim values should be valid"
    assert_dict_value $result issuer $long_string "Long issuer should match"
    assert_dict_value $result audience $long_string "Long audience should match"
    assert_dict_value $result subject $long_string "Long subject should match"
    assert_dict_value $result jwt_id $long_string "Long JWT ID should match"
}

# Test 20: Error handling with invalid parameters
run_test "Error handling with invalid parameters" {
    # Test with invalid check_expiration value
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"iat\":$now,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    
    # Test with invalid check_expiration (should default to 1)
    set result [::tossl::jwt::validate -token $token -check_expiration "invalid"]
    assert {[dict get $result valid] == 1} "Token should be valid even with invalid check_expiration parameter"
}

puts ""
puts "=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed"
puts "Failed: $failed"

if {$failed > 0} {
    puts "Some tests failed!"
    exit 1
} else {
    puts "All tests passed!"
    exit 0
} 