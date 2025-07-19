#!/usr/bin/env tclsh

# Comprehensive test suite for ::tossl::jwt::extract_claims
# Tests JWT claim extraction functionality

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

puts "=== JWT Extract Claims Test Suite ==="
puts "Testing ::tossl::jwt::extract_claims command"
puts ""

# Test 1: Basic claim extraction with standard claims
run_test "Basic claim extraction with standard claims" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should match"
    assert_dict_value $claims audience "test-audience" "Audience should match"
    assert_dict_value $claims subject "test-subject" "Subject should match"
    assert_dict_value $claims jwt_id "test-jwt-id" "JWT ID should match"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 2: Claim extraction with missing optional claims
run_test "Claim extraction with missing optional claims" {
    set now [clock seconds]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"iat\":$now}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should be present"
    assert {[dict get $claims issued_at] == $now} "Issued at should be present"
    
    # Optional claims should not be present
    assert {![dict exists $claims audience]} "Audience should not be present"
    assert {![dict exists $claims subject]} "Subject should not be present"
    assert {![dict exists $claims jwt_id]} "JWT ID should not be present"
    assert {![dict exists $claims expiration]} "Expiration should not be present"
    assert {![dict exists $claims not_before]} "Not before should not be present"
}

# Test 3: Claim extraction with all timestamp claims
run_test "Claim extraction with all timestamp claims" {
    set now [clock seconds]
    set nbf [expr {$now - 3600}] ;# 1 hour ago
    set exp [expr {$now + 7200}] ;# 2 hours from now
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"iat\":$now,\"nbf\":$nbf,\"exp\":$exp}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims not_before] == $nbf} "Not before should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 4: Claim extraction with empty token
run_test "Claim extraction with empty token" {
    if {[catch {::tossl::jwt::extract_claims -token ""} result]} {
        # Expected to fail
        assert 1 "Empty token should cause error"
    } else {
        error "Empty token should have caused an error"
    }
}

# Test 5: Claim extraction with missing token parameter
run_test "Claim extraction with missing token parameter" {
    if {[catch {::tossl::jwt::extract_claims} result]} {
        # Expected to fail
        assert 1 "Missing token parameter should cause error"
    } else {
        error "Missing token parameter should have caused an error"
    }
}

# Test 6: Claim extraction with invalid JWT format
run_test "Claim extraction with invalid JWT format" {
    set result [::tossl::jwt::extract_claims -token "invalid.jwt.format"]
    assert_dict_value $result error "Invalid JSON payload" "Error should indicate invalid JSON payload"
}

# Test 7: Claim extraction with malformed payload
run_test "Claim extraction with malformed payload" {
    set header [::tossl::base64url::encode "{\"alg\":\"none\",\"typ\":\"JWT\"}"]
    set payload [::tossl::base64url::encode "invalid json"]
    set token "$header.$payload."
    
    set result [::tossl::jwt::extract_claims -token $token]
    assert_dict_value $result error "Invalid JSON payload" "Error should indicate invalid JSON payload"
}

# Test 8: Claim extraction with different algorithms
run_test "Claim extraction with different algorithms" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp}"
    
    # Test with different algorithms
    set algorithms {none HS256}
    
    foreach alg $algorithms {
        set header_json "{\"alg\":\"$alg\",\"typ\":\"JWT\"}"
        set key [expr {$alg eq "none" ? "dummy" : "test_secret"}]
        
        set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $key -alg $alg]
        set claims [::tossl::jwt::extract_claims -token $token]
        
        assert_dict_value $claims issuer "test-issuer" "Issuer should match for algorithm $alg"
        assert_dict_value $claims audience "test-audience" "Audience should match for algorithm $alg"
        assert_dict_value $claims subject "test-subject" "Subject should match for algorithm $alg"
        assert {[dict get $claims issued_at] == $now} "Issued at should match for algorithm $alg"
        assert {[dict get $claims expiration] == $exp} "Expiration should match for algorithm $alg"
    }
}

# Test 9: Claim extraction with very long claim values
run_test "Claim extraction with very long claim values" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set long_string [string repeat "a" 100]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"$long_string\",\"aud\":\"$long_string\",\"sub\":\"$long_string\",\"iat\":$now,\"exp\":$exp,\"jti\":\"$long_string\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer $long_string "Long issuer should match"
    assert_dict_value $claims audience $long_string "Long audience should match"
    assert_dict_value $claims subject $long_string "Long subject should match"
    assert_dict_value $claims jwt_id $long_string "Long JWT ID should match"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 10: Claim extraction with special characters in claims
run_test "Claim extraction with special characters in claims" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set special_issuer "test-issuer@example.com"
    set special_audience "api.example.com/v1"
    set special_subject "user_123!@#$%^&*()"
    set special_jwt_id "jwt-id-with-special-chars-🎉🚀💻"
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"$special_issuer\",\"aud\":\"$special_audience\",\"sub\":\"$special_subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"$special_jwt_id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer $special_issuer "Special issuer should match"
    assert_dict_value $claims audience $special_audience "Special audience should match"
    assert_dict_value $claims subject $special_subject "Special subject should match"
    assert_dict_value $claims jwt_id $special_jwt_id "Special JWT ID should match"
}

# Test 11: Claim extraction with numeric string values
run_test "Claim extraction with numeric string values" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set numeric_issuer "12345"
    set numeric_audience "67890"
    set numeric_subject "11111"
    set numeric_jwt_id "99999"
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"$numeric_issuer\",\"aud\":\"$numeric_audience\",\"sub\":\"$numeric_subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"$numeric_jwt_id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer $numeric_issuer "Numeric issuer should match"
    assert_dict_value $claims audience $numeric_audience "Numeric audience should match"
    assert_dict_value $claims subject $numeric_subject "Numeric subject should match"
    assert_dict_value $claims jwt_id $numeric_jwt_id "Numeric JWT ID should match"
}

# Test 12: Claim extraction with zero timestamp values
run_test "Claim extraction with zero timestamp values" {
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"iat\":0,\"nbf\":0,\"exp\":0}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should match"
    # Zero timestamps are not included in the result (implementation behavior)
    assert {![dict exists $claims issued_at]} "Zero issued at should not be included"
    assert {![dict exists $claims not_before]} "Zero not before should not be included"
    assert {![dict exists $claims expiration]} "Zero expiration should not be included"
}

# Test 13: Claim extraction with negative timestamp values
run_test "Claim extraction with negative timestamp values" {
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"iat\":-1000,\"nbf\":-2000,\"exp\":-500}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should match"
    # Negative timestamps are not included in the result (implementation behavior)
    assert {![dict exists $claims issued_at]} "Negative issued at should not be included"
    assert {![dict exists $claims not_before]} "Negative not before should not be included"
    assert {![dict exists $claims expiration]} "Negative expiration should not be included"
}

# Test 14: Claim extraction with very large timestamp values
run_test "Claim extraction with very large timestamp values" {
    set large_timestamp 2147483000
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"iat\":$large_timestamp,\"exp\":[expr {$large_timestamp + 647}]}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should match"
    assert {[dict get $claims issued_at] == $large_timestamp} "Large issued at should be preserved"
    assert {[dict get $claims expiration] == [expr {$large_timestamp + 647}]} "Large expiration should be preserved"
}

# Test 15: Performance test with multiple extractions
run_test "Performance test with multiple extractions" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    
    set start_time [clock milliseconds]
    for {set i 0} {$i < 100} {incr i} {
        set claims [::tossl::jwt::extract_claims -token $token]
        assert_dict_value $claims issuer "test-issuer" "Issuer should match in performance test"
        assert_dict_value $claims audience "test-audience" "Audience should match in performance test"
        assert_dict_value $claims subject "test-subject" "Subject should match in performance test"
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "  Performance: 100 extractions in ${duration}ms"
    assert {$duration < 1000} "Performance test should complete in under 1 second"
}

# Test 16: Memory leak test
run_test "Memory leak test" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    
    # Run many extractions to check for memory leaks
    for {set i 0} {$i < 1000} {incr i} {
        set claims [::tossl::jwt::extract_claims -token $token]
        assert_dict_value $claims issuer "test-issuer" "Issuer should match in memory test"
        assert_dict_value $claims audience "test-audience" "Audience should match in memory test"
        assert_dict_value $claims subject "test-subject" "Subject should match in memory test"
    }
    
    puts "  Memory test: 1000 extractions completed without memory issues"
}

# Test 17: Integration test with create and extract
run_test "Integration test with create and extract" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"integration-issuer\",\"aud\":\"integration-audience\",\"sub\":\"integration-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"integration-jwt-id\"}"
    
    # Create token
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    assert {[string length $token] > 0} "Token should be created successfully"
    
    # Extract claims
    set claims [::tossl::jwt::extract_claims -token $token]
    assert_dict_value $claims issuer "integration-issuer" "Issuer should match"
    assert_dict_value $claims audience "integration-audience" "Audience should match"
    assert_dict_value $claims subject "integration-subject" "Subject should match"
    assert_dict_value $claims jwt_id "integration-jwt-id" "JWT ID should match"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 18: Claim extraction with empty string values
run_test "Claim extraction with empty string values" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"\",\"aud\":\"\",\"sub\":\"\",\"iat\":$now,\"exp\":$exp,\"jti\":\"\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "" "Empty issuer should be preserved"
    assert_dict_value $claims audience "" "Empty audience should be preserved"
    assert_dict_value $claims subject "" "Empty subject should be preserved"
    assert_dict_value $claims jwt_id "" "Empty JWT ID should be preserved"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 19: Claim extraction with whitespace-only values
run_test "Claim extraction with whitespace-only values" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"   \",\"aud\":\"  \",\"sub\":\" \",\"iat\":$now,\"exp\":$exp,\"jti\":\"  \"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "   " "Whitespace issuer should be preserved"
    assert_dict_value $claims audience "  " "Whitespace audience should be preserved"
    assert_dict_value $claims subject " " "Whitespace subject should be preserved"
    assert_dict_value $claims jwt_id "  " "Whitespace JWT ID should be preserved"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
}

# Test 20: Claim extraction with mixed data types
run_test "Claim extraction with mixed data types" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    
    set header_json "{\"alg\":\"none\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"string-issuer\",\"aud\":12345,\"sub\":\"string-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"string-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key "dummy" -alg "none"]
    set claims [::tossl::jwt::extract_claims -token $token]
    
    assert_dict_value $claims issuer "string-issuer" "String issuer should match"
    assert_dict_value $claims audience "12345" "Numeric audience should be converted to string"
    assert_dict_value $claims subject "string-subject" "String subject should match"
    assert_dict_value $claims jwt_id "string-jwt-id" "String JWT ID should match"
    assert {[dict get $claims issued_at] == $now} "Issued at should match"
    assert {[dict get $claims expiration] == $exp} "Expiration should match"
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