#!/usr/bin/env tclsh

# Comprehensive test suite for secure ::tossl::jwt::extract_claims
# Tests JWT claim extraction with signature verification

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

puts "=== Secure JWT Extract Claims Test Suite ==="
puts "Testing ::tossl::jwt::extract_claims command with signature verification"
puts ""

# Test 1: Basic claim extraction with HMAC signature
run_test "Basic claim extraction with HMAC signature" {
    set now [clock seconds]
    set exp [expr {$now + 3600}]
    set secret_key "test-secret-key"
    
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"aud\":\"test-audience\",\"sub\":\"test-subject\",\"iat\":$now,\"exp\":$exp,\"jti\":\"test-jwt-id\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS256"]
    
    assert_dict_value $claims issuer "test-issuer" "Issuer should match"
    assert_dict_value $claims audience "test-audience" "Audience should match"
    assert_dict_value $claims subject "test-subject" "Subject should match"
    assert_dict_value $claims issued_at $now "Issued at should match"
    assert_dict_value $claims expiration $exp "Expiration should match"
    assert_dict_value $claims jwt_id "test-jwt-id" "JWT ID should match"
}

# Test 2: Signature verification failure with wrong key
run_test "Signature verification failure with wrong key" {
    set secret_key "correct-key"
    set wrong_key "wrong-key"
    
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test-issuer\",\"sub\":\"test-subject\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    
    # This should fail with wrong key
    set error_caught 0
    if {[catch {::tossl::jwt::extract_claims -token $token -key $wrong_key -alg "HS256"} result]} {
        set error_caught 1
        assert {[string match "*signature verification failed*" $result]} "Should fail with signature verification error"
    }
    assert {$error_caught == 1} "Should have caught signature verification error"
}

# Test 3: Missing required parameters
run_test "Missing required parameters" {
    set error_caught 0
    if {[catch {::tossl::jwt::extract_claims -token "dummy"} result]} {
        set error_caught 1
        assert {[string match "*wrong # args*" $result]} "Should fail with wrong number of arguments"
    }
    assert {$error_caught == 1} "Should have caught parameter error"
}

# Test 4: Invalid JWT format
run_test "Invalid JWT format" {
    set error_caught 0
    if {[catch {::tossl::jwt::extract_claims -token "invalid.jwt" -key "key" -alg "HS256"} result]} {
        set error_caught 1
        assert {[string match "*Invalid JWT format*" $result]} "Should fail with invalid JWT format"
    }
    assert {$error_caught == 1} "Should have caught format error"
}

# Test 5: Different HMAC algorithms
run_test "Different HMAC algorithms" {
    set secret_key "test-key"
    set payload_json "{\"iss\":\"test\",\"sub\":\"user\"}"
    
    foreach alg {HS256 HS384 HS512} {
        set header_json "{\"alg\":\"$alg\",\"typ\":\"JWT\"}"
        set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg $alg]
        set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg $alg]
        
        assert_dict_value $claims issuer "test" "Issuer should match for $alg"
        assert_dict_value $claims subject "user" "Subject should match for $alg"
    }
}

# Test 6: Algorithm mismatch
run_test "Algorithm mismatch" {
    set secret_key "test-key"
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test\",\"sub\":\"user\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    
    # Try to verify with wrong algorithm
    set error_caught 0
    if {[catch {::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS512"} result]} {
        set error_caught 1
        assert {[string match "*signature verification failed*" $result]} "Should fail with algorithm mismatch"
    }
    assert {$error_caught == 1} "Should have caught algorithm mismatch error"
}

# Test 7: Claims with minimal data
run_test "Claims with minimal data" {
    set secret_key "test-key"
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"sub\":\"user123\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS256"]
    
    assert_dict_value $claims subject "user123" "Subject should match"
    assert {![dict exists $claims issuer]} "Issuer should not exist"
    assert {![dict exists $claims audience]} "Audience should not exist"
}

# Test 8: Claims with special characters
run_test "Claims with special characters" {
    set secret_key "test-key"
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test@example.com\",\"sub\":\"user with spaces\",\"aud\":\"https://api.example.com/v1\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS256"]
    
    assert_dict_value $claims issuer "test@example.com" "Issuer with @ should match"
    assert_dict_value $claims subject "user with spaces" "Subject with spaces should match"
    assert_dict_value $claims audience "https://api.example.com/v1" "Audience URL should match"
}

# Test 9: Performance test
run_test "Performance test with multiple extractions" {
    set secret_key "test-key"
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test\",\"sub\":\"user\"}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    
    set start_time [clock milliseconds]
    for {set i 0} {$i < 100} {incr i} {
        set claims [::tossl::jwt::extract_claims -token $token -key $secret_key -alg "HS256"]
        assert_dict_value $claims issuer "test" "Performance test iteration $i"
    }
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "  Performance: 100 extractions in ${duration}ms"
}

# Test 10: Security test - tampered token
run_test "Security test with tampered token" {
    set secret_key "test-key"
    set header_json "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    set payload_json "{\"iss\":\"test\",\"sub\":\"user\",\"admin\":false}"
    
    set token [::tossl::jwt::create -header $header_json -payload $payload_json -key $secret_key -alg "HS256"]
    
    # Tamper with the payload (change admin:false to admin:true)
    set parts [split $token "."]
    set header_part [lindex $parts 0]
    set payload_part [lindex $parts 1]
    set signature_part [lindex $parts 2]
    
    # Create malicious payload
    set malicious_payload_json "{\"iss\":\"test\",\"sub\":\"user\",\"admin\":true}"
    set malicious_payload_b64 [string map {+ - / _ = {}} [binary encode base64 $malicious_payload_json]]
    set tampered_token "$header_part.$malicious_payload_b64.$signature_part"
    
    # This should fail because signature won't match tampered payload
    set error_caught 0
    if {[catch {::tossl::jwt::extract_claims -token $tampered_token -key $secret_key -alg "HS256"} result]} {
        set error_caught 1
        assert {[string match "*signature verification failed*" $result]} "Should reject tampered token"
    }
    assert {$error_caught == 1} "Should have caught tampering attempt"
}

puts ""
puts "=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed"
puts "Failed: $failed"

if {$failed == 0} {
    puts "All tests passed! 🎉"
    puts ""
    puts "Security verification successful:"
    puts "✅ Signature verification is required"
    puts "✅ Invalid signatures are rejected"
    puts "✅ Tampered tokens are detected"
    puts "✅ Claims are only extracted from verified tokens"
} else {
    puts "Some tests failed! ❌"
    exit 1
}
