#!/usr/bin/env tclsh
# Test suite for ::tossl::jwt::verify
# Tests JWT token verification functionality

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set errors 0

proc test {name script} {
    puts "Testing: $name"
    if {[catch $script result]} {
        puts "  ❌ FAIL: $result"
        incr ::errors
    } else {
        puts "  ✅ PASS"
    }
}

# Test 1: Basic JWT verification with HS256
test "Basic JWT verification with HS256" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss example.com exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Verify the JWT
    set verify_result [tossl::jwt::verify -token $jwt -key "test_secret" -alg HS256]
    
    if {![dict get $verify_result valid]} {
        error "JWT verification should pass with correct key"
    }
    
    # Verify with wrong key should fail
    set verify_result [tossl::jwt::verify -token $jwt -key "wrong_secret" -alg HS256]
    
    if {[dict get $verify_result valid]} {
        error "JWT verification should fail with wrong key"
    }
}

# Test 2: JWT verification with different HMAC algorithms
test "JWT verification with different HMAC algorithms" {
    set algorithms {HS256 HS384 HS512}
    
    foreach alg $algorithms {
        set header [dict create alg $alg typ JWT]
        set payload [dict create sub "user_$alg" iss "test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg $alg]
        
        # Verify with correct key
        set verify_result [tossl::jwt::verify -token $jwt -key "test_secret" -alg $alg]
        if {![dict get $verify_result valid]} {
            error "JWT verification failed for algorithm $alg"
        }
        
        # Verify with wrong key should fail
        set verify_result [tossl::jwt::verify -token $jwt -key "wrong_secret" -alg $alg]
        if {[dict get $verify_result valid]} {
            error "JWT verification should fail with wrong key for algorithm $alg"
        }
    }
}

# Test 3: JWT verification with RSA algorithms
test "JWT verification with RSA algorithms" {
    # Generate RSA key pair
    set key_data [tossl::key::generate -type rsa -bits 2048]
    set private_key [dict get $key_data private]
    set public_key [dict get $key_data public]
    
    set algorithms {RS256 RS384 RS512}
    
    foreach alg $algorithms {
        set header [dict create alg $alg typ JWT]
        set payload [dict create sub "user_$alg" iss "test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg $alg]
        
        # Verify with correct public key
        set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg $alg]
        if {![dict get $verify_result valid]} {
            error "RSA JWT verification failed for algorithm $alg"
        }
        
        # Verify with wrong key should fail
        set wrong_key_data [tossl::key::generate -type rsa -bits 2048]
        set wrong_public_key [dict get $wrong_key_data public]
        set verify_result [tossl::jwt::verify -token $jwt -key $wrong_public_key -alg $alg]
        if {[dict get $verify_result valid]} {
            error "RSA JWT verification should fail with wrong key for algorithm $alg"
        }
    }
}

# Test 4: JWT verification with EC algorithms
test "JWT verification with EC algorithms" {
    # Generate EC key pair
    set key_data [tossl::key::generate -type ec -curve prime256v1]
    set private_key [dict get $key_data private]
    set public_key [dict get $key_data public]
    
    set algorithms {ES256 ES384 ES512}
    
    foreach alg $algorithms {
        set header [dict create alg $alg typ JWT]
        set payload [dict create sub "user_$alg" iss "test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg $alg]
        
        # Verify with correct public key
        set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg $alg]
        if {![dict get $verify_result valid]} {
            error "EC JWT verification failed for algorithm $alg"
        }
        
        # Verify with wrong key should fail
        set wrong_key_data [tossl::key::generate -type ec -curve prime256v1]
        set wrong_public_key [dict get $wrong_key_data public]
        set verify_result [tossl::jwt::verify -token $jwt -key $wrong_public_key -alg $alg]
        if {[dict get $verify_result valid]} {
            error "EC JWT verification should fail with wrong key for algorithm $alg"
        }
    }
}

# Test 5: JWT verification with "none" algorithm
test "JWT verification with none algorithm" {
    set header [dict create alg none typ JWT]
    set payload [dict create sub user_none iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "" -alg none]
    
    # Verify with none algorithm
    set verify_result [tossl::jwt::verify -token $jwt -key "" -alg none]
    if {![dict get $verify_result valid]} {
        error "JWT with none algorithm verification failed"
    }
    
    # Verify that none algorithm with non-empty signature fails
    set tampered_jwt [string range $jwt 0 end-1]X
    set verify_result [tossl::jwt::verify -token $tampered_jwt -key "" -alg none]
    if {[dict get $verify_result valid]} {
        error "JWT with none algorithm should fail with non-empty signature"
    }
}

# Test 6: JWT verification with tampered payload
test "JWT verification with tampered payload" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Tamper with the payload by changing one character
    lassign [split $jwt "."] header_part payload_part signature_part
    set tampered_payload [string replace $payload_part 0 0 "X"]
    set tampered_jwt "$header_part.$tampered_payload.$signature_part"
    
    # Verify tampered JWT should fail
    set verify_result [tossl::jwt::verify -token $tampered_jwt -key "test_secret" -alg HS256]
    if {[dict get $verify_result valid]} {
        error "JWT verification should fail with tampered payload"
    }
}

# Test 7: JWT verification with tampered signature
test "JWT verification with tampered signature" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Tamper with the signature by changing one character
    lassign [split $jwt "."] header_part payload_part signature_part
    set tampered_signature [string replace $signature_part 0 0 "X"]
    set tampered_jwt "$header_part.$payload_part.$tampered_signature"
    
    # Verify tampered JWT should fail
    set verify_result [tossl::jwt::verify -token $tampered_jwt -key "test_secret" -alg HS256]
    if {[dict get $verify_result valid]} {
        error "JWT verification should fail with tampered signature"
    }
}

# Test 8: JWT verification with wrong algorithm
test "JWT verification with wrong algorithm" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Verify with wrong algorithm should fail
    set verify_result [tossl::jwt::verify -token $jwt -key "test_secret" -alg HS384]
    if {[dict get $verify_result valid]} {
        error "JWT verification should fail with wrong algorithm"
    }
}

# Test 9: Error handling - missing parameters
test "Error handling - missing parameters" {
    if {![catch {tossl::jwt::verify} result]} {
        error "Should have failed for missing parameters"
    }
    
    if {![catch {tossl::jwt::verify -token "test"} result]} {
        error "Should have failed for missing key and algorithm"
    }
    
    if {![catch {tossl::jwt::verify -token "test" -key "secret"} result]} {
        error "Should have failed for missing algorithm"
    }
    
    if {![catch {tossl::jwt::verify -token "test" -alg HS256} result]} {
        error "Should have failed for missing key"
    }
}

# Test 10: Error handling - invalid JWT format
test "Error handling - invalid JWT format" {
    if {![catch {tossl::jwt::verify -token "invalid.jwt" -key "secret" -alg HS256} result]} {
        error "Should have failed for invalid JWT format"
    }
    
    if {![catch {tossl::jwt::verify -token "header.payload" -key "secret" -alg HS256} result]} {
        error "Should have failed for JWT with missing signature"
    }
    
    if {![catch {tossl::jwt::verify -token "header" -key "secret" -alg HS256} result]} {
        error "Should have failed for JWT with missing parts"
    }
}

# Test 11: Error handling - invalid keys
test "Error handling - invalid keys" {
    set header [dict create alg RS256 typ JWT]
    set payload [dict create sub user123 iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Try to verify with invalid RSA key
    if {![catch {tossl::jwt::verify -token $jwt -key "invalid_key" -alg RS256} result]} {
        error "Should have failed for invalid RSA key"
    }
    
    # Try to verify with invalid EC key
    if {![catch {tossl::jwt::verify -token $jwt -key "invalid_key" -alg ES256} result]} {
        error "Should have failed for invalid EC key"
    }
}

# Test 12: JWT verification with complex payload
test "JWT verification with complex payload" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub "complex_user" \
        iss "complex-app.com" \
        aud "api.example.com" \
        exp [expr [clock seconds] + 7200] \
        iat [clock seconds] \
        nbf [clock seconds] \
        jti "unique-token-id" \
        custom_claim "custom_value" \
        nested [dict create \
            level1 "value1" \
            level2 [dict create level3 "value3"]] \
        array_claim [list "item1" "item2" "item3"]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "complex_secret" -alg HS256]
    
    # Verify the JWT
    set verify_result [tossl::jwt::verify -token $jwt -key "complex_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT verification failed for complex payload"
    }
    
    # Verify with wrong key should fail
    set verify_result [tossl::jwt::verify -token $jwt -key "wrong_secret" -alg HS256]
    if {[dict get $verify_result valid]} {
        error "JWT verification should fail with wrong key for complex payload"
    }
}

# Test 13: JWT verification with large payload
test "JWT verification with large payload" {
    set header [dict create alg HS256 typ JWT]
    
    # Create a moderately large payload
    set large_data ""
    for {set i 0} {$i < 50} {incr i} {
        append large_data "chunk$i "
    }
    
    set payload [dict create \
        large_field $large_data \
        count 50 \
        description "Large payload test"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "large_secret" -alg HS256]
    
    # Verify the JWT
    set verify_result [tossl::jwt::verify -token $jwt -key "large_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT verification failed for large payload"
    }
}

# Test 14: JWT verification with special characters
test "JWT verification with special characters" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        message "Hello, World! 你好世界" \
        symbols "!@#$%^&*()_+-=[]{}|;':\",./<>?" \
        unicode "🎉🚀💻"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "special_secret" -alg HS256]
    
    # Verify the JWT
    set verify_result [tossl::jwt::verify -token $jwt -key "special_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT verification failed for special characters"
    }
}

# Test 15: Performance test - multiple verifications
test "Performance test - multiple verifications" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "perf_user" iss "perf-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "perf_secret" -alg HS256]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set verify_result [tossl::jwt::verify -token $jwt -key "perf_secret" -alg HS256]
        if {![dict get $verify_result valid]} {
            error "Performance test failed on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr $end_time - $start_time]
    
    puts "  Performance: 100 verifications in ${duration}ms"
}

# Test 16: Integration test - create and verify
test "Integration test - create and verify" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub "integration_user" \
        iss "integration-test.com" \
        aud "api.example.com" \
        exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "integration_secret" -alg HS256]
    
    # Verify the JWT
    set verify_result [tossl::jwt::verify -token $jwt -key "integration_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT verification failed in integration test"
    }
    
    # Decode and verify content
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload sub] != "integration_user"} {
        error "Decoded payload doesn't match original"
    }
}

# Test 17: Memory usage test
test "Memory usage test" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "memory_user" iss "memory-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "memory_secret" -alg HS256]
    
    # Perform multiple verifications to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set verify_result [tossl::jwt::verify -token $jwt -key "memory_secret" -alg HS256]
        if {![dict get $verify_result valid]} {
            error "Memory test failed on iteration $i"
        }
        
        # Force garbage collection if available
        if {[info commands tcl::unsupported::representation] ne ""} {
            unset verify_result
        }
    }
    
    puts "  Memory test: 50 verifications completed without errors"
}

# Test 18: JWT verification with different key types
test "JWT verification with different key types" {
    # Test HMAC with different key lengths
    set keys {"short" "medium_length_key" "very_long_key_for_hmac_verification_testing"}
    
    foreach key $keys {
        set header [dict create alg HS256 typ JWT]
        set payload [dict create sub "key_test" iss "key-test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $key -alg HS256]
        
        # Verify with correct key
        set verify_result [tossl::jwt::verify -token $jwt -key $key -alg HS256]
        if {![dict get $verify_result valid]} {
            error "JWT verification failed for key length [string length $key]"
        }
    }
}

# Test 19: JWT verification with algorithm mismatch
test "JWT verification with algorithm mismatch" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Try to verify with different algorithms
    set algorithms {HS384 HS512 RS256 ES256}
    
    foreach alg $algorithms {
        set verify_result [tossl::jwt::verify -token $jwt -key "test_secret" -alg $alg]
        if {[dict get $verify_result valid]} {
            error "JWT verification should fail with algorithm mismatch for $alg"
        }
    }
}

# Test 20: JWT verification with empty token
test "JWT verification with empty token" {
    if {![catch {tossl::jwt::verify -token "" -key "secret" -alg HS256} result]} {
        error "Should have failed for empty token"
    }
    
    if {![catch {tossl::jwt::verify -token "   " -key "secret" -alg HS256} result]} {
        error "Should have failed for whitespace-only token"
    }
}

# Summary
puts "\n=== JWT Verify Test Summary ==="
puts "Total tests: 20"
puts "Passed: [expr 20 - $errors]"
puts "Failed: $errors"

if {$errors > 0} {
    exit 1
} else {
    puts "All tests passed! ✅"
} 
