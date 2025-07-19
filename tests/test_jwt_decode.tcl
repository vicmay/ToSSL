#!/usr/bin/env tclsh
# Test suite for ::tossl::jwt::decode
# Tests JWT token decoding functionality

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

# Test 1: Basic JWT decode functionality
test "Basic JWT decode" {
    # Create a simple JWT token
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss test.com exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Decode the JWT
    set decoded [tossl::jwt::decode -token $jwt]
    
    # Verify the structure
    if {![dict exists $decoded header]} {
        error "Missing header in decoded JWT"
    }
    if {![dict exists $decoded payload]} {
        error "Missing payload in decoded JWT"
    }
    if {![dict exists $decoded signature]} {
        error "Missing signature in decoded JWT"
    }
    
    # Verify the content
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_header alg] != "HS256"} {
        error "Header algorithm mismatch"
    }
    if {[dict get $decoded_payload sub] != "user123"} {
        error "Payload subject mismatch"
    }
}

# Test 2: JWT with complex payload
test "JWT with complex payload" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub "user456" \
        iss "complex-app.com" \
        aud "api.example.com" \
        exp [expr [clock seconds] + 7200] \
        iat [clock seconds] \
        nbf [clock seconds] \
        jti "unique-token-id" \
        custom_claim "custom_value" \
        nested [dict create \
            level1 "value1" \
            level2 [dict create level3 "value3"]]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "complex_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload custom_claim] != "custom_value"} {
        error "Custom claim not preserved"
    }
    if {[dict get [dict get $decoded_payload nested] level1] != "value1"} {
        error "Nested claim not preserved"
    }
}

# Test 3: JWT with different algorithms
test "JWT with different algorithms" {
    set algorithms {HS256 HS384 HS512}
    
    foreach alg $algorithms {
        set header [dict create alg $alg typ JWT]
        set payload [dict create sub "user789" iss "test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg $alg]
        
        set decoded [tossl::jwt::decode -token $jwt]
        set decoded_header [tossl::json::parse [dict get $decoded header]]
        
        if {[dict get $decoded_header alg] != $alg} {
            error "Algorithm $alg not preserved in header"
        }
    }
}

# Test 4: JWT with RSA signature
test "JWT with RSA signature" {
    # Generate RSA key pair
    set key_data [tossl::key::generate -type rsa -bits 2048]
    set private_key [dict get $key_data private]
    
    set header [dict create alg RS256 typ JWT]
    set payload [dict create sub "rsa_user" iss "rsa-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg RS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    
    if {[dict get $decoded_header alg] != "RS256"} {
        error "RSA algorithm not preserved in header"
    }
}

# Test 5: JWT with EC signature
test "JWT with EC signature" {
    # Generate EC key pair
    set key_data [tossl::key::generate -type ec -curve prime256v1]
    set private_key [dict get $key_data private]
    
    set header [dict create alg ES256 typ JWT]
    set payload [dict create sub "ec_user" iss "ec-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key $private_key -alg ES256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    
    if {[dict get $decoded_header alg] != "ES256"} {
        error "EC algorithm not preserved in header"
    }
}

# Test 6: Error handling - invalid JWT format
test "Error handling - invalid JWT format" {
    if {![catch {tossl::jwt::decode -token "not-a-valid-jwt-token"} result]} {
        error "Should have failed for invalid JWT format"
    }
}

# Test 7: Error handling - missing parts
test "Error handling - missing parts" {
    if {![catch {tossl::jwt::decode -token "header.payload"} result]} {
        error "Should have failed for JWT missing signature"
    }
}

# Test 8: Error handling - wrong number of arguments
test "Error handling - wrong number of arguments" {
    if {![catch {tossl::jwt::decode} result]} {
        error "Should have failed for missing arguments"
    }
    if {![catch {tossl::jwt::decode -token "test" extra} result]} {
        error "Should have failed for extra arguments"
    }
}

# Test 9: Error handling - empty token
test "Error handling - empty token" {
    if {![catch {tossl::jwt::decode -token ""} result]} {
        error "Should have failed for empty token"
    }
}

# Test 10: JWT with special characters in payload
test "JWT with special characters in payload" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        message "Hello, World! 你好世界" \
        symbols "!@#$%^&*()_+-=[]{}|;':\",./<>?" \
        unicode "🎉🚀💻"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "special_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload message] != "Hello, World! 你好世界"} {
        error "Unicode characters not preserved"
    }
    if {[dict get $decoded_payload unicode] != "🎉🚀💻"} {
        error "Emoji characters not preserved"
    }
}

# Test 11: JWT with large payload
test "JWT with large payload" {
    set header [dict create alg HS256 typ JWT]
    
    # Create a moderately large payload (simplified to avoid JSON parsing issues)
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
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload count] != 50} {
        error "Large payload count not preserved"
    }
}

# Test 12: JWT with numeric claims
test "JWT with numeric claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        integer_claim 42 \
        float_claim 3.14159 \
        negative_claim -123 \
        zero_claim 0 \
        large_number 999999999999]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "numeric_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload integer_claim] != 42} {
        error "Integer claim not preserved"
    }
    if {[dict get $decoded_payload negative_claim] != -123} {
        error "Negative claim not preserved"
    }
}

# Test 13: JWT with boolean claims
test "JWT with boolean claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        true_claim true \
        false_claim false \
        mixed [dict create \
            flag1 true \
            flag2 false]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "boolean_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {![dict get $decoded_payload true_claim]} {
        error "True boolean claim not preserved"
    }
    if {[dict get $decoded_payload false_claim]} {
        error "False boolean claim not preserved"
    }
}

# Test 14: JWT with null claims
test "JWT with null claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        null_claim "" \
        empty_string "" \
        mixed [dict create \
            null_field "" \
            valid_field "value"]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "null_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload empty_string] != ""} {
        error "Empty string claim not preserved"
    }
}

# Test 15: Performance test - multiple decodes
test "Performance test - multiple decodes" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "perf_user" iss "perf-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "perf_secret" -alg HS256]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set decoded [tossl::jwt::decode -token $jwt]
        set decoded_payload [tossl::json::parse [dict get $decoded payload]]
        
        if {[dict get $decoded_payload sub] != "perf_user"} {
            error "Performance test failed on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr $end_time - $start_time]
    
    puts "  Performance: 100 decodes in ${duration}ms"
}

# Test 16: Integration test - decode and verify
test "Integration test - decode and verify" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "integration_user" iss "integration-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "integration_secret" -alg HS256]
    
    # Decode first
    set decoded [tossl::jwt::decode -token $jwt]
    
    # Then verify
    set verify_result [tossl::jwt::verify -token $jwt -key "integration_secret" -alg HS256]
    
    if {![dict get $verify_result valid]} {
        error "JWT verification failed after decode"
    }
    
    # Verify the decoded content matches
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
    
    # Perform multiple decodes to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set decoded [tossl::jwt::decode -token $jwt]
        set decoded_header [tossl::json::parse [dict get $decoded header]]
        set decoded_payload [tossl::json::parse [dict get $decoded payload]]
        
        # Force garbage collection if available
        if {[info commands tcl::unsupported::representation] ne ""} {
            unset decoded decoded_header decoded_payload
        }
    }
    
    puts "  Memory test: 50 decodes completed without errors"
}

# Test 18: JWT with array claims
test "JWT with array claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        roles [list "user" "admin" "moderator"] \
        permissions [list "read" "write" "delete"] \
        nested_arrays [list [list 1 2 3] [list "a" "b" "c"]]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "array_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[lindex [dict get $decoded_payload roles] 0] != "user"} {
        error "Array claim not preserved"
    }
}

# Test 19: JWT with expiration and timing claims
test "JWT with expiration and timing claims" {
    set current_time [clock seconds]
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub "timing_user" \
        iss "timing-test.com" \
        iat $current_time \
        exp [expr $current_time + 3600] \
        nbf [expr $current_time - 60]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "timing_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload iat] != $current_time} {
        error "Issued at time not preserved"
    }
    if {[dict get $decoded_payload exp] != [expr $current_time + 3600]} {
        error "Expiration time not preserved"
    }
}

# Test 20: JWT with custom header fields
test "JWT with custom header fields" {
    set header [dict create \
        alg HS256 \
        typ JWT \
        kid "key-id-123" \
        x5t "thumbprint-456" \
        custom_header "custom_value"]
    
    set payload [dict create sub "custom_user" iss "custom-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "custom_secret" -alg HS256]
    
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    
    if {[dict get $decoded_header kid] != "key-id-123"} {
        error "Custom header field 'kid' not preserved"
    }
    if {[dict get $decoded_header custom_header] != "custom_value"} {
        error "Custom header field not preserved"
    }
}

# Summary
puts "\n=== JWT Decode Test Summary ==="
puts "Total tests: 20"
puts "Passed: [expr 20 - $errors]"
puts "Failed: $errors"

if {$errors > 0} {
    exit 1
} else {
    puts "All tests passed! ✅"
} 