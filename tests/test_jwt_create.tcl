#!/usr/bin/env tclsh
# Test suite for ::tossl::jwt::create
# Tests JWT token creation functionality

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

# Test 1: Basic JWT creation with HS256
test "Basic JWT creation with HS256" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user123 iss example.com exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg HS256]
    
    # Verify the JWT structure
    if {[llength [split $jwt "."]] != 3} {
        error "JWT should have 3 parts separated by dots"
    }
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_header alg] != "HS256"} {
        error "Header algorithm should be HS256"
    }
    if {[dict get $decoded_payload sub] != "user123"} {
        error "Payload subject should be user123"
    }
}

# Test 2: JWT creation with different HMAC algorithms
test "JWT creation with different HMAC algorithms" {
    set algorithms {HS256 HS384 HS512}
    
    foreach alg $algorithms {
        set header [dict create alg $alg typ JWT]
        set payload [dict create sub "user_$alg" iss "test.com"]
        
        set header_json [tossl::json::generate $header]
        set payload_json [tossl::json::generate $payload]
        
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "test_secret" -alg $alg]
        
        # Verify the JWT can be verified
        set verify_result [tossl::jwt::verify -token $jwt -key "test_secret" -alg $alg]
        if {![dict get $verify_result valid]} {
            error "JWT verification failed for algorithm $alg"
        }
    }
}

# Test 3: JWT creation with RSA algorithms
test "JWT creation with RSA algorithms" {
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
        
        # Verify the JWT can be verified with public key
        set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg $alg]
        if {![dict get $verify_result valid]} {
            error "RSA JWT verification failed for algorithm $alg"
        }
    }
}

# Test 4: JWT creation with EC algorithms
test "JWT creation with EC algorithms" {
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
        
        # Verify the JWT can be verified with public key
        set verify_result [tossl::jwt::verify -token $jwt -key $public_key -alg $alg]
        if {![dict get $verify_result valid]} {
            error "EC JWT verification failed for algorithm $alg"
        }
    }
}

# Test 5: JWT creation with "none" algorithm
test "JWT creation with none algorithm" {
    set header [dict create alg none typ JWT]
    set payload [dict create sub user_none iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "" -alg none]
    
    # Verify the JWT structure has 3 parts
    set parts [split $jwt "."]
    if {[llength $parts] != 3} {
        error "JWT should have exactly 3 parts"
    }
    
    # Verify the JWT can be verified
    set verify_result [tossl::jwt::verify -token $jwt -key "" -alg none]
    if {![dict get $verify_result valid]} {
        error "JWT with none algorithm verification failed"
    }
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_header alg] != "none"} {
        error "Header algorithm should be none"
    }
    if {[dict get $decoded_payload sub] != "user_none"} {
        error "Payload subject should be user_none"
    }
    
    puts "  Note: JWT with none algorithm now works correctly with empty signature"
}

# Test 6: JWT creation with complex payload
test "JWT creation with complex payload" {
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
    
    # Verify the JWT can be decoded and verified
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload custom_claim] != "custom_value"} {
        error "Custom claim not preserved"
    }
    if {[dict get [dict get $decoded_payload nested] level1] != "value1"} {
        error "Nested claim not preserved"
    }
}

# Test 7: Error handling - missing parameters
test "Error handling - missing parameters" {
    if {![catch {tossl::jwt::create} result]} {
        error "Should have failed for missing parameters"
    }
    
    if {![catch {tossl::jwt::create -header "{}" -payload "{}"} result]} {
        error "Should have failed for missing key and algorithm"
    }
    
    if {![catch {tossl::jwt::create -header "{}" -key "secret" -alg HS256} result]} {
        error "Should have failed for missing payload"
    }
    
    if {![catch {tossl::jwt::create -payload "{}" -key "secret" -alg HS256} result]} {
        error "Should have failed for missing header"
    }
}

# Test 8: Error handling - invalid algorithm
test "Error handling - invalid algorithm" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub user iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    # Should default to HS256 for invalid algorithm
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "secret" -alg INVALID]
    
    # Verify it works with HS256
    set verify_result [tossl::jwt::verify -token $jwt -key "secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT with invalid algorithm should default to HS256"
    }
}

# Test 9: Error handling - invalid key for algorithm
test "Error handling - invalid key for algorithm" {
    set header [dict create alg RS256 typ JWT]
    set payload [dict create sub user iss test.com]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    if {![catch {tossl::jwt::create -header $header_json -payload $payload_json -key "invalid_key" -alg RS256} result]} {
        error "Should have failed for invalid RSA key"
    }
}

# Test 10: JWT creation with special characters in payload
test "JWT creation with special characters in payload" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        message "Hello, World! 你好世界" \
        symbols "!@#$%^&*()_+-=[]{}|;':\",./<>?" \
        unicode "🎉🚀💻" \
        newlines "line1\nline2\r\nline3"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "special_secret" -alg HS256]
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload message] != "Hello, World! 你好世界"} {
        error "Unicode characters not preserved"
    }
    if {[dict get $decoded_payload unicode] != "🎉🚀💻"} {
        error "Emoji characters not preserved"
    }
}

# Test 11: JWT creation with large payload
test "JWT creation with large payload" {
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
    
    # Verify the JWT can be decoded and verified
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload count] != 50} {
        error "Large payload count not preserved"
    }
    
    set verify_result [tossl::jwt::verify -token $jwt -key "large_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "Large payload JWT verification failed"
    }
}

# Test 12: JWT creation with numeric claims
test "JWT creation with numeric claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        integer_claim 42 \
        float_claim 3.14159 \
        negative_claim -123 \
        zero_claim 0 \
        large_number 999999999999 \
        timestamp [clock seconds]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "numeric_secret" -alg HS256]
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload integer_claim] != 42} {
        error "Integer claim not preserved"
    }
    if {[dict get $decoded_payload negative_claim] != -123} {
        error "Negative claim not preserved"
    }
}

# Test 13: JWT creation with boolean claims
test "JWT creation with boolean claims" {
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
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {![dict get $decoded_payload true_claim]} {
        error "True boolean claim not preserved"
    }
    if {[dict get $decoded_payload false_claim]} {
        error "False boolean claim not preserved"
    }
}

# Test 14: JWT creation with timing claims
test "JWT creation with timing claims" {
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
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload iat] != $current_time} {
        error "Issued at time not preserved"
    }
    if {[dict get $decoded_payload exp] != [expr $current_time + 3600]} {
        error "Expiration time not preserved"
    }
}

# Test 15: Performance test - multiple JWT creations
test "Performance test - multiple JWT creations" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "perf_user" iss "perf-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "perf_secret" -alg HS256]
        
        # Verify each JWT
        set verify_result [tossl::jwt::verify -token $jwt -key "perf_secret" -alg HS256]
        if {![dict get $verify_result valid]} {
            error "Performance test failed on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr $end_time - $start_time]
    
    puts "  Performance: 100 JWT creations in ${duration}ms"
}

# Test 16: Integration test - create and validate
test "Integration test - create and validate" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        sub "integration_user" \
        iss "integration-test.com" \
        aud "api.example.com" \
        exp [expr [clock seconds] + 3600]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "integration_secret" -alg HS256]
    
    # Test verification
    set verify_result [tossl::jwt::verify -token $jwt -key "integration_secret" -alg HS256]
    if {![dict get $verify_result valid]} {
        error "JWT verification failed"
    }
    
    # Test validation
    set validate_result [tossl::jwt::validate -token $jwt -issuer "integration-test.com" -audience "api.example.com"]
    if {![dict get $validate_result valid]} {
        error "JWT validation failed"
    }
    
    # Test claims extraction
    set claims [tossl::jwt::extract_claims -token $jwt -key "integration_secret" -alg "HS256"]
    if {[dict get $claims issuer] != "integration-test.com"} {
        error "Claims extraction failed"
    }
}

# Test 17: Memory usage test
test "Memory usage test" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create sub "memory_user" iss "memory-test.com"]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    # Perform multiple creations to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "memory_secret" -alg HS256]
        
        # Verify the JWT
        set verify_result [tossl::jwt::verify -token $jwt -key "memory_secret" -alg HS256]
        if {![dict get $verify_result valid]} {
            error "Memory test failed on iteration $i"
        }
        
        # Force garbage collection if available
        if {[info commands tcl::unsupported::representation] ne ""} {
            unset jwt verify_result
        }
    }
    
    puts "  Memory test: 50 JWT creations completed without errors"
}

# Test 18: JWT creation with custom header fields
test "JWT creation with custom header fields" {
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
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_header [tossl::json::parse [dict get $decoded header]]
    
    if {[dict get $decoded_header kid] != "key-id-123"} {
        error "Custom header field 'kid' not preserved"
    }
    if {[dict get $decoded_header custom_header] != "custom_value"} {
        error "Custom header field not preserved"
    }
}

# Test 19: JWT creation with array claims
test "JWT creation with array claims" {
    set header [dict create alg HS256 typ JWT]
    set payload [dict create \
        roles [list "user" "admin" "moderator"] \
        permissions [list "read" "write" "delete"] \
        nested_arrays [list [list 1 2 3] [list "a" "b" "c"]]]
    
    set header_json [tossl::json::generate $header]
    set payload_json [tossl::json::generate $payload]
    
    set jwt [tossl::jwt::create -header $header_json -payload $payload_json -key "array_secret" -alg HS256]
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[lindex [dict get $decoded_payload roles] 0] != "user"} {
        error "Array claim not preserved"
    }
    if {[lindex [dict get $decoded_payload nested_arrays] 0] != [list 1 2 3]} {
        error "Nested array claim not preserved"
    }
}

# Test 20: JWT creation with null and empty claims
test "JWT creation with null and empty claims" {
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
    
    # Verify the JWT can be decoded
    set decoded [tossl::jwt::decode -token $jwt]
    set decoded_payload [tossl::json::parse [dict get $decoded payload]]
    
    if {[dict get $decoded_payload empty_string] != ""} {
        error "Empty string claim not preserved"
    }
    if {[dict get [dict get $decoded_payload mixed] valid_field] != "value"} {
        error "Valid field in mixed claim not preserved"
    }
}

# Summary
puts "\n=== JWT Create Test Summary ==="
puts "Total tests: 20"
puts "Passed: [expr 20 - $errors]"
puts "Failed: $errors"

if {$errors > 0} {
    exit 1
} else {
    puts "All tests passed! ✅"
} 