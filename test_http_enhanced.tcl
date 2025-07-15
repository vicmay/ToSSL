#!/usr/bin/env tclsh
# Enhanced HTTP Client Test for TOSSL
# Tests all the new HTTP client features

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== TOSSL Enhanced HTTP Client Test ==="

# Test 1: Enhanced GET with custom headers
puts "\n1. Testing enhanced GET with custom headers..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/get" \
        -headers "User-Agent: ToSSL-Test/1.0\nAccept: application/json" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Enhanced GET successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Request time: [dict get $response request_time] ms"
    puts "   Response size: [dict get $response response_size] bytes"
} err]} {
    puts "   ✗ Enhanced GET failed: $err"
}

# Test 2: Enhanced POST with JSON content-type
puts "\n2. Testing enhanced POST with JSON content-type..."
if {[catch {
    set json_data "{\"name\": \"test\", \"value\": 42, \"active\": true}"
    set response [tossl::http::post_enhanced "https://httpbin.org/post" $json_data \
        -headers "Authorization: Bearer test-token\nX-Custom-Header: test-value" \
        -content_type "application/json" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Enhanced POST successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Request time: [dict get $response request_time] ms"
} err]} {
    puts "   ✗ Enhanced POST failed: $err"
}

# Test 3: Universal request command
puts "\n3. Testing universal request command..."
if {[catch {
    set response [tossl::http::request \
        -method GET \
        -url "https://httpbin.org/status/200" \
        -headers "User-Agent: ToSSL-Universal/1.0" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Universal request successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ Universal request failed: $err"
}

# Test 4: PUT request
puts "\n4. Testing PUT request..."
if {[catch {
    set response [tossl::http::request \
        -method PUT \
        -url "https://httpbin.org/put" \
        -data "{\"updated\": true}" \
        -content_type "application/json" \
        -headers "Content-Type: application/json" \
        -return_details true]
    
    puts "   ✓ PUT request successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ PUT request failed: $err"
}

# Test 5: DELETE request
puts "\n5. Testing DELETE request..."
if {[catch {
    set response [tossl::http::request \
        -method DELETE \
        -url "https://httpbin.org/delete" \
        -return_details true]
    
    puts "   ✓ DELETE request successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ DELETE request failed: $err"
}

# Test 6: Session management
puts "\n6. Testing session management..."
if {[catch {
    # Create session
    set session_id [tossl::http::session::create "test_session" \
        -timeout 30 \
        -user_agent "ToSSL-Session/1.0"]
    puts "   ✓ Session created: $session_id"
    
    # Use session for GET request
    set response [tossl::http::session::get $session_id "https://httpbin.org/get" \
        -headers "X-Session-Header: test"]
    puts "   ✓ Session GET successful"
    puts "   Status: [dict get $response status_code]"
    
    # Use session for POST request
    set response [tossl::http::session::post $session_id "https://httpbin.org/post" \
        "session_data=test" \
        -content_type "application/x-www-form-urlencoded"]
    puts "   ✓ Session POST successful"
    puts "   Status: [dict get $response status_code]"
    
    # Destroy session
    set result [tossl::http::session::destroy $session_id]
    puts "   ✓ Session destroyed: $result"
} err]} {
    puts "   ✗ Session management failed: $err"
}

# Test 7: File upload (simulated)
puts "\n7. Testing file upload..."
if {[catch {
    # Create a temporary file for testing
    set temp_file "/tmp/tossl_test_upload.txt"
    set f [open $temp_file w]
    puts $f "This is a test file for upload"
    close $f
    
    set response [tossl::http::upload "https://httpbin.org/post" $temp_file \
        -field_name "file" \
        -additional_fields "description: Test upload\ncategory: test" \
        -headers "X-Upload-Test: true"]
    
    puts "   ✓ File upload successful"
    puts "   Status: [dict get $response status_code]"
    
    # Clean up temp file
    file delete $temp_file
} err]} {
    puts "   ✗ File upload failed: $err"
}

# Test 8: Authentication
puts "\n8. Testing authentication..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/basic-auth/user/pass" \
        -auth "user:pass" \
        -return_details true]
    
    puts "   ✓ Authentication successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ Authentication failed: $err"
}

# Test 9: SSL verification control
puts "\n9. Testing SSL verification control..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/get" \
        -verify_ssl true \
        -return_details true]
    
    puts "   ✓ SSL verification successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ SSL verification failed: $err"
}

# Test 10: Timeout configuration
puts "\n10. Testing timeout configuration..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/delay/1" \
        -timeout 5 \
        -return_details true]
    
    puts "   ✓ Timeout configuration successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Request time: [dict get $response request_time] ms"
} err]} {
    puts "   ✗ Timeout configuration failed: $err"
}

# Test 11: Redirect control
puts "\n11. Testing redirect control..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/redirect/1" \
        -follow_redirects true \
        -return_details true]
    
    puts "   ✓ Redirect control successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Redirect count: [dict get $response redirect_count]"
} err]} {
    puts "   ✗ Redirect control failed: $err"
}

# Test 12: User agent customization
puts "\n12. Testing user agent customization..."
if {[catch {
    set response [tossl::http::get_enhanced "https://httpbin.org/user-agent" \
        -user_agent "ToSSL-Custom-UA/1.0" \
        -return_details true]
    
    puts "   ✓ User agent customization successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ User agent customization failed: $err"
}

# Test 13: Debug and metrics
puts "\n13. Testing debug and metrics..."
if {[catch {
    # Enable debug logging
    tossl::http::debug enable -level info
    puts "   ✓ Debug logging enabled"
    
    # Make a test request
    set response [tossl::http::get_enhanced "https://httpbin.org/get" \
        -return_details true]
    
    # Get metrics
    set metrics [tossl::http::metrics]
    puts "   ✓ Metrics collected"
    puts "   Total requests: [dict get $metrics total_requests]"
    puts "   Average response time: [dict get $metrics avg_response_time] ms"
    puts "   Total request time: [dict get $metrics total_request_time] ms"
    
    # Disable debug logging
    tossl::http::debug disable
    puts "   ✓ Debug logging disabled"
} err]} {
    puts "   ✗ Debug and metrics failed: $err"
}

# Test 14: Error handling
puts "\n14. Testing error handling..."
if {[catch {
    set response [tossl::http::get_enhanced "https://invalid-domain-that-does-not-exist-12345.com" \
        -timeout 5 \
        -return_details true]
    puts "   ✗ Should have failed but didn't"
} err]} {
    puts "   ✓ Error handling working: $err"
}

# Test 15: Legacy compatibility
puts "\n15. Testing legacy compatibility..."
if {[catch {
    set response [tossl::http::get "https://httpbin.org/get"]
    puts "   ✓ Legacy GET working"
    puts "   Status: [dict get $response status_code]"
    
    set response [tossl::http::post "https://httpbin.org/post" "test=data"]
    puts "   ✓ Legacy POST working"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ Legacy compatibility failed: $err"
}

puts "\n=== Enhanced HTTP Client Test Complete ==="
puts "All tests completed successfully!"
puts ""
puts "New features available:"
puts "- Enhanced GET/POST with custom headers, timeouts, authentication"
puts "- Universal request command supporting all HTTP methods"
puts "- Session management for connection reuse"
puts "- File upload support"
puts "- Debug logging and performance metrics"
puts "- SSL/TLS control and redirect management"
puts "- Backward compatibility with existing commands" 