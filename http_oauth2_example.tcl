#!/usr/bin/env tclsh
# OAuth2-Ready HTTP Client Example
# Demonstrates how the enhanced HTTP client supports OAuth2 requirements

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== OAuth2-Ready HTTP Client Example ==="

# Example 1: OAuth2 Bearer Token Authentication
puts "\n1. OAuth2 Bearer Token Authentication:"
if {[catch {
    set access_token "your-oauth2-access-token-here"
    
    set response [tossl::http::get_enhanced "https://api.example.com/users" \
        -headers "Authorization: Bearer $access_token\nAccept: application/json" \
        -content_type "application/json" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ OAuth2 Bearer token request successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Request time: [dict get $response request_time] ms"
    
    # Parse JSON response
    if {[catch {
        set users [tossl::json::parse [dict get $response body]]
        puts "   ✓ JSON response parsed successfully"
    }]} {
        puts "   Note: Response is not valid JSON (expected for this example)"
    }
} err]} {
    puts "   ✗ OAuth2 Bearer token request failed: $err"
}

# Example 2: OAuth2 Token Refresh
puts "\n2. OAuth2 Token Refresh:"
if {[catch {
    set refresh_token "your-refresh-token-here"
    set client_id "your-client-id"
    set client_secret "your-client-secret"
    
    # Create form data for token refresh
    set form_data "grant_type=refresh_token&refresh_token=$refresh_token&client_id=$client_id&client_secret=$client_secret"
    
    set response [tossl::http::post_enhanced "https://auth.example.com/oauth/token" $form_data \
        -headers "Content-Type: application/x-www-form-urlencoded" \
        -content_type "application/x-www-form-urlencoded" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ OAuth2 token refresh request successful"
    puts "   Status: [dict get $response status_code]"
    puts "   Request time: [dict get $response request_time] ms"
    
    # Parse token response
    if {[catch {
        set tokens [tossl::json::parse [dict get $response body]]
        puts "   ✓ Token response parsed successfully"
    }]} {
        puts "   Note: Response is not valid JSON (expected for this example)"
    }
} err]} {
    puts "   ✗ OAuth2 token refresh failed: $err"
}

# Example 3: Session-based API Client (OAuth2 Style)
puts "\n3. Session-based API Client (OAuth2 Style):"
if {[catch {
    # Create session for API client
    set session_id [tossl::http::session::create "oauth2_api_session" \
        -timeout 30 \
        -user_agent "ToSSL-OAuth2-Client/1.0"]
    
    puts "   ✓ OAuth2 API session created: $session_id"
    
    # Make authenticated API calls using session
    set access_token "your-access-token"
    
    # GET request with Bearer token
    set response [tossl::http::session::get $session_id "https://api.example.com/users" \
        -headers "Authorization: Bearer $access_token\nAccept: application/json"]
    
    puts "   ✓ Session-based GET request successful"
    puts "   Status: [dict get $response status_code]"
    
    # POST request with Bearer token
    set user_data "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}"
    set response [tossl::http::session::post $session_id "https://api.example.com/users" $user_data \
        -headers "Authorization: Bearer $access_token\nContent-Type: application/json" \
        -content_type "application/json"]
    
    puts "   ✓ Session-based POST request successful"
    puts "   Status: [dict get $response status_code]"
    
    # Clean up session
    set result [tossl::http::session::destroy $session_id]
    puts "   ✓ Session destroyed: $result"
} err]} {
    puts "   ✗ Session-based API client failed: $err"
}

# Example 4: Universal Request Command for OAuth2
puts "\n4. Universal Request Command for OAuth2:"
if {[catch {
    set access_token "your-access-token"
    
    # GET request
    set response [tossl::http::request \
        -method GET \
        -url "https://api.example.com/users" \
        -headers "Authorization: Bearer $access_token\nAccept: application/json" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Universal GET request successful"
    puts "   Status: [dict get $response status_code]"
    
    # PUT request
    set update_data "{\"status\": \"active\"}"
    set response [tossl::http::request \
        -method PUT \
        -url "https://api.example.com/users/123" \
        -data $update_data \
        -headers "Authorization: Bearer $access_token\nContent-Type: application/json" \
        -content_type "application/json" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Universal PUT request successful"
    puts "   Status: [dict get $response status_code]"
    
    # DELETE request
    set response [tossl::http::request \
        -method DELETE \
        -url "https://api.example.com/users/123" \
        -headers "Authorization: Bearer $access_token" \
        -timeout 30 \
        -return_details true]
    
    puts "   ✓ Universal DELETE request successful"
    puts "   Status: [dict get $response status_code]"
} err]} {
    puts "   ✗ Universal request command failed: $err"
}

# Example 5: Error Handling and Debugging
puts "\n5. Error Handling and Debugging:"
if {[catch {
    # Enable debug logging
    tossl::http::debug enable -level info
    puts "   ✓ Debug logging enabled"
    
    # Make a request that might fail
    set response [tossl::http::get_enhanced "https://httpbin.org/status/404" \
        -timeout 10 \
        -return_details true]
    
    puts "   ✓ Error handling test completed"
    puts "   Status: [dict get $response status_code]"
    
    # Get performance metrics
    set metrics [tossl::http::metrics]
    puts "   ✓ Performance metrics collected"
    puts "   Total requests: [dict get $metrics total_requests]"
    puts "   Average response time: [dict get $metrics avg_response_time] ms"
    
    # Disable debug logging
    tossl::http::debug disable
    puts "   ✓ Debug logging disabled"
} err]} {
    puts "   ✗ Error handling and debugging failed: $err"
}

puts "\n=== OAuth2-Ready Features Summary ==="
puts "✅ Custom Headers: Essential for 'Authorization: Bearer token'"
puts "✅ Content-Type Control: Required for JSON API calls"
puts "✅ Timeout Configuration: Important for token refresh operations"
puts "✅ SSL/TLS Options: Security requirements for OAuth2"
puts "✅ Session Management: Connection reuse for better performance"
puts "✅ Universal Request: Support for all HTTP methods (GET, POST, PUT, DELETE)"
puts "✅ Error Handling: Comprehensive error reporting"
puts "✅ Debug Logging: Detailed request/response logging"
puts "✅ Performance Metrics: Request timing and statistics"
puts "✅ Backward Compatibility: Existing commands still work"
puts ""
puts "The enhanced HTTP client is now ready for OAuth2 implementation!"
puts "All the necessary features are in place for building a complete OAuth2 client." 