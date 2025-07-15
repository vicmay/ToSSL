#!/usr/bin/env tclsh
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== TOSSL HTTP Client Test ==="

# Test 1: Basic GET request
puts "\n1. Testing basic GET request..."
if {[catch {
    set result [tossl::http::get "https://httpbin.org/get"]
    puts "   ✓ GET request successful"
    puts "   Response length: [string length $result]"
} err]} {
    puts "   ✗ GET request failed: $err"
}

# Test 2: Basic POST request
puts "\n2. Testing basic POST request..."
if {[catch {
    set result [tossl::http::post "https://httpbin.org/post" "test=data&value=123"]
    puts "   ✓ POST request successful"
    puts "   Response length: [string length $result]"
} err]} {
    puts "   ✗ POST request failed: $err"
}

# Test 3: JSON POST request
puts "\n3. Testing JSON POST request..."
if {[catch {
    set json_data "{\"name\": \"test\", \"value\": 42, \"active\": true}"
    set result [tossl::http::post "https://httpbin.org/post" $json_data]
    puts "   ✓ JSON POST request successful"
    puts "   Response length: [string length $result]"
} err]} {
    puts "   ✗ JSON POST request failed: $err"
}

# Test 4: Error handling - invalid URL
puts "\n4. Testing error handling (invalid URL)..."
if {[catch {
    set result [tossl::http::get "https://invalid-domain-that-does-not-exist-12345.com"]
    puts "   ✗ Should have failed but didn't"
} err]} {
    puts "   ✓ Error handling working: $err"
}

# Test 5: HTTPS with certificate verification
puts "\n5. Testing HTTPS with certificate verification..."
if {[catch {
    set result [tossl::http::get "https://httpbin.org/status/200"]
    puts "   ✓ HTTPS with certificate verification successful"
} err]} {
    puts "   ✗ HTTPS test failed: $err"
}

# Test 6: Different HTTP status codes
puts "\n6. Testing different HTTP status codes..."
foreach status {200 404 500} {
    if {[catch {
        set result [tossl::http::get "https://httpbin.org/status/$status"]
        puts "   ✓ Status $status request successful"
    } err]} {
        puts "   ✗ Status $status request failed: $err"
    }
}

# Test 7: Large response handling
puts "\n7. Testing large response handling..."
if {[catch {
    set result [tossl::http::get "https://httpbin.org/bytes/1000"]
    puts "   ✓ Large response (1000 bytes) successful"
    puts "   Response length: [string length $result]"
} err]} {
    puts "   ✗ Large response test failed: $err"
}

puts "\n=== HTTP Client Test Complete ==="
puts "If all tests passed, libcurl integration is working correctly!" 