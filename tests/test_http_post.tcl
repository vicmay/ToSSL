# tests/test_http_post.tcl ;# Test for ::tossl::http::post

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Test basic POST request
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data"]} res]
if {$rc == 0 && [dict exists $response status_code] && [dict get $response status_code] == 200} {
    puts ";# PASS: basic POST request"
} else {
    puts stderr ";# FAIL: basic POST request: $res"
    exit 1
}

# Test POST with JSON data
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "{\"key\": \"value\", \"number\": 42}" -content_type "application/json"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with JSON data"
} else {
    puts stderr ";# FAIL: POST with JSON data: $res"
    exit 2
}

# Test POST with custom headers
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -headers "X-Test-Header: test-value"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with custom headers"
} else {
    puts stderr ";# FAIL: POST with custom headers: $res"
    exit 3
}

# Test POST with timeout
set rc [catch {set response [tossl::http::post "https://httpbin.org/delay/1" "test data" -timeout 5]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with timeout"
} else {
    puts stderr ";# FAIL: POST with timeout: $res"
    exit 4
}

# Test POST with user agent
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -user_agent "TestAgent/1.0"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with user agent"
} else {
    puts stderr ";# FAIL: POST with user agent: $res"
    exit 5
}

# Test POST with return details
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -return_details 1]} res]
if {$rc == 0 && [dict exists $response request_time] && [dict exists $response response_size]} {
    puts ";# PASS: POST with return details"
} else {
    puts stderr ";# FAIL: POST with return details: $res"
    exit 6
}

# Test POST with authentication (use a different endpoint that supports POST)
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -auth "user:pass"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with authentication"
} else {
    puts stderr ";# FAIL: POST with authentication: $res"
    exit 7
}

# Test POST with cookies
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -cookies "session=12345; user=test"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with cookies"
} else {
    puts stderr ";# FAIL: POST with cookies: $res"
    exit 8
}

# Test POST with follow_redirects disabled (test with a different approach)
set rc [catch {set response [tossl::http::post "https://httpbin.org/status/302" "test data" -follow_redirects 0]} res]
if {$rc == 0 && [dict get $response status_code] == 302} {
    puts ";# PASS: POST with follow_redirects disabled"
} else {
    puts stderr ";# FAIL: POST with follow_redirects disabled: $res"
    exit 9
}

# Test POST with verify_ssl disabled (should still work with httpbin.org)
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "test data" -verify_ssl 0]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with verify_ssl disabled"
} else {
    puts stderr ";# FAIL: POST with verify_ssl disabled: $res"
    exit 10
}

# Test error: missing URL
set rc [catch {tossl::http::post "test data"} res]
if {$rc != 0} {
    puts ";# PASS: error on missing URL"
} else {
    puts stderr ";# FAIL: expected error on missing URL"
    exit 11
}

# Test error: missing data
set rc [catch {tossl::http::post "https://httpbin.org/post"} res]
if {$rc != 0} {
    puts ";# PASS: error on missing data"
} else {
    puts stderr ";# FAIL: expected error on missing data"
    exit 12
}

# Test error: invalid URL
set rc [catch {set response [tossl::http::post "://invalid-url" "test data"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: invalid URL returns status_code 0"
} else {
    puts stderr ";# FAIL: invalid URL test: $res"
    exit 13
}

# Test POST with form data
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "name=test&value=123" -content_type "application/x-www-form-urlencoded"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with form data"
} else {
    puts stderr ";# FAIL: POST with form data: $res"
    exit 14
}

# Test POST with XML data
set rc [catch {set response [tossl::http::post "https://httpbin.org/post" "<test><value>123</value></test>" -content_type "application/xml"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST with XML data"
} else {
    puts stderr ";# FAIL: POST with XML data: $res"
    exit 15
}

puts ";# All tests passed."
exit 0 