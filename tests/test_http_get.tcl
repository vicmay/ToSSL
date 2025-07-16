# tests/test_http_get.tcl ;# Test for ::tossl::http::get

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Test basic GET request to httpbin.org
set rc [catch {set response [tossl::http::get "https://httpbin.org/get"]} res]
if {$rc == 0 && [dict exists $response status_code] && [dict exists $response body]} {
    puts ";# PASS: basic GET request"
} else {
    puts stderr ";# FAIL: basic GET request: $res"
    exit 1
}

# Test response structure
if {[dict get $response status_code] == 200} {
    puts ";# PASS: status code 200"
} else {
    puts stderr ";# FAIL: unexpected status code: [dict get $response status_code]"
    exit 2
}

# Test response body contains expected content
if {[string first "httpbin.org" [dict get $response body]] >= 0} {
    puts ";# PASS: response body contains expected content"
} else {
    puts stderr ";# FAIL: response body missing expected content"
    exit 3
}

# Test headers exist
if {[dict exists $response headers] && [string length [dict get $response headers]] > 0} {
    puts ";# PASS: response headers present"
} else {
    puts stderr ";# FAIL: response headers missing or empty"
    exit 4
}

# Test GET with custom headers
set rc [catch {set response [tossl::http::get "https://httpbin.org/headers" -headers "X-Test-Header: test-value"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with custom headers"
} else {
    puts stderr ";# FAIL: GET with custom headers: $res"
    exit 5
}

# Test GET with timeout
set rc [catch {set response [tossl::http::get "https://httpbin.org/delay/1" -timeout 5]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with timeout"
} else {
    puts stderr ";# FAIL: GET with timeout: $res"
    exit 6
}

# Test GET with user agent
set rc [catch {set response [tossl::http::get "https://httpbin.org/user-agent" -user_agent "TestAgent/1.0"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with user agent"
} else {
    puts stderr ";# FAIL: GET with user agent: $res"
    exit 7
}

# Test GET with return details
set rc [catch {set response [tossl::http::get "https://httpbin.org/get" -return_details 1]} res]
if {$rc == 0 && [dict exists $response request_time] && [dict exists $response response_size]} {
    puts ";# PASS: GET with return details"
} else {
    puts stderr ";# FAIL: GET with return details: $res"
    exit 8
}

# Test GET with authentication
set rc [catch {set response [tossl::http::get "https://httpbin.org/basic-auth/user/pass" -auth "user:pass"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with authentication"
} else {
    puts stderr ";# FAIL: GET with authentication: $res"
    exit 9
}

# Test GET with cookies
set rc [catch {set response [tossl::http::get "https://httpbin.org/cookies" -cookies "session=12345; user=test"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with cookies"
} else {
    puts stderr ";# FAIL: GET with cookies: $res"
    exit 10
}

# Test GET with follow_redirects disabled
set rc [catch {set response [tossl::http::get "https://httpbin.org/status/302" -follow_redirects 0]} res]
if {$rc == 0 && [dict get $response status_code] == 302} {
    puts ";# PASS: GET with follow_redirects disabled"
} else {
    puts stderr ";# FAIL: GET with follow_redirects disabled: $res"
    exit 11
}

# Test GET with verify_ssl disabled
set rc [catch {set response [tossl::http::get "https://httpbin.org/get" -verify_ssl 0]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: GET with verify_ssl disabled"
} else {
    puts stderr ";# FAIL: GET with verify_ssl disabled: $res"
    exit 12
}

# Test error: missing URL
set rc [catch {tossl::http::get} res]
if {$rc != 0} {
    puts ";# PASS: error on missing URL"
} else {
    puts stderr ";# FAIL: expected error on missing URL"
    exit 13
}

# Test error: invalid URL
set rc [catch {set response [tossl::http::get "://invalid-url"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: invalid URL returns status_code 0"
} else {
    puts stderr ";# FAIL: invalid URL test: $res"
    exit 14
}

# Test error: non-existent domain
set rc [catch {set response [tossl::http::get "https://this-domain-does-not-exist-12345.com/"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: non-existent domain returns status_code 0"
} else {
    puts stderr ";# FAIL: non-existent domain test: $res"
    exit 15
}

# Test GET request to endpoint that returns specific status code
set rc [catch {set response [tossl::http::get "https://httpbin.org/status/404"]} res]
if {$rc == 0 && [dict get $response status_code] == 404} {
    puts ";# PASS: 404 status code handled correctly"
} else {
    puts stderr ";# FAIL: 404 status code test: $res"
    exit 16
}

puts ";# All tests passed."
exit 0 