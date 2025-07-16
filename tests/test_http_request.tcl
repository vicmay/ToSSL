# tests/test_http_request.tcl ;# Test for ::tossl::http::request

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Test GET request
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/get"]} res]
if {$rc == 0 && [dict exists $response status_code] && [dict get $response status_code] == 200} {
    puts ";# PASS: GET request"
} else {
    puts stderr ";# FAIL: GET request: $res"
    exit 1
}

# Test POST request with data
set rc [catch {set response [tossl::http::request -method POST -url "https://httpbin.org/post" -data "test data"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: POST request with data"
} else {
    puts stderr ";# FAIL: POST request: $res"
    exit 2
}

# Test PUT request
set rc [catch {set response [tossl::http::request -method PUT -url "https://httpbin.org/put" -data "put data"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: PUT request"
} else {
    puts stderr ";# FAIL: PUT request: $res"
    exit 3
}

# Test DELETE request
set rc [catch {set response [tossl::http::request -method DELETE -url "https://httpbin.org/delete"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: DELETE request"
} else {
    puts stderr ";# FAIL: DELETE request: $res"
    exit 4
}

# Test PATCH request
set rc [catch {set response [tossl::http::request -method PATCH -url "https://httpbin.org/patch" -data "patch data"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: PATCH request"
} else {
    puts stderr ";# FAIL: PATCH request: $res"
    exit 5
}

# Test with custom headers
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/headers" -headers "X-Test-Header: test-value"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: custom headers"
} else {
    puts stderr ";# FAIL: custom headers: $res"
    exit 6
}

# Test with content type
set rc [catch {set response [tossl::http::request -method POST -url "https://httpbin.org/post" -data "json data" -content_type "application/json"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: content type"
} else {
    puts stderr ";# FAIL: content type: $res"
    exit 7
}

# Test with timeout
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/delay/1" -timeout 5]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: timeout"
} else {
    puts stderr ";# FAIL: timeout: $res"
    exit 8
}

# Test with user agent
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/user-agent" -user_agent "TestAgent/1.0"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: user agent"
} else {
    puts stderr ";# FAIL: user agent: $res"
    exit 9
}

# Test with return details
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/get" -return_details 1]} res]
if {$rc == 0 && [dict exists $response request_time] && [dict exists $response response_size]} {
    puts ";# PASS: return details"
} else {
    puts stderr ";# FAIL: return details: $res"
    exit 10
}

# Test error: missing method
set rc [catch {tossl::http::request -url "https://httpbin.org/get"} res]
if {$rc != 0} {
    puts ";# PASS: error on missing method"
} else {
    puts stderr ";# FAIL: expected error on missing method"
    exit 11
}

# Test error: missing URL
set rc [catch {tossl::http::request -method GET} res]
if {$rc != 0} {
    puts ";# PASS: error on missing URL"
} else {
    puts stderr ";# FAIL: expected error on missing URL"
    exit 12
}

# Test error: invalid method (libcurl accepts custom methods, so this may succeed)
set rc [catch {set response [tossl::http::request -method INVALID -url "https://httpbin.org/get"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: custom HTTP method accepted"
} else {
    puts stderr ";# FAIL: custom HTTP method test: $res"
    exit 13
}

# Test error: invalid URL
set rc [catch {set response [tossl::http::request -method GET -url "://invalid-url"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: invalid URL returns status_code 0"
} else {
    puts stderr ";# FAIL: invalid URL test: $res"
    exit 14
}

# Test with cookies
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/cookies" -cookies "session=12345; user=test"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: cookies"
} else {
    puts stderr ";# FAIL: cookies: $res"
    exit 15
}

# Test with authentication (httpbin.org supports basic auth)
set rc [catch {set response [tossl::http::request -method GET -url "https://httpbin.org/basic-auth/user/pass" -auth "user:pass"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: authentication"
} else {
    puts stderr ";# FAIL: authentication: $res"
    exit 16
}

puts ";# All tests passed."
exit 0 