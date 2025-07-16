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

# Test error: missing URL
set rc [catch {tossl::http::get} res]
if {$rc != 0} {
    puts ";# PASS: error on missing URL"
} else {
    puts stderr ";# FAIL: expected error on missing URL"
    exit 5
}

# Test error: invalid URL
set rc [catch {set response [tossl::http::get "://invalid-url"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: invalid URL returns status_code 0"
} else {
    puts stderr ";# FAIL: invalid URL test: $res"
    exit 6
}

# Test error: non-existent domain
set rc [catch {set response [tossl::http::get "https://this-domain-does-not-exist-12345.com/"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: non-existent domain returns status_code 0"
} else {
    puts stderr ";# FAIL: non-existent domain test: $res"
    exit 7
}

# Test GET request to endpoint that returns specific status code
set rc [catch {set response [tossl::http::get "https://httpbin.org/status/404"]} res]
if {$rc == 0 && [dict get $response status_code] == 404} {
    puts ";# PASS: 404 status code handled correctly"
} else {
    puts stderr ";# FAIL: 404 status code test: $res"
    exit 8
}

puts ";# All tests passed."
exit 0 