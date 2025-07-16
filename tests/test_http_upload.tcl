# tests/test_http_upload.tcl ;# Test for ::tossl::http::upload

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Create a temporary test file
set test_file "test_upload.txt"
set test_content "This is a test file for upload testing.\nLine 2\nLine 3"
set fd [open $test_file w]
puts $fd $test_content
close $fd

# Test basic file upload to httpbin.org
set rc [catch {set response [tossl::http::upload "https://httpbin.org/post" $test_file]} res]
if {$rc == 0 && [dict exists $response status_code] && [dict exists $response body]} {
    puts ";# PASS: basic file upload"
} else {
    puts stderr ";# FAIL: basic file upload: $res"
    file delete $test_file
    exit 1
}

# Test response structure
if {[dict get $response status_code] == 200} {
    puts ";# PASS: status code 200"
} else {
    puts stderr ";# FAIL: unexpected status code: [dict get $response status_code]"
    file delete $test_file
    exit 2
}

# Test response body contains expected content
if {[string first "test file" [dict get $response body]] >= 0} {
    puts ";# PASS: response body contains file content"
} else {
    puts stderr ";# FAIL: response body missing file content"
    file delete $test_file
    exit 3
}

# Test with custom field name
set rc [catch {set response [tossl::http::upload "https://httpbin.org/post" $test_file -field_name "custom_file"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: custom field name"
} else {
    puts stderr ";# FAIL: custom field name: $res"
    file delete $test_file
    exit 4
}

# Test with additional fields
set rc [catch {set response [tossl::http::upload "https://httpbin.org/post" $test_file -additional_fields "description:test file\ncategory:test"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: additional fields"
} else {
    puts stderr ";# FAIL: additional fields: $res"
    file delete $test_file
    exit 5
}

# Test with custom headers
set rc [catch {set response [tossl::http::upload "https://httpbin.org/post" $test_file -headers "X-Test-Header: test-value"]} res]
if {$rc == 0 && [dict get $response status_code] == 200} {
    puts ";# PASS: custom headers"
} else {
    puts stderr ";# FAIL: custom headers: $res"
    file delete $test_file
    exit 6
}

# Test error: missing URL
set rc [catch {tossl::http::upload} res]
if {$rc != 0} {
    puts ";# PASS: error on missing URL"
} else {
    puts stderr ";# FAIL: expected error on missing URL"
    file delete $test_file
    exit 7
}

# Test error: missing file path
set rc [catch {tossl::http::upload "https://httpbin.org/post"} res]
if {$rc != 0} {
    puts ";# PASS: error on missing file path"
} else {
    puts stderr ";# FAIL: expected error on missing file path"
    file delete $test_file
    exit 8
}

# Test error: non-existent file
set rc [catch {set response [tossl::http::upload "https://httpbin.org/post" "non_existent_file.txt"]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: non-existent file returns status_code 0"
} else {
    puts stderr ";# FAIL: non-existent file test: $res"
    file delete $test_file
    exit 9
}

# Test error: invalid URL
set rc [catch {set response [tossl::http::upload "://invalid-url" $test_file]} res]
if {$rc == 0 && [dict get $response status_code] == 0} {
    puts ";# PASS: invalid URL returns status_code 0"
} else {
    puts stderr ";# FAIL: invalid URL test: $res"
    file delete $test_file
    exit 10
}

# Clean up test file
file delete $test_file

puts ";# All tests passed."
exit 0 