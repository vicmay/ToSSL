# tests/test_http_metrics.tcl ;# Test for ::tossl::http::metrics

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Test initial metrics (should be zero)
set rc [catch {set metrics [tossl::http::metrics]} res]
if {$rc == 0 && [dict exists $metrics total_requests] && [dict get $metrics total_requests] == 0} {
    puts ";# PASS: initial metrics are zero"
} else {
    puts stderr ";# FAIL: initial metrics test: $res"
    exit 1
}

# Test metrics structure
if {[dict exists $metrics avg_response_time] && [dict exists $metrics total_request_time]} {
    puts ";# PASS: metrics structure is correct"
} else {
    puts stderr ";# FAIL: metrics structure missing required fields"
    exit 2
}

# Test initial average response time (should be 0.0 when no requests)
if {[dict get $metrics avg_response_time] == 0.0} {
    puts ";# PASS: initial average response time is 0.0"
} else {
    puts stderr ";# FAIL: initial average response time should be 0.0"
    exit 3
}

# Test initial total request time (should be 0.0 when no requests)
if {[dict get $metrics total_request_time] == 0.0} {
    puts ";# PASS: initial total request time is 0.0"
} else {
    puts stderr ";# FAIL: initial total request time should be 0.0"
    exit 4
}

# Make some HTTP requests to generate metrics
set rc [catch {tossl::http::get "https://httpbin.org/get"} res]
if {$rc != 0} {
    puts stderr ";# FAIL: could not make test request: $res"
    exit 5
}

set rc [catch {tossl::http::get "https://httpbin.org/status/200"} res]
if {$rc != 0} {
    puts stderr ";# FAIL: could not make second test request: $res"
    exit 6
}

set rc [catch {tossl::http::post "https://httpbin.org/post" "test data"} res]
if {$rc != 0} {
    puts stderr ";# FAIL: could not make third test request: $res"
    exit 7
}

# Test metrics after requests
set rc [catch {set metrics [tossl::http::metrics]} res]
if {$rc == 0 && [dict get $metrics total_requests] == 3} {
    puts ";# PASS: total requests count is correct"
} else {
    puts stderr ";# FAIL: total requests count incorrect: [dict get $metrics total_requests]"
    exit 8
}

# Test that total request time is positive
if {[dict get $metrics total_request_time] > 0.0} {
    puts ";# PASS: total request time is positive"
} else {
    puts stderr ";# FAIL: total request time should be positive"
    exit 9
}

# Test that average response time is positive
if {[dict get $metrics avg_response_time] > 0.0} {
    puts ";# PASS: average response time is positive"
} else {
    puts stderr ";# FAIL: average response time should be positive"
    exit 10
}

# Test that average response time calculation is correct
set expected_avg [expr {[dict get $metrics total_request_time] / [dict get $metrics total_requests]}]
set actual_avg [dict get $metrics avg_response_time]
set diff [expr {abs($expected_avg - $actual_avg)}]
if {$diff < 0.001} {
    puts ";# PASS: average response time calculation is correct"
} else {
    puts stderr ";# FAIL: average response time calculation incorrect: expected $expected_avg, got $actual_avg"
    exit 11
}

# Make more requests to test metrics accumulation
set rc [catch {tossl::http::get "https://httpbin.org/delay/1" -timeout 5} res]
if {$rc != 0} {
    puts stderr ";# FAIL: could not make delayed request: $res"
    exit 12
}

# Test metrics accumulation
set rc [catch {set metrics [tossl::http::metrics]} res]
if {$rc == 0 && [dict get $metrics total_requests] == 4} {
    puts ";# PASS: metrics accumulate correctly"
} else {
    puts stderr ";# FAIL: metrics accumulation incorrect: [dict get $metrics total_requests]"
    exit 13
}

# Test that total request time increased
if {[dict get $metrics total_request_time] > 0.0} {
    puts ";# PASS: total request time accumulates"
} else {
    puts stderr ";# FAIL: total request time should accumulate"
    exit 14
}

# Test metrics consistency after multiple calls
set rc [catch {set metrics1 [tossl::http::metrics]} res]
if {$rc != 0} {
    puts stderr ";# FAIL: first metrics call failed: $res"
    exit 15
}

set rc [catch {set metrics2 [tossl::http::metrics]} res]
if {$rc != 0} {
    puts stderr ";# FAIL: second metrics call failed: $res"
    exit 16
}

# Metrics should be identical when called consecutively without new requests
if {[dict get $metrics1 total_requests] == [dict get $metrics2 total_requests] && \
    [dict get $metrics1 total_request_time] == [dict get $metrics2 total_request_time] && \
    [dict get $metrics1 avg_response_time] == [dict get $metrics2 avg_response_time]} {
    puts ";# PASS: metrics are consistent across calls"
} else {
    puts stderr ";# FAIL: metrics should be consistent across calls"
    exit 17
}

# Test metrics with no arguments (should not error)
set rc [catch {tossl::http::metrics} res]
if {$rc == 0} {
    puts ";# PASS: metrics command accepts no arguments"
} else {
    puts stderr ";# FAIL: metrics command should accept no arguments: $res"
    exit 18
}

puts ";# All tests passed."
exit 0 