#!/usr/bin/env tclsh

;# Test file for ::tossl::http::debug command
;# Tests debug functionality, levels, and integration with HTTP requests

package require tossl

;# Test counter
set test_count 0
set passed_count 0

proc test {name test_script} {
    global test_count passed_count
    incr test_count
    puts "Test $test_count: $name"
    
    if {[catch {eval $test_script} result]} {
        puts "  FAILED: $result"
        return 0
    } else {
        puts "  PASSED"
        incr passed_count
        return 1
    }
}

proc assert {condition message} {
    if {!$condition} {
        error "Assertion failed: $message"
    }
}

proc assert_equals {expected actual message} {
    if {$expected ne $actual} {
        error "Assertion failed: $message (expected: '$expected', got: '$actual')"
    }
}

proc assert_true {condition message} {
    if {!$condition} {
        error "Assertion failed: $message"
    }
}

proc assert_error {script message} {
    set result [catch $script error_msg]
    if {$result != 1} {
        error "Assertion failed: $message (expected error, got result: $result)"
    }
    return $error_msg
}

puts "=== Testing ::tossl::http::debug ==="

;# Test 1: Basic enable/disable functionality
test "Enable debug logging" {
    set result [::tossl::http::debug enable]
    assert_equals "Debug logging enabled" $result "Enable should return success message"
}

test "Disable debug logging" {
    set result [::tossl::http::debug disable]
    assert_equals "Debug logging disabled" $result "Disable should return success message"
}

;# Test 2: Enable with different debug levels
test "Enable with verbose level" {
    set result [::tossl::http::debug enable -level verbose]
    assert_equals "Debug logging enabled" $result "Enable with verbose should return success message"
}

test "Enable with info level" {
    set result [::tossl::http::debug enable -level info]
    assert_equals "Debug logging enabled" $result "Enable with info should return success message"
}

test "Enable with warning level" {
    set result [::tossl::http::debug enable -level warning]
    assert_equals "Debug logging enabled" $result "Enable with warning should return success message"
}

test "Enable with error level" {
    set result [::tossl::http::debug enable -level error]
    assert_equals "Debug logging enabled" $result "Enable with error should return success message"
}

;# Test 3: Enable without level (should default to info)
test "Enable without level (defaults to info)" {
    set result [::tossl::http::debug enable]
    assert_equals "Debug logging enabled" $result "Enable without level should return success message"
}

;# Test 4: Error handling - invalid actions
test "Invalid action should return error" {
    set error_msg [assert_error {::tossl::http::debug invalid_action} "Invalid action should cause error"]
    if {![string match "*Invalid action*" $error_msg]} {
        error "Error should mention invalid action, got: $error_msg"
    }
}

test "Invalid level should be ignored (enable still works)" {
    set result [::tossl::http::debug enable -level invalid_level]
    assert_equals "Debug logging enabled" $result "Enable with invalid level should still work"
}

;# Test 5: Error handling - wrong number of arguments
test "No arguments should return error" {
    set error_msg [assert_error {::tossl::http::debug} "No arguments should cause error"]
    if {![string match "*wrong # args*" $error_msg]} {
        error "Error should mention wrong number of arguments, got: $error_msg"
    }
}

test "Only level without action should return error" {
    set error_msg [assert_error {::tossl::http::debug -level verbose} "Only level without action should cause error"]
    if {![string match "*wrong # args*" $error_msg] && ![string match "*Invalid action*" $error_msg]} {
        error "Error should mention wrong number of arguments or invalid action, got: $error_msg"
    }
}

;# Test 6: Integration test - debug with HTTP request
test "Debug enabled during HTTP request" {
    ;# Enable debug
    ::tossl::http::debug enable -level info
    
    ;# Make a simple HTTP request to test debug output
    ;# Note: We can't easily capture stdout in TCL, so we just verify the request works
    set response [::tossl::http::get "https://httpbin.org/get"]
    ;# For this test, we just verify that debug was enabled and the request executed
    puts "  Note: Debug was enabled during HTTP request"
    
    ;# Disable debug
    ::tossl::http::debug disable
}

;# Test 7: Multiple enable/disable cycles
test "Multiple enable/disable cycles" {
    for {set i 0} {$i < 3} {incr i} {
        set result1 [::tossl::http::debug enable]
        assert_equals "Debug logging enabled" $result1 "Enable cycle $i should work"
        
        set result2 [::tossl::http::debug disable]
        assert_equals "Debug logging disabled" $result2 "Disable cycle $i should work"
    }
}

;# Test 8: Debug with different levels in sequence
test "Debug level changes" {
    ;# Test each level
    foreach level {error warning info verbose} {
        set result [::tossl::http::debug enable -level $level]
        assert_equals "Debug logging enabled" $result "Enable with $level should work"
        
        set result [::tossl::http::debug disable]
        assert_equals "Debug logging disabled" $result "Disable after $level should work"
    }
}

;# Test 9: Case sensitivity for levels
test "Case sensitivity for debug levels" {
    ;# Test that levels are case-sensitive (they should be)
    foreach level {VERBOSE Info WARNING Error} {
        set result [::tossl::http::debug enable -level $level]
        assert_equals "Debug logging enabled" $result "Enable with $level should work (case-insensitive or ignored)"
        
        set result [::tossl::http::debug disable]
        assert_equals "Debug logging disabled" $result "Disable should work"
    }
}

;# Test 10: Final state verification
test "Final state verification" {
    ;# Ensure debug is disabled at the end
    set result [::tossl::http::debug disable]
    assert_equals "Debug logging disabled" $result "Final disable should work"
}

;# Test 11: Debug with HTTP error (to test error logging)
test "Debug with HTTP error request" {
    ;# Enable debug
    ::tossl::http::debug enable -level error
    
    ;# Make a request to a non-existent domain to trigger error
    set response [::tossl::http::get "https://nonexistent-domain-that-will-fail.com"]
    ;# For error requests, we just verify the command executed (debug was enabled)
    puts "  Note: Debug was enabled during error request"
    
    ;# Disable debug
    ::tossl::http::debug disable
}

;# Test 12: Debug with timeout error
test "Debug with timeout error" {
    ;# Enable debug
    ::tossl::http::debug enable -level warning
    
    ;# Make a request with very short timeout to trigger timeout error
    set response [::tossl::http::get "https://httpbin.org/delay/10" -timeout 1]
    ;# For timeout requests, we just verify the command executed (debug was enabled)
    puts "  Note: Debug was enabled during timeout request"
    
    ;# Disable debug
    ::tossl::http::debug disable
}

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: [expr {$test_count - $passed_count}]"

if {$passed_count == $test_count} {
    puts "ALL TESTS PASSED!"
    exit 0
} else {
    puts "SOME TESTS FAILED!"
    exit 1
} 