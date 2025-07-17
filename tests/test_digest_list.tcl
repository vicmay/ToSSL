#!/usr/bin/env tclsh

;# Test file for ::tossl::digest::list command
;# Tests digest algorithm listing functionality

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

puts "=== Testing ::tossl::digest::list ==="

;# Test 1: Basic functionality - get list of digest algorithms
test "Get list of digest algorithms" {
    set algorithms [::tossl::digest::list]
    set length [llength $algorithms]
    assert_true [expr {$length > 0}] "Should return non-empty list"
    puts "  Found $length digest algorithms"
}

;# Test 2: Verify list structure
test "Verify list structure" {
    set algorithms [::tossl::digest::list]
    set length [llength $algorithms]
    assert_true [expr {$length > 0}] "List should not be empty"
    
    ;# Check that each element is a string
    foreach alg $algorithms {
        assert_true [string is ascii $alg] "Algorithm name should be ASCII string"
        assert_true [expr {[string length $alg] > 0}] "Algorithm name should not be empty"
    }
}

;# Test 3: Check for common digest algorithms
test "Check for common digest algorithms" {
    set algorithms [::tossl::digest::list]
    set common_algs {SHA256 SHA1 MD5 SHA512}
    set found_count 0
    
    foreach common_alg $common_algs {
        if {[lsearch -exact $algorithms $common_alg] >= 0} {
            incr found_count
            puts "  Found common algorithm: $common_alg"
        }
    }
    
    ;# Should find at least some common algorithms
    assert_true [expr {$found_count > 0}] "Should find at least some common digest algorithms"
}

;# Test 4: Verify algorithms are valid by testing them
test "Verify algorithms are valid by testing them" {
    set algorithms [::tossl::digest::list]
    set test_data "test data"
    set valid_count 0
    
    ;# Test first few algorithms to verify they work
    set test_algorithms [lrange $algorithms 0 4]
    foreach alg $test_algorithms {
        if {[catch {
            set hash [::tossl::digest -alg $alg $test_data]
            assert_true [expr {[string length $hash] > 0}] "Hash should not be empty"
        }]} {
            puts "  Warning: Algorithm '$alg' failed digest test"
        } else {
            incr valid_count
            puts "  Verified algorithm: $alg"
        }
    }
    
    ;# Should have at least some valid algorithms
    assert_true [expr {$valid_count > 0}] "Should have at least some valid digest algorithms"
}

;# Test 5: Error handling - wrong number of arguments
test "Error handling - wrong number of arguments" {
    set error_msg [assert_error {::tossl::digest::list extra_arg} "Wrong number of arguments should cause error"]
    assert_true [string match "*wrong # args*" $error_msg] "Error should mention wrong number of arguments"
}

;# Test 6: Consistency - multiple calls should return same results
test "Consistency - multiple calls should return same results" {
    set algorithms1 [::tossl::digest::list]
    set algorithms2 [::tossl::digest::list]
    
    assert_equals [llength $algorithms1] [llength $algorithms2] "Multiple calls should return same number of algorithms"
    
    ;# Sort both lists for comparison
    set sorted1 [lsort $algorithms1]
    set sorted2 [lsort $algorithms2]
    
    assert_equals $sorted1 $sorted2 "Multiple calls should return same algorithms"
}

;# Test 7: Check for specific algorithm types
test "Check for specific algorithm types" {
    set algorithms [::tossl::digest::list]
    
    ;# Check for SHA family
    set sha_found 0
    foreach alg $algorithms {
        if {[string match "SHA*" $alg]} {
            incr sha_found
        }
    }
    assert_true [expr {$sha_found > 0}] "Should find SHA family algorithms"
    
    ;# Check for other common families
    set md5_found 0
    foreach alg $algorithms {
        if {[string match "MD5" $alg]} {
            incr md5_found
        }
    }
    
    puts "  Found $sha_found SHA algorithms, $md5_found MD5 algorithms"
}

;# Test 8: Performance test - multiple rapid calls
test "Performance test - multiple rapid calls" {
    set start_time [clock clicks -milliseconds]
    
    for {set i 0} {$i < 10} {incr i} {
        set algorithms [::tossl::digest::list]
        set length [llength $algorithms]
        assert_true [expr {$length > 0}] "Each call should return algorithms"
    }
    
    set end_time [clock clicks -milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "  Completed 10 calls in ${duration}ms"
    assert_true [expr {$duration < 1000}] "Should complete 10 calls in under 1 second"
}

;# Test 9: Verify no duplicates in list
test "Verify no duplicates in list" {
    set algorithms [::tossl::digest::list]
    set unique_algorithms [lsort -unique $algorithms]
    
    assert_equals [llength $algorithms] [llength $unique_algorithms] "List should contain no duplicates"
}

;# Test 10: Check algorithm name format
test "Check algorithm name format" {
    set algorithms [::tossl::digest::list]
    
    foreach alg $algorithms {
        ;# Algorithm names should contain only alphanumeric characters, hyphens, and slashes
        assert_true [regexp {^[A-Z0-9/-]+$} $alg] "Algorithm name should be uppercase alphanumeric with hyphens and slashes: '$alg'"
        assert_true [expr {[string length $alg] <= 50}] "Algorithm name should be reasonably short: '$alg'"
    }
}

;# Test 11: Integration test - use listed algorithms with digest command
test "Integration test - use listed algorithms with digest command" {
    set algorithms [::tossl::digest::list]
    set test_data "integration test data"
    set successful_tests 0
    
    ;# Test a few algorithms from the list
    set alg_test_count 0
    foreach alg $algorithms {
        if {$alg_test_count >= 5} break ;# Limit to first 5 algorithms
        
        if {[catch {
            set hash [::tossl::digest -alg $alg $test_data]
            assert_true [expr {[string length $hash] > 0}] "Hash should not be empty for $alg"
            incr successful_tests
        }]} {
            puts "  Warning: Algorithm '$alg' failed integration test"
        }
        incr alg_test_count
    }
    
    assert_true [expr {$successful_tests > 0}] "Should have at least some successful integration tests"
    puts "  Successfully tested $successful_tests algorithms"
}

;# Test 12: Verify list characteristics
test "Verify list characteristics" {
    set algorithms [::tossl::digest::list]
    
    ;# Check that we have a reasonable number of algorithms
    set length [llength $algorithms]
    assert_true [expr {$length >= 5}] "Should have at least 5 digest algorithms"
    assert_true [expr {$length <= 100}] "Should have reasonable number of algorithms (<=100)"
    
    ;# Check that all algorithms are unique
    set unique_count [llength [lsort -unique $algorithms]]
    assert_equals $length $unique_count "All algorithms should be unique"
    
    puts "  List contains $length unique algorithms"
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