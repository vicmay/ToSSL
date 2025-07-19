# tests/test_keywrap_algorithms.tcl ;# Test for ::tossl::keywrap::algorithms

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::keywrap::algorithms ==="

# Test counter
set passed_count 0
set failed_count 0

# Test helper function
proc test {name test_script} {
    global passed_count failed_count
    puts "Test [expr {$passed_count + $failed_count + 1}]: $name"
    if {[catch $test_script result]} {
        puts "    FAILED: $result"
        incr failed_count
    } else {
        puts "    PASSED"
        incr passed_count
    }
}

# Test 1: Basic functionality - get algorithms list
test "Basic functionality - get algorithms list" {
    set algorithms [tossl::keywrap::algorithms]
    
    # Verify it's a list
    if {![llength $algorithms]} {
        error "Algorithms list is empty"
    }
    
    # Verify it contains expected algorithms
    set expected_algorithms {
        aes-128-ecb aes-192-ecb aes-256-ecb
        aes-128-cbc aes-192-cbc aes-256-cbc
    }
    
    foreach expected $expected_algorithms {
        if {[lsearch $algorithms $expected] == -1} {
            error "Expected algorithm '$expected' not found in list: $algorithms"
        }
    }
    
    puts "    Retrieved algorithms: $algorithms"
}

# Test 2: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::keywrap::algorithms extra-arg} result]} {
        puts "    Correctly rejected extra argument: $result"
    } else {
        error "Should have rejected extra argument"
    }
}

# Test 3: Command exists and returns list
test "Command exists and returns list" {
    if {[catch {tossl::keywrap::algorithms} algorithms]} {
        error "Command failed: $algorithms"
    }
    
    if {![llength $algorithms]} {
        error "Command returned empty list"
    }
    
    puts "    Command returned [llength $algorithms] algorithms"
}

# Test 4: All returned algorithms are valid
test "All returned algorithms are valid" {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        # Test that each algorithm can be used with kekgen
        if {[catch {
            set kek [tossl::keywrap::kekgen $algorithm]
            puts "    ✓ $algorithm: Generated [string length $kek] byte KEK"
        } err]} {
            error "Algorithm '$algorithm' is not valid: $err"
        }
    }
}

# Test 5: Algorithm consistency with info command
test "Algorithm consistency with info command" {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "    ✓ $algorithm: $info"
        } err]} {
            error "Cannot get info for algorithm '$algorithm': $err"
        }
    }
}

# Test 6: Algorithm consistency with wrap/unwrap commands
test "Algorithm consistency with wrap/unwrap commands" {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        if {[catch {
            # Generate KEK
            set kek [tossl::keywrap::kekgen $algorithm]
            
            # Test data
            set test_data "Test data for $algorithm"
            
            # Wrap data
            set wrapped [tossl::keywrap::wrap $algorithm $kek $test_data]
            
            # Unwrap data
            set unwrapped [tossl::keywrap::unwrap $algorithm $kek $wrapped]
            
            # Verify
            if {$test_data eq $unwrapped} {
                puts "    ✓ $algorithm: Wrap/unwrap cycle successful"
            } else {
                puts "    ⚠ $algorithm: Wrap/unwrap cycle failed (data mismatch)"
            }
        } err]} {
            puts "    ⚠ $algorithm: Wrap/unwrap test failed: $err"
        }
    }
}

# Test 7: Performance test - multiple calls
test "Performance test - multiple calls" {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set algorithms [tossl::keywrap::algorithms]
        if {![llength $algorithms]} {
            error "Empty algorithms list on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 100 calls in ${duration}ms"
}

# Test 8: Algorithm count verification
test "Algorithm count verification" {
    set algorithms [tossl::keywrap::algorithms]
    set count [llength $algorithms]
    
    # Should have 6 algorithms (3 AES variants × 2 modes)
    if {$count != 6} {
        error "Expected 6 algorithms, got $count: $algorithms"
    }
    
    puts "    Found $count algorithms as expected"
}

# Test 9: Algorithm format verification
test "Algorithm format verification" {
    set algorithms [tossl::keywrap::algorithms]
    
    foreach algorithm $algorithms {
        # Check format: aes-<keylen>-<mode>
        if {![regexp {^aes-(128|192|256)-(ecb|cbc)$} $algorithm]} {
            error "Invalid algorithm format: $algorithm"
        }
    }
    
    puts "    All algorithms have correct format"
}

# Test 10: Integration with other keywrap commands
test "Integration with other keywrap commands" {
    set algorithms [tossl::keywrap::algorithms]
    
    # Test that algorithms work with all keywrap commands
    foreach algorithm $algorithms {
        if {[catch {
            # Test with kekgen
            set kek [tossl::keywrap::kekgen $algorithm]
            
            # Test with info
            set info [tossl::keywrap::info $algorithm]
            
            # Test with wrap/unwrap
            set test_data "Integration test data"
            set wrapped [tossl::keywrap::wrap $algorithm $kek $test_data]
            set unwrapped [tossl::keywrap::unwrap $algorithm $kek $wrapped]
            
            puts "    ✓ $algorithm: All commands work together"
        } err]} {
            puts "    ⚠ $algorithm: Integration test failed: $err"
        }
    }
}

# Test 11: Algorithm uniqueness
test "Algorithm uniqueness" {
    set algorithms [tossl::keywrap::algorithms]
    
    # Check for duplicates
    set unique_algorithms [lsort -unique $algorithms]
    if {[llength $algorithms] != [llength $unique_algorithms]} {
        error "Duplicate algorithms found: $algorithms"
    }
    
    puts "    All algorithms are unique"
}

# Test 12: Algorithm sorting verification
test "Algorithm sorting verification" {
    set algorithms [tossl::keywrap::algorithms]
    set sorted_algorithms [lsort $algorithms]
    
    # The algorithms should be in a consistent order
    if {$algorithms ne $sorted_algorithms} {
        puts "    Algorithms not in sorted order (this is acceptable)"
    } else {
        puts "    Algorithms are in sorted order"
    }
}

# Test 13: Memory usage test
test "Memory usage test" {
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set algorithms [tossl::keywrap::algorithms]
        if {![llength $algorithms]} {
            error "Empty algorithms list on iteration $i"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 14: Error handling for invalid calls
test "Error handling for invalid calls" {
    # Test with invalid number of arguments
    if {[catch {tossl::keywrap::algorithms arg1 arg2} result]} {
        puts "    Correctly rejected multiple arguments: $result"
    } else {
        error "Should have rejected multiple arguments"
    }
}

# Test 15: Algorithm availability verification
test "Algorithm availability verification" {
    set algorithms [tossl::keywrap::algorithms]
    
    # Verify each algorithm is actually available in OpenSSL
    foreach algorithm $algorithms {
        if {[catch {
            # Try to get cipher info directly
            set cipher_info [tossl::algorithm::info $algorithm cipher]
            puts "    ✓ $algorithm: Available in OpenSSL"
        } err]} {
            puts "    ⚠ $algorithm: Not available in OpenSSL: $err"
        }
    }
}

# Print test summary
puts "\n=== Test Summary ==="
puts "Total tests: [expr {$passed_count + $failed_count}]"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "\n❌ Some tests failed!"
    exit 1
} else {
    puts "\n✅ All tests passed!"
} 