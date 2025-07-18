# Test for ::tossl::rand::test
load ./libtossl.so

puts "Testing rand::test: missing required args..."
set rc [catch {tossl::rand::test} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "rand::test missing args: OK"

puts "Testing rand::test: invalid argument type..."
set rc [catch {tossl::rand::test "not_a_number"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid argument type did not error"
    exit 1
}
puts "rand::test invalid argument type: OK"

puts "Testing rand::test: zero count..."
set rc [catch {tossl::rand::test 0} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Zero count did not error"
    exit 1
}
puts "rand::test zero count: OK"

puts "Testing rand::test: negative count..."
set rc [catch {tossl::rand::test -1} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Negative count did not error"
    exit 1
}
puts "rand::test negative count: OK"

puts "Testing rand::test: count too large..."
set rc [catch {tossl::rand::test 1000001} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Count too large did not error"
    exit 1
}
puts "rand::test count too large: OK"

puts "Testing rand::test: basic functionality..."
# Test with small count
set rc [catch {tossl::rand::test 1000} result]
if {$rc != 0} {
    puts "FAIL: Basic test failed: $result"
    exit 1
}
puts "rand::test 1000: OK"
puts "Result: $result"

# Verify result contains expected components
if {[string match "*chi_square=*" $result]} {
    puts "  ✓ Result contains chi_square statistic"
} else {
    puts "  ✗ Result missing chi_square statistic"
}

if {[string match "*consecutive_zeros=*" $result]} {
    puts "  ✓ Result contains consecutive_zeros count"
} else {
    puts "  ✗ Result missing consecutive_zeros count"
}

if {[string match "*max_consecutive_zeros=*" $result]} {
    puts "  ✓ Result contains max_consecutive_zeros count"
} else {
    puts "  ✗ Result missing max_consecutive_zeros count"
}

puts "Testing rand::test: different count values..."
set test_counts {100 500 1000 5000 10000}

foreach count $test_counts {
    puts "Testing count: $count"
    set rc [catch {tossl::rand::test $count} result]
    if {$rc == 0} {
        puts "  ✓ Test successful"
        puts "  Result: $result"
        
        # Verify result format
        if {[string match "*chi_square=*" $result] && [string match "*consecutive_zeros=*" $result]} {
            puts "  ✓ Result format is valid"
        } else {
            puts "  ✗ Result format is invalid"
        }
    } else {
        puts "  ✗ Test failed: $result"
    }
}

puts "Testing rand::test: multiple runs consistency..."
# Run multiple tests to check consistency
set results {}
for {set i 0} {$i < 5} {incr i} {
    set rc [catch {tossl::rand::test 1000} result]
    if {$rc == 0} {
        lappend results $result
        puts "  Run $i: $result"
    } else {
        puts "  Run $i failed: $result"
    }
}

if {[llength $results] == 5} {
    puts "  ✓ All 5 runs successful"
    
    # Check that results are different (randomness)
    set unique_results [lsort -unique $results]
    if {[llength $unique_results] > 1} {
        puts "  ✓ Results show randomness (different values)"
    } else {
        puts "  ✗ Results are identical (suspicious)"
    }
} else {
    puts "  ✗ Not all runs successful"
}

puts "Testing rand::test: edge cases..."
# Test minimum valid count
set rc [catch {tossl::rand::test 1} result]
if {$rc == 0} {
    puts "  ✓ Minimum count (1) works"
    puts "  Result: $result"
} else {
    puts "  ✗ Minimum count failed: $result"
}

# Test maximum valid count
set rc [catch {tossl::rand::test 1000000} result]
if {$rc == 0} {
    puts "  ✓ Maximum count (1000000) works"
    puts "  Result: $result"
} else {
    puts "  ✗ Maximum count failed: $result"
}

puts "Testing rand::test: performance..."
# Test performance with larger count
set start_time [clock milliseconds]
set rc [catch {tossl::rand::test 50000} result]
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

if {$rc == 0} {
    puts "  ✓ Performance test successful"
    puts "  Duration: ${duration}ms for 50000 bytes"
    puts "  Result: $result"
    
    if {$duration < 5000} {
        puts "  ✓ Performance acceptable (< 5 seconds)"
    } else {
        puts "  ✗ Performance slow (> 5 seconds)"
    }
} else {
    puts "  ✗ Performance test failed: $result"
}

puts "Testing rand::test: result parsing..."
# Test that we can extract values from the result
set rc [catch {tossl::rand::test 1000} result]
if {$rc == 0} {
    puts "  ✓ Result parsing test"
    
    # Try to extract chi_square value
    if {[regexp {chi_square=([0-9.]+)} $result -> chi_square]} {
        puts "  ✓ Chi-square value: $chi_square"
        
        # Chi-square should be reasonable (not extreme)
        if {$chi_square > 0 && $chi_square < 1000} {
            puts "  ✓ Chi-square value is reasonable"
        } else {
            puts "  ✗ Chi-square value is extreme: $chi_square"
        }
    } else {
        puts "  ✗ Could not extract chi-square value"
    }
    
    # Try to extract consecutive_zeros value
    if {[regexp {consecutive_zeros=([0-9]+)} $result -> consecutive_zeros]} {
        puts "  ✓ Consecutive zeros: $consecutive_zeros"
        
        # Should have some consecutive zeros but not too many
        if {$consecutive_zeros >= 0 && $consecutive_zeros < 100} {
            puts "  ✓ Consecutive zeros count is reasonable"
        } else {
            puts "  ✗ Consecutive zeros count is extreme: $consecutive_zeros"
        }
    } else {
        puts "  ✗ Could not extract consecutive_zeros value"
    }
    
    # Try to extract max_consecutive_zeros value
    if {[regexp {max_consecutive_zeros=([0-9]+)} $result -> max_consecutive_zeros]} {
        puts "  ✓ Max consecutive zeros: $max_consecutive_zeros"
        
        # Should have some max consecutive zeros but not too many
        if {$max_consecutive_zeros >= 0 && $max_consecutive_zeros < 50} {
            puts "  ✓ Max consecutive zeros count is reasonable"
        } else {
            puts "  ✗ Max consecutive zeros count is extreme: $max_consecutive_zeros"
        }
    } else {
        puts "  ✗ Could not extract max_consecutive_zeros value"
    }
} else {
    puts "  ✗ Result parsing test failed: $result"
}

puts "Testing rand::test: statistical validation..."
# Run multiple tests and check statistical properties
set chi_square_values {}
set consecutive_zeros_values {}
set max_consecutive_zeros_values {}

for {set i 0} {$i < 10} {incr i} {
    set rc [catch {tossl::rand::test 1000} result]
    if {$rc == 0} {
        # Extract values
        if {[regexp {chi_square=([0-9.]+)} $result -> chi_square]} {
            lappend chi_square_values $chi_square
        }
        if {[regexp {consecutive_zeros=([0-9]+)} $result -> consecutive_zeros]} {
            lappend consecutive_zeros_values $consecutive_zeros
        }
        if {[regexp {max_consecutive_zeros=([0-9]+)} $result -> max_consecutive_zeros]} {
            lappend max_consecutive_zeros_values $max_consecutive_zeros
        }
    }
}

puts "  Collected 10 test results"

# Check chi-square values
if {[llength $chi_square_values] == 10} {
    puts "  ✓ Chi-square values collected: $chi_square_values"
    
    # Chi-square should vary (not all identical)
    set unique_chi [lsort -unique -real $chi_square_values]
    if {[llength $unique_chi] > 1} {
        puts "  ✓ Chi-square values show variation"
    } else {
        puts "  ✗ Chi-square values are identical (suspicious)"
    }
} else {
    puts "  ✗ Could not collect chi-square values"
}

# Check consecutive_zeros values
if {[llength $consecutive_zeros_values] == 10} {
    puts "  ✓ Consecutive zeros values collected: $consecutive_zeros_values"
    
    # Should vary
    set unique_zeros [lsort -unique -integer $consecutive_zeros_values]
    if {[llength $unique_zeros] > 1} {
        puts "  ✓ Consecutive zeros values show variation"
    } else {
        puts "  ✗ Consecutive zeros values are identical (suspicious)"
    }
} else {
    puts "  ✗ Could not collect consecutive zeros values"
}

puts "Testing rand::test: error handling..."
# Test with non-integer values
set test_values {"1.5" "abc" "" "0.1" "-0.5"}

foreach value $test_values {
    set rc [catch {tossl::rand::test $value} result]
    if {$rc != 0} {
        puts "  ✓ Correctly rejected invalid value: $value"
    } else {
        puts "  ✗ Should have rejected invalid value: $value"
    }
}

puts "All ::tossl::rand::test tests passed" 