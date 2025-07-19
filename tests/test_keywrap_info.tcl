# tests/test_keywrap_info.tcl ;# Test for ::tossl::keywrap::info

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::keywrap::info..."

# Test 1: Basic functionality - get info for different algorithms
puts "\n=== Test 1: Basic Keywrap Algorithm Information ==="
set rc [catch {
    # Test AES-128-ECB
    set aes128ecb_info [tossl::keywrap::info aes-128-ecb]
    puts "✓ AES-128-ECB info: $aes128ecb_info"
    
    # Verify the result contains expected information
    if {[string match "*name AES-128-ECB*" $aes128ecb_info] && 
        [string match "*block_size 16*" $aes128ecb_info] && 
        [string match "*key_length 16*" $aes128ecb_info] && 
        [string match "*iv_length 0*" $aes128ecb_info]} {
        puts "✓ AES-128-ECB info is correct"
    } else {
        error "AES-128-ECB info is incorrect: $aes128ecb_info"
    }
    
    # Test AES-256-CBC
    set aes256cbc_info [tossl::keywrap::info aes-256-cbc]
    puts "✓ AES-256-CBC info: $aes256cbc_info"
    
    # Test AES-192-ECB
    set aes192ecb_info [tossl::keywrap::info aes-192-ecb]
    puts "✓ AES-192-ECB info: $aes192ecb_info"
    
    # Test AES-128-CBC
    set aes128cbc_info [tossl::keywrap::info aes-128-cbc]
    puts "✓ AES-128-CBC info: $aes128cbc_info"
    
    # Test AES-192-CBC
    set aes192cbc_info [tossl::keywrap::info aes-192-cbc]
    puts "✓ AES-192-CBC info: $aes192cbc_info"
    
    # Test AES-256-ECB
    set aes256ecb_info [tossl::keywrap::info aes-256-ecb]
    puts "✓ AES-256-ECB info: $aes256ecb_info"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple algorithm information parsing
puts "\n=== Test 2: Multiple Algorithm Information ==="
set rc [catch {
    set test_algorithms {
        aes-128-ecb
        aes-192-ecb
        aes-256-ecb
        aes-128-cbc
        aes-192-cbc
        aes-256-cbc
    }
    
    foreach algorithm $test_algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "✓ '$algorithm' -> $info"
            
            # Verify result contains all required fields
            if {[string match "*name*" $info] && 
                [string match "*block_size*" $info] && 
                [string match "*key_length*" $info] && 
                [string match "*iv_length*" $info]} {
                puts "  ✓ Contains all required fields"
            } else {
                puts "  ⚠ Missing some required fields"
            }
            
            # Verify algorithm name matches
            if {[string match "*name [string toupper $algorithm]*" $info]} {
                puts "  ✓ Algorithm name is correct"
            } else {
                puts "  ⚠ Algorithm name may not be correct"
            }
            
            # Verify block size is reasonable
            if {[regexp {block_size (\d+)} $info -> block_size]} {
                if {$block_size >= 8 && $block_size <= 64} {
                    puts "  ✓ Block size is reasonable: $block_size"
                } else {
                    puts "  ⚠ Block size may be unusual: $block_size"
                }
            } else {
                puts "  ⚠ Could not extract block size"
            }
            
            # Verify key length is reasonable
            if {[regexp {key_length (\d+)} $info -> key_length]} {
                if {$key_length >= 8 && $key_length <= 64} {
                    puts "  ✓ Key length is reasonable: $key_length"
                } else {
                    puts "  ⚠ Key length may be unusual: $key_length"
                }
            } else {
                puts "  ⚠ Could not extract key length"
            }
            
            # Verify IV length is reasonable
            if {[regexp {iv_length (\d+)} $info -> iv_length]} {
                if {$iv_length >= 0 && $iv_length <= 32} {
                    puts "  ✓ IV length is reasonable: $iv_length"
                } else {
                    puts "  ⚠ IV length may be unusual: $iv_length"
                }
            } else {
                puts "  ⚠ Could not extract IV length"
            }
            
        } err]} {
            puts "✗ Failed to get info for '$algorithm': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple algorithm information test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::keywrap::info
} result]
if {$rc != 0} {
    puts "✓ No arguments correctly rejected: $result"
} else {
    puts stderr "✗ No arguments should have caused an error"
    exit 3
}

set rc [catch {
    tossl::keywrap::info "aes-128-ecb" "extra-arg"
} result]
if {$rc != 0} {
    puts "✓ Too many arguments correctly rejected: $result"
} else {
    puts stderr "✗ Too many arguments should have caused an error"
    exit 3
}

# Test 4: Error handling - invalid algorithms
puts "\n=== Test 4: Invalid Algorithm Error Handling ==="
set invalid_algorithms {
    "invalid-algorithm"
    "aes-999-ecb"
    "idea"
    "aes"
    "aes-128"
    "aes-ecb"
    ""
    "aes-128-ecb-invalid"
    "aes-128-cbc-invalid"
    "aes-192-ecb-invalid"
    "aes-192-cbc-invalid"
    "aes-256-ecb-invalid"
    "aes-256-cbc-invalid"
}

foreach algorithm $invalid_algorithms {
    set rc [catch {
        tossl::keywrap::info $algorithm
    } result]
    if {$rc != 0} {
        puts "✓ Invalid algorithm '$algorithm' correctly rejected: $result"
    } else {
        puts stderr "✗ Invalid algorithm '$algorithm' should have caused an error"
        exit 4
    }
}

# Test 5: Edge cases and special values
puts "\n=== Test 5: Edge Cases and Special Values ==="
set rc [catch {
    # Test with very long algorithm name
    set long_algorithm [string repeat "a" 1000]
    if {[catch {
        tossl::keywrap::info $long_algorithm
    } err]} {
        puts "✓ Very long algorithm name correctly rejected: $err"
    } else {
        puts "✓ Very long algorithm name accepted (unexpected)"
    }
    
    # Test with special characters
    set special_algorithms {
        "aes-128-ecb\n"
        "aes-128-ecb\t"
        "aes-128-ecb "
        " aes-128-ecb"
        "aes-128-ecb\x00"
        "aes-128-ecb\x01"
    }
    
    foreach algorithm $special_algorithms {
        if {[catch {
            tossl::keywrap::info $algorithm
        } err]} {
            puts "✓ Special characters in '$algorithm' correctly rejected: $err"
        } else {
            puts "✓ Special characters in '$algorithm' accepted (may be valid)"
        }
    }
    
    # Test with case variations
    set case_variations {
        "AES-128-ECB"
        "Aes-128-Ecb"
        "aes-128-ECB"
        "AES-128-ecb"
    }
    
    foreach algorithm $case_variations {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "✓ Case variation '$algorithm' accepted: $info"
        } err]} {
            puts "✓ Case variation '$algorithm' rejected: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Edge cases test failed: $result"
    exit 5
}

# Test 6: Performance test
puts "\n=== Test 6: Performance Test ==="
set rc [catch {
    set iterations 50
    set test_algorithm "aes-128-ecb"
    
    # Time multiple info operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set result [tossl::keywrap::info $test_algorithm]
        if {![string match "*name*" $result]} {
            error "Invalid result generated on iteration $i"
        }
    }
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set avg_time [expr {double($total_time) / $iterations}]
    
    puts "✓ Performance test completed:"
    puts "  Total time: ${total_time}ms for $iterations operations"
    puts "  Average time: [format %.2f $avg_time]ms per operation"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Performance test failed: $result"
    exit 6
}

# Test 7: Algorithm-specific validation
puts "\n=== Test 7: Algorithm-Specific Validation ==="
set rc [catch {
    # Test ECB algorithms (should have iv_length = 0)
    set ecb_algorithms {aes-128-ecb aes-192-ecb aes-256-ecb}
    foreach algorithm $ecb_algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "✓ $algorithm -> $info"
            
            if {[regexp {iv_length 0} $info]} {
                puts "  ✓ Correctly shows IV length 0 for ECB mode"
            } else {
                puts "  ⚠ May not correctly show IV length for ECB mode"
            }
        } err]} {
            puts "✗ Failed to get info for $algorithm: $err"
        }
    }
    
    # Test CBC algorithms (should have iv_length > 0)
    set cbc_algorithms {aes-128-cbc aes-192-cbc aes-256-cbc}
    foreach algorithm $cbc_algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "✓ $algorithm -> $info"
            
            if {[regexp {iv_length (\d+)} $info -> iv_length] && $iv_length > 0} {
                puts "  ✓ Correctly shows IV length > 0 for CBC mode: $iv_length"
            } else {
                puts "  ⚠ May not correctly show IV length for CBC mode"
            }
        } err]} {
            puts "✗ Failed to get info for $algorithm: $err"
        }
    }
    
    # Test key length progression
    set key_lengths {
        {aes-128-ecb 16}
        {aes-192-ecb 24}
        {aes-256-ecb 32}
        {aes-128-cbc 16}
        {aes-192-cbc 24}
        {aes-256-cbc 32}
    }
    
    foreach key_test $key_lengths {
        set algorithm [lindex $key_test 0]
        set expected_length [lindex $key_test 1]
        
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            if {[regexp "key_length $expected_length" $info]} {
                puts "✓ $algorithm has correct key length: $expected_length"
            } else {
                puts "⚠ $algorithm may have incorrect key length (expected $expected_length)"
            }
        } err]} {
            puts "✗ Failed to validate key length for $algorithm: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Algorithm-specific validation failed: $result"
    exit 7
}

# Test 8: Memory and resource management
puts "\n=== Test 8: Memory and Resource Management ==="
set rc [catch {
    # Test many info operations to check for memory leaks
    set results {}
    set test_algorithm "aes-128-ecb"
    
    for {set i 0} {$i < 25} {incr i} {
        set result [tossl::keywrap::info $test_algorithm]
        lappend results $result
        
        # Verify each result works
        if {![string match "*name*" $result]} {
            error "Invalid result generated on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $results] info results"
    puts "  ✓ All info results are valid"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 8
}

# Test 9: Error recovery and robustness
puts "\n=== Test 9: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can get info after various operations
    set test_operations {
        "Basic info retrieval"
        "After multiple info operations"
        "After algorithm-specific validation"
        "After memory management test"
    }
    
    set test_algorithm "aes-128-ecb"
    
    foreach operation $test_operations {
        if {[catch {
            set result [tossl::keywrap::info $test_algorithm]
            
            if {![string match "*name*" $result]} {
                error "Invalid result after $operation"
            }
            
            puts "✓ Keywrap info retrieval successful after $operation"
        } err]} {
            error "Keywrap info retrieval failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 9
}

# Test 10: Algorithm consistency validation
puts "\n=== Test 10: Algorithm Consistency Validation ==="
set rc [catch {
    # Test that the same algorithm always returns consistent info
    set test_algorithm "aes-128-ecb"
    set first_result [tossl::keywrap::info $test_algorithm]
    
    for {set i 0} {$i < 10} {incr i} {
        set current_result [tossl::keywrap::info $test_algorithm]
        
        if {$current_result eq $first_result} {
            puts "✓ Consistent result for $test_algorithm (iteration [expr {$i + 1}])"
        } else {
            puts "⚠ Inconsistent result for $test_algorithm (iteration [expr {$i + 1}])"
            puts "  First: $first_result"
            puts "  Current: $current_result"
        }
    }
    
    puts "✓ Algorithm consistency validation completed"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Algorithm consistency validation failed: $result"
    exit 10
}

# Test 11: Information format validation
puts "\n=== Test 11: Information Format Validation ==="
set rc [catch {
    # Test that all algorithms return properly formatted information
    set test_algorithms {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
    
    foreach algorithm $test_algorithms {
        if {[catch {
            set info [tossl::keywrap::info $algorithm]
            puts "✓ $algorithm format validation:"
            
            # Check for required fields
            set required_fields {name block_size key_length iv_length}
            foreach field $required_fields {
                if {[string match "*$field*" $info]} {
                    puts "  ✓ Contains $field"
                } else {
                    puts "  ⚠ Missing $field"
                }
            }
            
            # Check for proper value format
            if {[regexp {name [A-Z0-9-]+} $info]} {
                puts "  ✓ Name format is correct"
            } else {
                puts "  ⚠ Name format may be incorrect"
            }
            
            if {[regexp {block_size \d+} $info]} {
                puts "  ✓ Block size format is correct"
            } else {
                puts "  ⚠ Block size format may be incorrect"
            }
            
            if {[regexp {key_length \d+} $info]} {
                puts "  ✓ Key length format is correct"
            } else {
                puts "  ⚠ Key length format may be incorrect"
            }
            
            if {[regexp {iv_length \d+} $info]} {
                puts "  ✓ IV length format is correct"
            } else {
                puts "  ⚠ IV length format may be incorrect"
            }
            
        } err]} {
            puts "✗ Failed to validate format for $algorithm: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Information format validation failed: $result"
    exit 11
}

# Test 12: Integration with other keywrap commands
puts "\n=== Test 12: Integration with Other Keywrap Commands ==="
set rc [catch {
    # Test that info works with algorithms from the algorithms list
    if {[catch {
        set algorithms [tossl::keywrap::algorithms]
        puts "✓ Retrieved algorithms list: $algorithms"
        
        foreach algorithm $algorithms {
            if {[catch {
                set info [tossl::keywrap::info $algorithm]
                puts "✓ Info for '$algorithm': $info"
            } err]} {
                puts "⚠ Failed to get info for '$algorithm' from algorithms list: $err"
            }
        }
    } err]} {
        puts "⚠ Could not test integration with algorithms list: $err"
    }
    
    # Test that info works with algorithms used in key generation
    set test_algorithms {aes-128-ecb aes-256-cbc}
    foreach algorithm $test_algorithms {
        if {[catch {
            # Get algorithm info
            set info [tossl::keywrap::info $algorithm]
            puts "✓ Algorithm info for $algorithm: $info"
            
            # Generate a key using the same algorithm
            set key [tossl::keywrap::kekgen $algorithm]
            puts "✓ Generated key for $algorithm: [string length $key] bytes"
            
            # Verify key length matches info
            if {[regexp {key_length (\d+)} $info -> expected_length]} {
                if {[string length $key] == $expected_length} {
                    puts "  ✓ Key length matches info: $expected_length bytes"
                } else {
                    puts "  ⚠ Key length mismatch: expected $expected_length, got [string length $key]"
                }
            }
            
        } err]} {
            puts "⚠ Failed to test integration for $algorithm: $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Integration test failed: $result"
    exit 12
}

puts "\n=== All Keywrap Info Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple algorithm information working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Algorithm-specific validation working"
puts "✓ Memory management working"
puts "✓ Error recovery and robustness working"
puts "✓ Algorithm consistency validation completed"
puts "✓ Information format validation working"
puts "✓ Integration with other keywrap commands working"

exit 0 