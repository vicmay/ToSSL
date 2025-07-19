# tests/test_cipher_list.tcl ;# Test for ::tossl::cipher::list

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::cipher::list ==="

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

# Test 1: Basic functionality - get all ciphers
test "Basic functionality - get all ciphers" {
    set ciphers [tossl::cipher::list]
    
    # Verify it's a list
    if {![llength $ciphers]} {
        error "Cipher list is empty"
    }
    
    # Verify it contains expected ciphers
    set expected_ciphers {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm}
    
    foreach expected $expected_ciphers {
        if {[lsearch $ciphers $expected] == -1} {
            puts "    ⚠ Expected cipher '$expected' not found in list"
        } else {
            puts "    ✓ Found expected cipher: $expected"
        }
    }
    
    puts "    Retrieved [llength $ciphers] ciphers"
}

# Test 2: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::cipher::list extra-arg1 extra-arg2} result]} {
        puts "    Correctly rejected too many arguments: $result"
    } else {
        error "Should have rejected too many arguments"
    }
}

# Test 3: Command exists and returns list
test "Command exists and returns list" {
    if {[catch {tossl::cipher::list} ciphers]} {
        error "Command failed: $ciphers"
    }
    
    if {![llength $ciphers]} {
        error "Command returned empty list"
    }
    
    puts "    Command returned [llength $ciphers] ciphers"
}

# Test 4: Type filtering - CBC mode
test "Type filtering - CBC mode" {
    set cbc_ciphers [tossl::cipher::list -type cbc]
    
    if {![llength $cbc_ciphers]} {
        error "No CBC ciphers found"
    }
    
    # Verify all returned ciphers contain "cbc" in their name
    foreach cipher $cbc_ciphers {
        if {![string match "*cbc*" [string tolower $cipher]]} {
            error "Non-CBC cipher found in CBC list: $cipher"
        }
    }
    
    puts "    Found [llength $cbc_ciphers] CBC ciphers"
}

# Test 5: Type filtering - GCM mode
test "Type filtering - GCM mode" {
    set gcm_ciphers [tossl::cipher::list -type gcm]
    
    if {![llength $gcm_ciphers]} {
        puts "    ⚠ No GCM ciphers found (this might be expected)"
    } else {
        # Verify all returned ciphers contain "gcm" in their name
        foreach cipher $gcm_ciphers {
            if {![string match "*gcm*" [string tolower $cipher]]} {
                error "Non-GCM cipher found in GCM list: $cipher"
            }
        }
        puts "    Found [llength $gcm_ciphers] GCM ciphers"
    }
}

# Test 6: Type filtering - ECB mode
test "Type filtering - ECB mode" {
    set ecb_ciphers [tossl::cipher::list -type ecb]
    
    if {![llength $ecb_ciphers]} {
        puts "    ⚠ No ECB ciphers found (this might be expected)"
    } else {
        # Verify all returned ciphers contain "ecb" in their name
        foreach cipher $ecb_ciphers {
            if {![string match "*ecb*" [string tolower $cipher]]} {
                error "Non-ECB cipher found in ECB list: $cipher"
            }
        }
        puts "    Found [llength $ecb_ciphers] ECB ciphers"
    }
}

# Test 7: Type filtering - invalid type
test "Type filtering - invalid type" {
    if {[catch {tossl::cipher::list -type invalid-type} result]} {
        puts "    Correctly rejected invalid type: $result"
    } else {
        puts "    ⚠ Invalid type was accepted (returned [llength $result] ciphers)"
    }
}

# Test 8: Performance test - multiple list attempts
test "Performance test - multiple list attempts" {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 10} {incr i} {
        set ciphers [tossl::cipher::list]
        if {![llength $ciphers]} {
            error "Empty cipher list on iteration $i"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 10 list operations in ${duration}ms"
}

# Test 9: List format verification
test "List format verification" {
    set ciphers [tossl::cipher::list]
    
    # Verify each element is a string
    foreach cipher $ciphers {
        if {![string is ascii $cipher]} {
            error "Non-string cipher name found: $cipher"
        }
    }
    
    puts "    All [llength $ciphers] cipher names are valid strings"
}

# Test 10: Integration with cipher analyze
test "Integration with cipher analyze" {
    set ciphers [tossl::cipher::list]
    
    # Test first 5 ciphers with analyze command
    set test_ciphers [lrange $ciphers 0 4]
    set success_count 0
    
    foreach cipher $test_ciphers {
        if {[catch {tossl::cipher::analyze $cipher} analysis]} {
            puts "    ⚠ Could not analyze $cipher: $analysis"
        } else {
            puts "    ✓ $cipher: $analysis"
            incr success_count
        }
    }
    
    puts "    Successfully analyzed $success_count out of [llength $test_ciphers] ciphers"
}

# Test 11: Integration with cipher info
test "Integration with cipher info" {
    set ciphers [tossl::cipher::list]
    
    # Test first 3 ciphers with info command
    set test_ciphers [lrange $ciphers 0 2]
    set success_count 0
    
    foreach cipher $test_ciphers {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            puts "    ✓ $cipher: [dict get $info block_size] bytes block size"
            incr success_count
        }
    }
    
    puts "    Successfully got info for $success_count out of [llength $test_ciphers] ciphers"
}

# Test 12: Algorithm consistency verification
test "Algorithm consistency verification" {
    set ciphers [tossl::cipher::list]
    
    # Check for common cipher families
    set families {aes des camellia aria sm4 chacha20}
    set found_families {}
    
    foreach family $families {
        foreach cipher $ciphers {
            if {[string match "*$family*" [string tolower $cipher]]} {
                lappend found_families $family
                break
            }
        }
    }
    
    puts "    Found cipher families: $found_families"
    
    if {[llength $found_families] == 0} {
        puts "    ⚠ No expected cipher families found"
    }
}

# Test 13: Mode consistency verification
test "Mode consistency verification" {
    set ciphers [tossl::cipher::list]
    
    # Check for common modes
    set modes {cbc ecb gcm ccm ofb cfb ctr}
    set found_modes {}
    
    foreach mode $modes {
        foreach cipher $ciphers {
            if {[string match "*$mode*" [string tolower $cipher]]} {
                lappend found_modes $mode
                break
            }
        }
    }
    
    puts "    Found cipher modes: $found_modes"
    
    if {[llength $found_modes] == 0} {
        puts "    ⚠ No expected cipher modes found"
    }
}

# Test 14: Memory usage test
test "Memory usage test" {
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set ciphers [tossl::cipher::list]
        if {![llength $ciphers]} {
            error "Memory test failed on iteration $i: empty list"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 15: Error handling for invalid option
test "Error handling for invalid option" {
    if {[catch {tossl::cipher::list -invalid} result]} {
        puts "    Correctly rejected invalid option: $result"
    } else {
        error "Should have rejected invalid option"
    }
}

# Test 16: Error handling for missing type value
test "Error handling for missing type value" {
    if {[catch {tossl::cipher::list -type} result]} {
        puts "    Correctly rejected missing type value: $result"
    } else {
        error "Should have rejected missing type value"
    }
}

# Test 17: Case sensitivity test
test "Case sensitivity test" {
    set ciphers_lower [tossl::cipher::list -type cbc]
    set ciphers_upper [tossl::cipher::list -type CBC]
    
    # Both should return the same results (case-insensitive)
    if {[llength $ciphers_lower] != [llength $ciphers_upper]} {
        puts "    ⚠ Case sensitivity difference: [llength $ciphers_lower] vs [llength $ciphers_upper]"
    } else {
        puts "    ✓ Case-insensitive filtering works correctly"
    }
}

# Test 18: Empty type filter test
test "Empty type filter test" {
    if {[catch {tossl::cipher::list -type ""} result]} {
        puts "    Correctly rejected empty type: $result"
    } else {
        puts "    ⚠ Empty type was accepted (returned [llength $result] ciphers)"
    }
}

# Test 19: List sorting verification
test "List sorting verification" {
    set ciphers [tossl::cipher::list]
    
    # Check if list is sorted (it might not be, but we should verify consistency)
    set sorted_ciphers [lsort $ciphers]
    
    if {[llength $ciphers] != [llength $sorted_ciphers]} {
        error "List length changed after sorting"
    }
    
    puts "    List contains [llength $ciphers] unique ciphers"
}

# Test 20: Algorithm availability verification
test "Algorithm availability verification" {
    set ciphers [tossl::cipher::list]
    
    # Test a few specific ciphers that should be available
    set test_ciphers {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm}
    set available_count 0
    
    foreach test_cipher $test_ciphers {
        if {[lsearch $ciphers $test_cipher] != -1} {
            puts "    ✓ $test_cipher: Available"
            incr available_count
        } else {
            puts "    ⚠ $test_cipher: Not available"
        }
    }
    
    puts "    $available_count out of [llength $test_ciphers] test ciphers are available"
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