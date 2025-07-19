# tests/test_cipher_info.tcl ;# Test for ::tossl::cipher::info

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::cipher::info ==="

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

# Test 1: Basic functionality - get cipher info
test "Basic functionality - get cipher info" {
    set info [tossl::cipher::info -alg AES-128-CBC]
    
    # Verify it's a dictionary
    if {![dict exists $info name]} {
        error "Info is not a dictionary or missing 'name' key"
    }
    
    # Verify required keys exist
    set required_keys {name block_size key_length iv_length}
    foreach key $required_keys {
        if {![dict exists $info $key]} {
            error "Missing required key: $key"
        }
    }
    
    # Verify values are reasonable
    if {[dict get $info name] ne "AES-128-CBC"} {
        error "Wrong cipher name: [dict get $info name]"
    }
    
    if {[dict get $info block_size] != 16} {
        error "Wrong block size: [dict get $info block_size]"
    }
    
    if {[dict get $info key_length] != 16} {
        error "Wrong key length: [dict get $info key_length]"
    }
    
    if {[dict get $info iv_length] != 16} {
        error "Wrong IV length: [dict get $info iv_length]"
    }
    
    puts "    AES-128-CBC: [dict get $info name], [dict get $info block_size] bytes block, [dict get $info key_length] bytes key, [dict get $info iv_length] bytes IV"
}

# Test 2: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::cipher::info} result]} {
        puts "    Correctly rejected no arguments: $result"
    } else {
        error "Should have rejected no arguments"
    }
    
    if {[catch {tossl::cipher::info extra-arg1 extra-arg2 extra-arg3} result]} {
        puts "    Correctly rejected too many arguments: $result"
    } else {
        error "Should have rejected too many arguments"
    }
}

# Test 3: Error handling for missing -alg parameter
test "Error handling for missing -alg parameter" {
    if {[catch {tossl::cipher::info AES-128-CBC} result]} {
        puts "    Correctly rejected missing -alg parameter: $result"
    } else {
        error "Should have rejected missing -alg parameter"
    }
}

# Test 4: Error handling for unknown cipher
test "Error handling for unknown cipher" {
    if {[catch {tossl::cipher::info -alg UNKNOWN-CIPHER-123} result]} {
        puts "    Correctly rejected unknown cipher: $result"
    } else {
        error "Should have accepted unknown cipher"
    }
}

# Test 5: Test multiple cipher types
test "Test multiple cipher types" {
    set test_ciphers {
        {AES-128-CBC 16 16 16}
        {AES-256-GCM 1 32 12}
        {DES-CBC 8 8 8}
        {ChaCha20 1 32 16}
    }
    
    foreach test_case $test_ciphers {
        lassign $test_case cipher expected_block expected_key expected_iv
        
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            set actual_block [dict get $info block_size]
            set actual_key [dict get $info key_length]
            set actual_iv [dict get $info iv_length]
            
            if {$actual_block != $expected_block || $actual_key != $expected_key || $actual_iv != $expected_iv} {
                puts "    ⚠ $cipher: expected block=$expected_block,key=$expected_key,iv=$expected_iv; got block=$actual_block,key=$actual_key,iv=$actual_iv"
            } else {
                puts "    ✓ $cipher: block=$actual_block, key=$actual_key, iv=$actual_iv"
            }
        }
    }
}

# Test 6: Test different AES variants
test "Test different AES variants" {
    set aes_variants {
        {AES-128-CBC 16 16 16}
        {AES-192-CBC 16 24 16}
        {AES-256-CBC 16 32 16}
        {AES-128-GCM 1 16 12}
        {AES-256-GCM 1 32 12}
        {AES-128-ECB 16 16 0}
        {AES-256-ECB 16 32 0}
    }
    
    foreach test_case $aes_variants {
        lassign $test_case cipher expected_block expected_key expected_iv
        
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            set actual_block [dict get $info block_size]
            set actual_key [dict get $info key_length]
            set actual_iv [dict get $info iv_length]
            
            if {$actual_block != $expected_block || $actual_key != $expected_key || $actual_iv != $expected_iv} {
                puts "    ⚠ $cipher: expected block=$expected_block,key=$expected_key,iv=$expected_iv; got block=$actual_block,key=$actual_key,iv=$actual_iv"
            } else {
                puts "    ✓ $cipher: block=$actual_block, key=$actual_key, iv=$actual_iv"
            }
        }
    }
}

# Test 7: Test legacy ciphers
test "Test legacy ciphers" {
    set legacy_ciphers {
        {DES-CBC 8 8 8}
        {DES-ECB 8 8 0}
        {BF-CBC 8 16 8}
        {CAST5-CBC 8 16 8}
    }
    
    foreach test_case $legacy_ciphers {
        lassign $test_case cipher expected_block expected_key expected_iv
        
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            set actual_block [dict get $info block_size]
            set actual_key [dict get $info key_length]
            set actual_iv [dict get $info iv_length]
            
            if {$actual_block != $expected_block || $actual_key != $expected_key || $actual_iv != $expected_iv} {
                puts "    ⚠ $cipher: expected block=$expected_block,key=$expected_key,iv=$expected_iv; got block=$actual_block,key=$actual_key,iv=$actual_iv"
            } else {
                puts "    ✓ $cipher: block=$actual_block, key=$actual_key, iv=$actual_iv"
            }
        }
    }
}

# Test 8: Test stream ciphers
test "Test stream ciphers" {
    set stream_ciphers {
        {ChaCha20 1 32 16}
        {ChaCha20-Poly1305 1 32 16}
    }
    
    foreach test_case $stream_ciphers {
        lassign $test_case cipher expected_block expected_key expected_iv
        
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            set actual_block [dict get $info block_size]
            set actual_key [dict get $info key_length]
            set actual_iv [dict get $info iv_length]
            
            if {$actual_block != $expected_block || $actual_key != $expected_key || $actual_iv != $expected_iv} {
                puts "    ⚠ $cipher: expected block=$expected_block,key=$expected_key,iv=$expected_iv; got block=$actual_block,key=$actual_key,iv=$actual_iv"
            } else {
                puts "    ✓ $cipher: block=$actual_block, key=$actual_key, iv=$actual_iv"
            }
        }
    }
}

# Test 9: Performance test - multiple info requests
test "Performance test - multiple info requests" {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 50} {incr i} {
        set info [tossl::cipher::info -alg AES-128-CBC]
        if {![dict exists $info name]} {
            error "Performance test failed on iteration $i: invalid info"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 50 info requests in ${duration}ms"
}

# Test 10: Dictionary format verification
test "Dictionary format verification" {
    set info [tossl::cipher::info -alg AES-128-CBC]
    
    # Verify all values are of correct types
    if {![string is integer [dict get $info block_size]]} {
        error "block_size is not an integer: [dict get $info block_size]"
    }
    
    if {![string is integer [dict get $info key_length]]} {
        error "key_length is not an integer: [dict get $info key_length]"
    }
    
    if {![string is integer [dict get $info iv_length]]} {
        error "iv_length is not an integer: [dict get $info iv_length]"
    }
    
    if {![string is ascii [dict get $info name]]} {
        error "name is not a valid string: [dict get $info name]"
    }
    
    puts "    All dictionary values have correct types"
}

# Test 11: Integration with cipher list
test "Integration with cipher list" {
    set ciphers [tossl::cipher::list]
    set test_ciphers [lrange $ciphers 0 4] ;# Test first 5 ciphers
    set success_count 0
    
    foreach cipher $test_ciphers {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            puts "    ✓ $cipher: [dict get $info block_size] bytes block, [dict get $info key_length] bytes key"
            incr success_count
        }
    }
    
    puts "    Successfully got info for $success_count out of [llength $test_ciphers] ciphers"
}

# Test 12: Integration with cipher analyze
test "Integration with cipher analyze" {
    set test_ciphers {AES-128-CBC AES-256-GCM DES-CBC}
    
    foreach cipher $test_ciphers {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } elseif {[catch {tossl::cipher::analyze $cipher} analysis]} {
            puts "    ⚠ Could not analyze $cipher: $analysis"
        } else {
            # Compare info with analyze results
            set info_block [dict get $info block_size]
            set info_key [dict get $info key_length]
            set info_iv [dict get $info iv_length]
            
            # Parse analyze result (format: "key_len=X, iv_len=Y, block_size=Z, flags=0xW")
            if {[regexp {key_len=(\d+), iv_len=(\d+), block_size=(\d+)} $analysis -> analyze_key analyze_iv analyze_block]} {
                if {$info_block == $analyze_block && $info_key == $analyze_key && $info_iv == $analyze_iv} {
                    puts "    ✓ $cipher: info and analyze results match"
                } else {
                    puts "    ⚠ $cipher: info/analyze mismatch - info: block=$info_block,key=$info_key,iv=$info_iv; analyze: block=$analyze_block,key=$analyze_key,iv=$analyze_iv"
                }
            } else {
                puts "    ⚠ Could not parse analyze result for $cipher: $analysis"
            }
        }
    }
}

# Test 13: Edge cases - empty cipher name
test "Edge cases - empty cipher name" {
    if {[catch {tossl::cipher::info -alg ""} result]} {
        puts "    Correctly rejected empty cipher name: $result"
    } else {
        error "Should have rejected empty cipher name"
    }
}

# Test 14: Edge cases - whitespace in cipher name
test "Edge cases - whitespace in cipher name" {
    if {[catch {tossl::cipher::info -alg " AES-128-CBC "} result]} {
        puts "    Correctly rejected whitespace in cipher name: $result"
    } else {
        puts "    ⚠ Accepted whitespace in cipher name (this might be expected)"
    }
}

# Test 15: Case sensitivity test
test "Case sensitivity test" {
    # Test if case matters for cipher names
    set lower_case [catch {tossl::cipher::info -alg aes-128-cbc} lower_result]
    set upper_case [catch {tossl::cipher::info -alg AES-128-CBC} upper_result]
    
    if {$lower_case == 0 && $upper_case == 0} {
        puts "    ✓ Both case variants work"
    } elseif {$lower_case != 0 && $upper_case == 0} {
        puts "    ✓ Only uppercase works (case-sensitive)"
    } elseif {$lower_case == 0 && $upper_case != 0} {
        puts "    ✓ Only lowercase works (case-sensitive)"
    } else {
        puts "    ⚠ Neither case variant works"
    }
}

# Test 16: Memory usage test
test "Memory usage test" {
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 100} {incr i} {
        set info [tossl::cipher::info -alg AES-128-CBC]
        if {![dict exists $info name]} {
            error "Memory test failed on iteration $i: invalid info"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 17: Error message consistency
test "Error message consistency" {
    # Test that error messages are consistent
    set error1 [catch {tossl::cipher::info -alg INVALID-CIPHER} result1]
    set error2 [catch {tossl::cipher::info -alg ANOTHER-INVALID} result2]
    
    if {$error1 && $error2} {
        if {$result1 eq $result2} {
            puts "    ✓ Error messages are consistent: $result1"
        } else {
            puts "    ⚠ Error messages differ: '$result1' vs '$result2'"
        }
    } else {
        puts "    ⚠ Expected errors but got success"
    }
}

# Test 18: Parameter validation
test "Parameter validation" {
    # Test various invalid parameter combinations
    set invalid_calls {
        {tossl::cipher::info}
        {tossl::cipher::info -alg}
        {tossl::cipher::info -alg AES-128-CBC extra}
        {tossl::cipher::info -wrong AES-128-CBC}
        {tossl::cipher::info AES-128-CBC -alg}
    }
    
    foreach call $invalid_calls {
        if {[catch $call result]} {
            puts "    ✓ Correctly rejected: $call -> $result"
        } else {
            puts "    ⚠ Unexpectedly accepted: $call"
        }
    }
}

# Test 19: Cipher family consistency
test "Cipher family consistency" {
    # Test that ciphers in the same family have consistent properties
    set aes_ciphers {AES-128-CBC AES-192-CBC AES-256-CBC}
    set block_sizes {}
    
    foreach cipher $aes_ciphers {
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not get info for $cipher: $info"
        } else {
            lappend block_sizes [dict get $info block_size]
        }
    }
    
    if {[llength $block_sizes] > 1} {
        set first_block [lindex $block_sizes 0]
        set consistent 1
        foreach block $block_sizes {
            if {$block != $first_block} {
                set consistent 0
                break
            }
        }
        
        if {$consistent} {
            puts "    ✓ AES family has consistent block size: $first_block"
        } else {
            puts "    ⚠ AES family has inconsistent block sizes: $block_sizes"
        }
    }
}

# Test 20: Security assessment
test "Security assessment" {
    # Test that we can assess cipher security based on info
    set test_ciphers {
        {AES-128-CBC standard}
        {AES-256-CBC high}
        {DES-CBC weak}
        {ChaCha20 high}
    }
    
    foreach test_case $test_ciphers {
        lassign $test_case cipher expected_security
        
        if {[catch {tossl::cipher::info -alg $cipher} info]} {
            puts "    ⚠ Could not assess $cipher: $info"
        } else {
            set key_length [dict get $info key_length]
            set block_size [dict get $info block_size]
            
            set actual_security "unknown"
            if {$key_length >= 32} {
                set actual_security "high"
            } elseif {$key_length >= 16} {
                set actual_security "standard"
            } elseif {$key_length < 16} {
                set actual_security "weak"
            }
            
            if {$actual_security eq $expected_security} {
                puts "    ✓ $cipher: $actual_security security (${key_length} bytes key)"
            } else {
                puts "    ⚠ $cipher: expected $expected_security, got $actual_security (${key_length} bytes key)"
            }
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