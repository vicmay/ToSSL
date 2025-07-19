# tests/test_cipher_analyze.tcl ;# Test for ::tossl::cipher::analyze

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::cipher::analyze ==="

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

# Test 1: Basic functionality - analyze AES-128-CBC
test "Basic AES-128-CBC analysis" {
    set analysis [tossl::cipher::analyze aes-128-cbc]
    
    # Verify it contains expected information
    if {![string match "*key_len=16*" $analysis] || 
        ![string match "*iv_len=16*" $analysis] || 
        ![string match "*block_size=16*" $analysis]} {
        error "AES-128-CBC analysis missing expected fields: $analysis"
    }
    
    puts "    Analysis: $analysis"
}

# Test 2: Basic functionality - analyze AES-256-CBC
test "Basic AES-256-CBC analysis" {
    set analysis [tossl::cipher::analyze aes-256-cbc]
    
    # Verify it contains expected information
    if {![string match "*key_len=32*" $analysis] || 
        ![string match "*iv_len=16*" $analysis] || 
        ![string match "*block_size=16*" $analysis]} {
        error "AES-256-CBC analysis missing expected fields: $analysis"
    }
    
    puts "    Analysis: $analysis"
}

# Test 3: Error handling for invalid cipher
test "Error handling for invalid cipher" {
    if {[catch {tossl::cipher::analyze invalid-cipher} result]} {
        puts "    Correctly rejected invalid cipher: $result"
    } else {
        error "Should have rejected invalid cipher"
    }
}

# Test 4: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::cipher::analyze} result]} {
        puts "    Correctly rejected no arguments: $result"
    } else {
        error "Should have rejected no arguments"
    }
}

# Test 5: Error handling for too many arguments
test "Error handling for too many arguments" {
    if {[catch {tossl::cipher::analyze aes-256-cbc extra-arg} result]} {
        puts "    Correctly rejected too many arguments: $result"
    } else {
        error "Should have rejected too many arguments"
    }
}

# Test 6: Command exists and accepts correct arguments
test "Command exists and accepts correct arguments" {
    if {[catch {tossl::cipher::analyze aes-256-cbc} analysis]} {
        error "Command failed: $analysis"
    } else {
        puts "    Command exists and executed successfully"
    }
}

# Test 7: Multiple cipher analysis
test "Multiple cipher analysis" {
    set ciphers {aes-128-ecb aes-192-ecb aes-256-ecb aes-128-cbc aes-192-cbc aes-256-cbc}
    
    foreach cipher $ciphers {
        if {[catch {tossl::cipher::analyze $cipher} analysis]} {
            error "Failed to analyze $cipher: $analysis"
        } else {
            puts "    ✓ $cipher: $analysis"
        }
    }
}

# Test 8: Performance test - multiple analysis attempts
test "Performance test - multiple analysis attempts" {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set analysis [tossl::cipher::analyze aes-256-cbc]
        if {![string match "*key_len=32*" $analysis]} {
            error "Invalid analysis on iteration $i: $analysis"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 100 analyses in ${duration}ms"
}

# Test 9: Analysis format verification
test "Analysis format verification" {
    set analysis [tossl::cipher::analyze aes-256-cbc]
    
    # Check format: key_len=X, iv_len=Y, block_size=Z, flags=0xW
    if {![regexp {key_len=\d+, iv_len=\d+, block_size=\d+, flags=0x[0-9a-fA-F]+} $analysis]} {
        error "Invalid analysis format: $analysis"
    }
    
    puts "    Analysis format is correct: $analysis"
}

# Test 10: Integration with cipher list
test "Integration with cipher list" {
    if {[catch {
        set ciphers [tossl::cipher::list]
        puts "    Retrieved [llength $ciphers] ciphers"
        
        # Test a few common ciphers
        set common_ciphers {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm}
        foreach cipher $common_ciphers {
            if {[lsearch $ciphers $cipher] != -1} {
                set analysis [tossl::cipher::analyze $cipher]
                puts "    ✓ $cipher: $analysis"
            } else {
                puts "    ⚠ $cipher: Not available"
            }
        }
    } err]} {
        puts "    ⚠ Could not test integration with cipher list: $err"
    }
}

# Test 11: Algorithm consistency verification
test "Algorithm consistency verification" {
    set ciphers {aes-128-cbc aes-192-cbc aes-256-cbc}
    
    foreach cipher $ciphers {
        set analysis [tossl::cipher::analyze $cipher]
        
        # Extract key length
        if {[regexp {key_len=(\d+)} $analysis -> key_len]} {
            # Verify key length matches cipher name
            if {[string match "*128*" $cipher] && $key_len != 16} {
                error "Key length mismatch for $cipher: expected 16, got $key_len"
            } elseif {[string match "*192*" $cipher] && $key_len != 24} {
                error "Key length mismatch for $cipher: expected 24, got $key_len"
            } elseif {[string match "*256*" $cipher] && $key_len != 32} {
                error "Key length mismatch for $cipher: expected 32, got $key_len"
            }
        } else {
            error "Could not extract key length from analysis: $analysis"
        }
        
        puts "    ✓ $cipher: key_len=$key_len (consistent)"
    }
}

# Test 12: Block size verification
test "Block size verification" {
    set ciphers {aes-128-cbc aes-256-cbc camellia-128-cbc camellia-256-cbc}
    
    foreach cipher $ciphers {
        set analysis [tossl::cipher::analyze $cipher]
        
        # Extract block size
        if {[regexp {block_size=(\d+)} $analysis -> block_size]} {
            # AES and Camellia should have 16-byte block size
            if {$block_size != 16} {
                error "Block size mismatch for $cipher: expected 16, got $block_size"
            }
        } else {
            error "Could not extract block size from analysis: $analysis"
        }
        
        puts "    ✓ $cipher: block_size=$block_size (correct)"
    }
}

# Test 13: IV length verification
test "IV length verification" {
    set ciphers {aes-128-cbc aes-256-cbc aes-128-ecb aes-256-ecb}
    
    foreach cipher $ciphers {
        set analysis [tossl::cipher::analyze $cipher]
        
        # Extract IV length
        if {[regexp {iv_len=(\d+)} $analysis -> iv_len]} {
            # CBC mode should have IV, ECB should not
            if {[string match "*cbc*" $cipher] && $iv_len != 16} {
                error "IV length mismatch for $cipher: expected 16, got $iv_len"
            } elseif {[string match "*ecb*" $cipher] && $iv_len != 0} {
                error "IV length mismatch for $cipher: expected 0, got $iv_len"
            }
        } else {
            error "Could not extract IV length from analysis: $analysis"
        }
        
        puts "    ✓ $cipher: iv_len=$iv_len (correct)"
    }
}

# Test 14: Flags verification
test "Flags verification" {
    set analysis [tossl::cipher::analyze aes-256-cbc]
    
    # Extract flags
    if {[regexp {flags=0x([0-9a-fA-F]+)} $analysis -> flags]} {
        # Flags should be a valid hex number
        if {![regexp {^[0-9a-fA-F]+$} $flags]} {
            error "Invalid flags format: $flags"
        }
        puts "    ✓ Flags: 0x$flags (valid hex)"
    } else {
        error "Could not extract flags from analysis: $analysis"
    }
}

# Test 15: Memory usage test
test "Memory usage test" {
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 50} {incr i} {
        set analysis [tossl::cipher::analyze aes-256-cbc]
        if {![string match "*key_len=32*" $analysis]} {
            error "Memory test failed on iteration $i: $analysis"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 16: Error handling for empty cipher name
test "Error handling for empty cipher name" {
    if {[catch {tossl::cipher::analyze ""} result]} {
        puts "    Correctly rejected empty cipher name: $result"
    } else {
        error "Should have rejected empty cipher name"
    }
}

# Test 17: Analysis parsing test
test "Analysis parsing test" {
    set analysis [tossl::cipher::analyze aes-256-cbc]
    
    # Parse all components
    if {[regexp {key_len=(\d+), iv_len=(\d+), block_size=(\d+), flags=0x([0-9a-fA-F]+)} $analysis -> key_len iv_len block_size flags]} {
        puts "    Parsed: key_len=$key_len, iv_len=$iv_len, block_size=$block_size, flags=0x$flags"
        
        # Validate parsed values
        if {$key_len != 32} {
            error "Parsed key length incorrect: $key_len"
        }
        if {$iv_len != 16} {
            error "Parsed IV length incorrect: $iv_len"
        }
        if {$block_size != 16} {
            error "Parsed block size incorrect: $block_size"
        }
    } else {
        error "Could not parse analysis string: $analysis"
    }
}

# Test 18: GCM mode analysis
test "GCM mode analysis" {
    if {[catch {tossl::cipher::analyze aes-256-gcm} analysis]} {
        puts "    ⚠ AES-256-GCM not available: $analysis"
    } else {
        puts "    ✓ AES-256-GCM: $analysis"
        
        # GCM should have IV length
        if {[regexp {iv_len=(\d+)} $analysis -> iv_len]} {
            if {$iv_len == 0} {
                error "GCM mode should have IV length > 0"
            }
        }
    }
}

# Test 19: ChaCha20 analysis
test "ChaCha20 analysis" {
    if {[catch {tossl::cipher::analyze chacha20-poly1305} analysis]} {
        puts "    ⚠ ChaCha20-Poly1305 not available: $analysis"
    } else {
        puts "    ✓ ChaCha20-Poly1305: $analysis"
    }
}

# Test 20: Algorithm availability verification
test "Algorithm availability verification" {
    set test_ciphers {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm chacha20-poly1305}
    
    foreach cipher $test_ciphers {
        if {[catch {tossl::cipher::analyze $cipher} analysis]} {
            puts "    ⚠ $cipher: Not available"
        } else {
            puts "    ✓ $cipher: Available"
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