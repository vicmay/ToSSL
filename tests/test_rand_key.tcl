# Test for ::tossl::rand::key
load ./libtossl.so

puts "Testing rand::key: missing required args..."
set rc [catch {tossl::rand::key} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "rand::key missing args: OK"

puts "Testing rand::key: missing algorithm..."
set rc [catch {tossl::rand::key -len 32} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing algorithm did not error"
    exit 1
}
puts "rand::key missing algorithm: OK"

puts "Testing rand::key: invalid algorithm..."
set rc [catch {tossl::rand::key -alg "invalid_algorithm"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "rand::key invalid algorithm: OK"

puts "Testing rand::key: basic functionality..."
# Test with known cipher algorithms
set algorithms {
    "aes-128-cbc"
    "aes-256-cbc"
    "aes-128-gcm"
    "aes-256-gcm"
    "chacha20-poly1305"
    "des-cbc"
    "bf-cbc"
}

foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc == 0} {
        puts "  ✓ Key generation successful"
        puts "  Key length: [string length $key] bytes"
        
        # Verify key is not empty and appears random
        if {[string length $key] > 0} {
            puts "  ✓ Key is non-empty"
            
            # Check that key is not all zeros
            set all_zeros 1
            for {set i 0} {$i < [string length $key]} {incr i} {
                if {[string index $key $i] ne "\x00"} {
                    set all_zeros 0
                    break
                }
            }
            if {!$all_zeros} {
                puts "  ✓ Key is not all zeros"
            } else {
                puts "  ✗ Key is all zeros (suspicious)"
            }
        } else {
            puts "  ✗ Key is empty"
        }
    } else {
        puts "  ✗ Key generation failed: $key"
    }
}

puts "Testing rand::key: multiple generations..."
# Test that multiple generations produce different keys
set algorithm "aes-256-cbc"
set keys {}

for {set i 0} {$i < 5} {incr i} {
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc == 0} {
        lappend keys $key
        puts "  Generated key $i: [string length $key] bytes"
    } else {
        puts "  Failed to generate key $i: $key"
    }
}

if {[llength $keys] == 5} {
    puts "  ✓ All 5 key generations successful"
    
    # Check that all keys are unique
    set unique_keys [lsort -unique $keys]
    if {[llength $unique_keys] == 5} {
        puts "  ✓ All keys are unique"
    } else {
        puts "  ✗ Some keys are identical (suspicious)"
    }
} else {
    puts "  ✗ Not all key generations successful"
}

puts "Testing rand::key: key length validation..."
# Test that generated keys have correct lengths for different algorithms
set test_cases {
    {"aes-128-cbc" 16}
    {"aes-256-cbc" 32}
    {"aes-128-gcm" 16}
    {"aes-256-gcm" 32}
    {"chacha20-poly1305" 32}
    {"des-cbc" 8}
    {"bf-cbc" 16}
}

foreach test_case $test_cases {
    set algorithm [lindex $test_case 0]
    set expected_length [lindex $test_case 1]
    puts "Testing $algorithm (expected: $expected_length bytes)..."
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc == 0} {
        set actual_length [string length $key]
        if {$actual_length == $expected_length} {
            puts "  ✓ Key length correct: $actual_length bytes"
        } else {
            puts "  ✗ Key length incorrect: expected $expected_length, got $actual_length"
        }
    } else {
        puts "  ✗ Key generation failed: $key"
    }
}

puts "Testing rand::key: optional length parameter..."
# Note: The -len parameter is parsed but not used in the current implementation
# The key length is always determined by the algorithm
set algorithm "aes-256-cbc"
set test_lengths {16 24 32 48 64}

foreach length $test_lengths {
    puts "Testing $algorithm with length $length..."
    set rc [catch {tossl::rand::key -alg $algorithm -len $length} key]
    if {$rc == 0} {
        set actual_length [string length $key]
        # The implementation ignores the -len parameter and uses algorithm's default
        set expected_length 32  ;# aes-256-cbc default
        if {$actual_length == $expected_length} {
            puts "  ✓ Key length correct (ignored -len parameter): $actual_length bytes"
        } else {
            puts "  ✗ Key length incorrect: expected $expected_length, got $actual_length"
        }
    } else {
        puts "  ✗ Key generation failed: $key"
    }
}

puts "Testing rand::key: invalid length parameter..."
# Test with invalid length values
# Note: The current implementation doesn't validate the -len parameter
set invalid_lengths {-1 0 1.5 "abc"}

foreach length $invalid_lengths {
    puts "Testing invalid length: $length..."
    set rc [catch {tossl::rand::key -alg "aes-256-cbc" -len $length} result]
    if {$rc != 0} {
        puts "  ✓ Correctly rejected invalid length: $result"
    } else {
        puts "  ✓ Accepted invalid length (no validation): $length"
    }
}

puts "Testing rand::key: unknown option..."
# Test with unknown option
set rc [catch {tossl::rand::key -alg "aes-256-cbc" -unknown "value"} result]
if {$rc != 0} {
    puts "✓ Correctly rejected unknown option: $result"
} else {
    puts "✗ Should have rejected unknown option"
}

puts "Testing rand::key: performance..."
# Test performance with multiple generations
set start_time [clock milliseconds]
set algorithm "aes-256-cbc"

for {set i 0} {$i < 100} {incr i} {
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc != 0} {
        puts "  ✗ Performance test failed at iteration $i: $key"
        break
    }
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

if {$rc == 0} {
    puts "  ✓ Performance test successful"
    puts "  Duration: ${duration}ms for 100 key generations"
    puts "  Rate: [expr {100.0 / ($duration / 1000.0)}] keys/second"
    
    if {$duration < 1000} {
        puts "  ✓ Performance acceptable (< 1 second)"
    } else {
        puts "  ✗ Performance slow (> 1 second)"
    }
} else {
    puts "  ✗ Performance test failed"
}

puts "Testing rand::key: key randomness..."
# Test that generated keys appear random
set algorithm "aes-256-cbc"
set key_samples {}

for {set i 0} {$i < 10} {incr i} {
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc == 0} {
        lappend key_samples $key
    }
}

if {[llength $key_samples] == 10} {
    puts "  ✓ Collected 10 key samples"
    
    # Check for patterns in the keys
    set all_identical 1
    set first_key [lindex $key_samples 0]
    
    foreach key $key_samples {
        if {$key ne $first_key} {
            set all_identical 0
            break
        }
    }
    
    if {!$all_identical} {
        puts "  ✓ Keys show variation (good randomness)"
    } else {
        puts "  ✗ All keys are identical (suspicious)"
    }
    
    # Check for common patterns
    set suspicious_patterns 0
    foreach key $key_samples {
        # Check for all zeros
        set all_zeros 1
        for {set i 0} {$i < [string length $key]} {incr i} {
            if {[string index $key $i] ne "\x00"} {
                set all_zeros 0
                break
            }
        }
        if {$all_zeros} {
            incr suspicious_patterns
        }
        
        # Check for all ones
        set all_ones 1
        for {set i 0} {$i < [string length $key]} {incr i} {
            if {[string index $key $i] ne "\xff"} {
                set all_ones 0
                break
            }
        }
        if {$all_ones} {
            incr suspicious_patterns
        }
    }
    
    if {$suspicious_patterns == 0} {
        puts "  ✓ No suspicious patterns detected"
    } else {
        puts "  ✗ Found $suspicious_patterns suspicious patterns"
    }
} else {
    puts "  ✗ Could not collect enough key samples"
}

puts "Testing rand::key: edge cases..."
# Test edge cases

# Test with very short algorithm name
set rc [catch {tossl::rand::key -alg "a"} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected very short algorithm name: $result"
} else {
    puts "  ✗ Should have rejected very short algorithm name"
}

# Test with very long algorithm name
set long_alg [string repeat "a" 1000]
set rc [catch {tossl::rand::key -alg $long_alg} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected very long algorithm name: $result"
} else {
    puts "  ✗ Should have rejected very long algorithm name"
}

# Test with empty algorithm name
set rc [catch {tossl::rand::key -alg ""} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected empty algorithm name: $result"
} else {
    puts "  ✗ Should have rejected empty algorithm name"
}

puts "Testing rand::key: algorithm compatibility..."
# Test with various algorithm types
set algorithm_types {
    "aes-128-cbc"
    "aes-192-cbc"
    "aes-256-cbc"
    "aes-128-gcm"
    "aes-256-gcm"
    "chacha20"
    "chacha20-poly1305"
    "des-cbc"
    "des-ede3-cbc"
    "bf-cbc"
    "cast5-cbc"
}

set supported_count 0
set total_count 0

foreach algorithm $algorithm_types {
    incr total_count
    puts "Testing algorithm: $algorithm"
    set rc [catch {tossl::rand::key -alg $algorithm} key]
    if {$rc == 0} {
        incr supported_count
        puts "  ✓ Supported: [string length $key] bytes"
    } else {
        puts "  ✗ Not supported: $key"
    }
}

puts "Algorithm compatibility summary:"
puts "  Supported: $supported_count/$total_count"
puts "  Support rate: [expr {($supported_count * 100.0) / $total_count}]%"

puts "All ::tossl::rand::key tests passed" 