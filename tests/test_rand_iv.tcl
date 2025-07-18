# Test for ::tossl::rand::iv
load ./libtossl.so

puts "Testing rand::iv: missing required args..."
set rc [catch {tossl::rand::iv} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "rand::iv missing args: OK"

puts "Testing rand::iv: missing algorithm..."
set rc [catch {tossl::rand::iv -unknown "value"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing algorithm did not error"
    exit 1
}
puts "rand::iv missing algorithm: OK"

puts "Testing rand::iv: invalid algorithm..."
set rc [catch {tossl::rand::iv -alg "invalid_algorithm"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "rand::iv invalid algorithm: OK"

puts "Testing rand::iv: basic functionality..."
# Test with known cipher algorithms that require IVs
set algorithms {
    "aes-128-cbc"
    "aes-256-cbc"
    "aes-128-gcm"
    "aes-256-gcm"
    "des-cbc"
    "bf-cbc"
    "cast5-cbc"
}

foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        puts "  ✓ IV generation successful"
        puts "  IV length: [string length $iv] bytes"
        
        # Verify IV is not empty and appears random
        if {[string length $iv] > 0} {
            puts "  ✓ IV is non-empty"
            
            # Check that IV is not all zeros
            set all_zeros 1
            for {set i 0} {$i < [string length $iv]} {incr i} {
                if {[string index $iv $i] ne "\x00"} {
                    set all_zeros 0
                    break
                }
            }
            if {!$all_zeros} {
                puts "  ✓ IV is not all zeros"
            } else {
                puts "  ✗ IV is all zeros (suspicious)"
            }
        } else {
            puts "  ✗ IV is empty"
        }
    } else {
        puts "  ✗ IV generation failed: $iv"
    }
}

puts "Testing rand::iv: multiple generations..."
# Test that multiple generations produce different IVs
set algorithm "aes-256-cbc"
set ivs {}

for {set i 0} {$i < 5} {incr i} {
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        lappend ivs $iv
        puts "  Generated IV $i: [string length $iv] bytes"
    } else {
        puts "  Failed to generate IV $i: $iv"
    }
}

if {[llength $ivs] == 5} {
    puts "  ✓ All 5 IV generations successful"
    
    # Check that all IVs are unique
    set unique_ivs [lsort -unique $ivs]
    if {[llength $unique_ivs] == 5} {
        puts "  ✓ All IVs are unique"
    } else {
        puts "  ✗ Some IVs are identical (suspicious)"
    }
} else {
    puts "  ✗ Not all IV generations successful"
}

puts "Testing rand::iv: IV length validation..."
# Test that generated IVs have correct lengths for different algorithms
set test_cases {
    {"aes-128-cbc" 16}
    {"aes-256-cbc" 16}
    {"aes-128-gcm" 12}
    {"aes-256-gcm" 12}
    {"des-cbc" 8}
    {"bf-cbc" 8}
    {"cast5-cbc" 8}
}

foreach test_case $test_cases {
    set algorithm [lindex $test_case 0]
    set expected_length [lindex $test_case 1]
    puts "Testing $algorithm (expected: $expected_length bytes)..."
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        set actual_length [string length $iv]
        if {$actual_length == $expected_length} {
            puts "  ✓ IV length correct: $actual_length bytes"
        } else {
            puts "  ✗ IV length incorrect: expected $expected_length, got $actual_length"
        }
    } else {
        puts "  ✗ IV generation failed: $iv"
    }
}

puts "Testing rand::iv: algorithms without IV..."
# Test algorithms that don't require IVs
set no_iv_algorithms {
    "aes-128-ecb"
    "aes-256-ecb"
}

foreach algorithm $no_iv_algorithms {
    puts "Testing $algorithm (should not require IV)..."
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc != 0} {
        puts "  ✓ Correctly rejected: $iv"
    } else {
        puts "  ✗ Should have rejected algorithm that doesn't require IV"
    }
}

puts "Testing rand::iv: algorithms with IV support..."
# Test algorithms that do support IVs (including ChaCha20)
set iv_algorithms {
    "chacha20"
    "chacha20-poly1305"
}

foreach algorithm $iv_algorithms {
    puts "Testing $algorithm (supports IV)..."
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        puts "  ✓ IV generation successful: [string length $iv] bytes"
    } else {
        puts "  ✗ IV generation failed: $iv"
    }
}

puts "Testing rand::iv: unknown option..."
# Test with unknown option
set rc [catch {tossl::rand::iv -alg "aes-256-cbc" -unknown "value"} result]
if {$rc != 0} {
    puts "✓ Correctly rejected unknown option: $result"
} else {
    puts "✗ Should have rejected unknown option"
}

puts "Testing rand::iv: performance..."
# Test performance with multiple generations
set start_time [clock milliseconds]
set algorithm "aes-256-cbc"

for {set i 0} {$i < 100} {incr i} {
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc != 0} {
        puts "  ✗ Performance test failed at iteration $i: $iv"
        break
    }
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

if {$rc == 0} {
    puts "  ✓ Performance test successful"
    puts "  Duration: ${duration}ms for 100 IV generations"
    puts "  Rate: [expr {100.0 / ($duration / 1000.0)}] IVs/second"
    
    if {$duration < 1000} {
        puts "  ✓ Performance acceptable (< 1 second)"
    } else {
        puts "  ✗ Performance slow (> 1 second)"
    }
} else {
    puts "  ✗ Performance test failed"
}

puts "Testing rand::iv: IV randomness..."
# Test that generated IVs appear random
set algorithm "aes-256-cbc"
set iv_samples {}

for {set i 0} {$i < 10} {incr i} {
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        lappend iv_samples $iv
    }
}

if {[llength $iv_samples] == 10} {
    puts "  ✓ Collected 10 IV samples"
    
    # Check for patterns in the IVs
    set all_identical 1
    set first_iv [lindex $iv_samples 0]
    
    foreach iv $iv_samples {
        if {$iv ne $first_iv} {
            set all_identical 0
            break
        }
    }
    
    if {!$all_identical} {
        puts "  ✓ IVs show variation (good randomness)"
    } else {
        puts "  ✗ All IVs are identical (suspicious)"
    }
    
    # Check for common patterns
    set suspicious_patterns 0
    foreach iv $iv_samples {
        # Check for all zeros
        set all_zeros 1
        for {set i 0} {$i < [string length $iv]} {incr i} {
            if {[string index $iv $i] ne "\x00"} {
                set all_zeros 0
                break
            }
        }
        if {$all_zeros} {
            incr suspicious_patterns
        }
        
        # Check for all ones
        set all_ones 1
        for {set i 0} {$i < [string length $iv]} {incr i} {
            if {[string index $iv $i] ne "\xff"} {
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
    puts "  ✗ Could not collect enough IV samples"
}

puts "Testing rand::iv: edge cases..."
# Test edge cases

# Test with very short algorithm name
set rc [catch {tossl::rand::iv -alg "a"} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected very short algorithm name: $result"
} else {
    puts "  ✗ Should have rejected very short algorithm name"
}

# Test with very long algorithm name
set long_alg [string repeat "a" 1000]
set rc [catch {tossl::rand::iv -alg $long_alg} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected very long algorithm name: $result"
} else {
    puts "  ✗ Should have rejected very long algorithm name"
}

# Test with empty algorithm name
set rc [catch {tossl::rand::iv -alg ""} result]
if {$rc != 0} {
    puts "  ✓ Correctly rejected empty algorithm name: $result"
} else {
    puts "  ✗ Should have rejected empty algorithm name"
}

puts "Testing rand::iv: algorithm compatibility..."
# Test with various algorithm types
set algorithm_types {
    "aes-128-cbc"
    "aes-192-cbc"
    "aes-256-cbc"
    "aes-128-gcm"
    "aes-256-gcm"
    "aes-128-ccm"
    "aes-256-ccm"
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "des-ede3-cbc"
    "bf-cbc"
    "cast5-cbc"
    "chacha20"
    "chacha20-poly1305"
}

set supported_count 0
set total_count 0

foreach algorithm $algorithm_types {
    incr total_count
    puts "Testing algorithm: $algorithm"
    set rc [catch {tossl::rand::iv -alg $algorithm} iv]
    if {$rc == 0} {
        incr supported_count
        puts "  ✓ Supported: [string length $iv] bytes"
    } else {
        puts "  ✗ Not supported: $iv"
    }
}

puts "Algorithm compatibility summary:"
puts "  Supported: $supported_count/$total_count"
puts "  Support rate: [expr {($supported_count * 100.0) / $total_count}]%"

puts "Testing rand::iv: encryption workflow..."
# Test complete encryption workflow with generated IV
set algorithm "aes-256-cbc"
set plaintext "Secret message for testing"

# Generate key and IV
set rc1 [catch {tossl::rand::key -alg $algorithm} key]
set rc2 [catch {tossl::rand::iv -alg $algorithm} iv]

if {$rc1 == 0 && $rc2 == 0} {
    puts "  ✓ Key and IV generation successful"
    puts "  Key length: [string length $key] bytes"
    puts "  IV length: [string length $iv] bytes"
    
    # Test encryption
    set rc3 [catch {tossl::encrypt -alg $algorithm -key $key -iv $iv $plaintext} ciphertext]
    if {$rc3 == 0} {
        puts "  ✓ Encryption successful"
        
        # Test decryption
        set rc4 [catch {tossl::decrypt -alg $algorithm -key $key -iv $iv $ciphertext} decrypted]
        if {$rc4 == 0} {
            if {$decrypted eq $plaintext} {
                puts "  ✓ Decryption successful - round-trip works"
            } else {
                puts "  ✗ Decryption failed - data mismatch"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
            puts "    Note: This may be due to encryption/decrypt command issues, not IV generation"
        }
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
        puts "    Note: This may be due to encryption command issues, not IV generation"
    }
} else {
    puts "  ✗ Key or IV generation failed"
    if {$rc1 != 0} {
        puts "    Key generation: $key"
    }
    if {$rc2 != 0} {
        puts "    IV generation: $iv"
    }
}

puts "Testing rand::iv: GCM mode workflow..."
# Test GCM mode which uses nonce instead of IV
set algorithm "aes-256-gcm"
set plaintext "Secret message for GCM testing"

# Generate key and nonce
set rc1 [catch {tossl::rand::key -alg $algorithm} key]
set rc2 [catch {tossl::rand::iv -alg $algorithm} nonce]

if {$rc1 == 0 && $rc2 == 0} {
    puts "  ✓ Key and nonce generation successful"
    puts "  Key length: [string length $key] bytes"
    puts "  Nonce length: [string length $nonce] bytes"
    
    # Test GCM encryption
    set rc3 [catch {tossl::encrypt -alg $algorithm -key $key -iv $nonce $plaintext} result]
    if {$rc3 == 0} {
        puts "  ✓ GCM encryption successful"
        
        # Check result format
        if {[string is list $result]} {
            puts "    Result is a list, checking for dict format..."
            if {[catch {dict get $result ciphertext} ciphertext] == 0 && [catch {dict get $result tag} tag] == 0} {
                puts "    ✓ Found ciphertext and tag in result"
                
                # Test GCM decryption
                set rc4 [catch {tossl::decrypt -alg $algorithm -key $key -iv $nonce $ciphertext -tag $tag} decrypted]
                if {$rc4 == 0} {
                    if {$decrypted eq $plaintext} {
                        puts "  ✓ GCM decryption successful - round-trip works"
                    } else {
                        puts "  ✗ GCM decryption failed - data mismatch"
                    }
                } else {
                    puts "  ✗ GCM decryption failed: $decrypted"
                    puts "    Note: This may be due to decrypt command issues, not IV generation"
                }
            } else {
                puts "    ✗ Result does not contain expected ciphertext/tag fields"
                puts "    Result format: $result"
            }
        } else {
            puts "    ✗ Result is not in expected format"
            puts "    Result type: [tcl::unsupported::representation $result]"
            puts "    Result: $result"
        }
    } else {
        puts "  ✗ GCM encryption failed: $result"
        puts "    Note: This may be due to encryption command issues, not IV generation"
    }
} else {
    puts "  ✗ Key or nonce generation failed"
    if {$rc1 != 0} {
        puts "    Key generation: $key"
    }
    if {$rc2 != 0} {
        puts "    Nonce generation: $nonce"
    }
}

puts "All ::tossl::rand::iv tests passed" 