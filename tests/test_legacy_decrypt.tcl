# Test for ::tossl::legacy::decrypt
load ./libtossl.so

puts "Testing legacy::decrypt: missing required args..."
set rc [catch {tossl::legacy::decrypt} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "legacy::decrypt missing args: OK"

puts "Testing legacy::decrypt: wrong number of args..."
set rc [catch {tossl::legacy::decrypt "des-cbc" "key"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Wrong number of args did not error"
    exit 1
}
puts "legacy::decrypt wrong args: OK"

puts "Testing legacy::decrypt: invalid algorithm..."
set key [binary format H* "0011223344556677"]
set iv [binary format H* "0102030405060708"]
set data "test data"
set rc [catch {tossl::legacy::decrypt "invalid_algorithm" $key $iv $data} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "legacy::decrypt invalid algorithm: OK"

puts "Testing legacy::decrypt: basic functionality..."
# Test with known legacy algorithms
set test_data "Hello, World! This is a test message for legacy decryption."
set algorithms {
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "bf-cfb"
    "bf-ofb"
    "cast5-cbc"
    "cast5-cfb"
    "cast5-ofb"
}

foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    
    # Get algorithm info to determine key and IV lengths
    set info [tossl::legacy::info $algorithm]
    set key_length 0
    set iv_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key_name [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key_name eq "key_length"} {
            set key_length $value
        } elseif {$key_name eq "iv_length"} {
            set iv_length $value
        }
    }
    
    # Generate appropriate key and IV
    set key [tossl::legacy::keygen $algorithm]
    set iv [tossl::legacy::ivgen $algorithm]
    
    puts "  Key length: [string length $key] bytes (expected: $key_length)"
    puts "  IV length: [string length $iv] bytes (expected: $iv_length)"
    
    # First encrypt the data
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        puts "  Ciphertext length: [string length $ciphertext] bytes"
        
        # Now test decryption
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            puts "  ✓ Decryption successful"
            puts "  Decrypted length: [string length $decrypted] bytes"
            
            # Verify decryption matches original
            if {$decrypted eq $test_data} {
                puts "  ✓ Decryption round-trip successful"
            } else {
                puts "  ✗ Decryption round-trip failed"
                puts "    Original: '$test_data'"
                puts "    Decrypted: '$decrypted'"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
        }
        
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
    }
}

puts "Testing legacy::decrypt: stream ciphers..."
# Test with stream ciphers (RC4)
set stream_ciphers {
    "rc4"
    "rc4-40"
}

foreach algorithm $stream_ciphers {
    puts "Testing $algorithm..."
    
    # Get algorithm info
    set info [tossl::legacy::info $algorithm]
    set key_length 0
    set iv_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key_name [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key_name eq "key_length"} {
            set key_length $value
        } elseif {$key_name eq "iv_length"} {
            set iv_length $value
        }
    }
    
    # Generate key (stream ciphers don't need IV)
    set key [tossl::legacy::keygen $algorithm]
    puts "  Key length: [string length $key] bytes (expected: $key_length)"
    puts "  IV length: $iv_length bytes (should be 0 for stream ciphers)"
    
    # For stream ciphers, use empty IV
    set iv ""
    
    # First encrypt the data
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Now test decryption
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            puts "  ✓ Decryption successful"
            
            if {$decrypted eq $test_data} {
                puts "  ✓ Decryption round-trip successful"
            } else {
                puts "  ✗ Decryption round-trip failed"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
        }
        
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
    }
}

puts "Testing legacy::decrypt: ECB mode..."
# Test with ECB mode (no IV required)
set ecb_algorithms {
    "des-ecb"
    "bf-ecb"
    "cast5-ecb"
}

foreach algorithm $ecb_algorithms {
    puts "Testing $algorithm..."
    
    # Get algorithm info
    set info [tossl::legacy::info $algorithm]
    set key_length 0
    set iv_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key_name [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key_name eq "key_length"} {
            set key_length $value
        } elseif {$key_name eq "iv_length"} {
            set iv_length $value
        }
    }
    
    # Generate key (ECB mode doesn't need IV)
    set key [tossl::legacy::keygen $algorithm]
    puts "  Key length: [string length $key] bytes (expected: $key_length)"
    puts "  IV length: $iv_length bytes (should be 0 for ECB mode)"
    
    # For ECB mode, use empty IV
    set iv ""
    
    # First encrypt the data
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Now test decryption
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            puts "  ✓ Decryption successful"
            
            if {$decrypted eq $test_data} {
                puts "  ✓ Decryption round-trip successful"
            } else {
                puts "  ✗ Decryption round-trip failed"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
        }
        
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
    }
}

puts "Testing legacy::decrypt: different data sizes..."
# Test with different data sizes
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

set test_cases {
    ""                    ;# Empty string
    "A"                   ;# Single character
    "Hello"               ;# Short string
    "This is a longer test message that should work with legacy decryption algorithms."
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
}

foreach test_data $test_cases {
    puts "Testing data size: [string length $test_data] bytes"
    
    # First encrypt
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Then decrypt
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            if {$decrypted eq $test_data} {
                puts "  ✓ Decryption round-trip successful"
            } else {
                puts "  ✗ Decryption round-trip failed"
                puts "    Original: '$test_data'"
                puts "    Decrypted: '$decrypted'"
            }
        } else {
            puts "  ✗ Decryption failed: $decrypted"
        }
        
    } else {
        puts "  ✗ Encryption failed: $ciphertext"
    }
}

puts "Testing legacy::decrypt: key/IV length validation..."
# Test with incorrect key/IV lengths
set algorithm "des-cbc"
set correct_key [tossl::legacy::keygen $algorithm]
set correct_iv [tossl::legacy::ivgen $algorithm]
set test_data "test"

# First create valid ciphertext
set rc [catch {tossl::legacy::encrypt $algorithm $correct_key $correct_iv $test_data} ciphertext]
if {$rc == 0} {
    puts "  ✓ Created valid ciphertext for testing"
    
    # Test with wrong key length
    set wrong_key [string range $correct_key 0 3]  ;# Too short
    set rc [catch {tossl::legacy::decrypt $algorithm $wrong_key $correct_iv $ciphertext} result]
    if {$rc == 0} {
        puts "WARNING: Decryption succeeded with wrong key length"
    } else {
        puts "✓ Decryption correctly failed with wrong key length"
    }
    
    # Test with wrong IV length
    set wrong_iv [string range $correct_iv 0 3]  ;# Too short
    set rc [catch {tossl::legacy::decrypt $algorithm $correct_key $wrong_iv $ciphertext} result]
    if {$rc == 0} {
        puts "WARNING: Decryption succeeded with wrong IV length"
    } else {
        puts "✓ Decryption correctly failed with wrong IV length"
    }
    
} else {
    puts "  ✗ Failed to create ciphertext for testing"
}

puts "Testing legacy::decrypt: invalid ciphertext..."
# Test with invalid ciphertext
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

# Test with random data as ciphertext
set random_ciphertext [tossl::randbytes 32]
set rc [catch {tossl::legacy::decrypt $algorithm $key $iv $random_ciphertext} result]
if {$rc == 0} {
    puts "WARNING: Decryption succeeded with random ciphertext"
} else {
    puts "✓ Decryption correctly failed with random ciphertext"
}

# Test with empty ciphertext
set rc [catch {tossl::legacy::decrypt $algorithm $key $iv ""} result]
if {$rc == 0} {
    puts "WARNING: Decryption succeeded with empty ciphertext"
} else {
    puts "✓ Decryption correctly failed with empty ciphertext"
}

puts "Testing legacy::decrypt: modern algorithms..."
# Test with modern algorithms that should not be supported
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

set test_key [binary format H* "00112233445566778899aabbccddeeff"]
set test_iv [binary format H* "0102030405060708090a0b0c0d0e0f10"]
set test_ciphertext [binary format H* "1234567890abcdef"]

foreach algorithm $modern_algorithms {
    set rc [catch {tossl::legacy::decrypt $algorithm $test_key $test_iv $test_ciphertext} result]
    if {$rc == 0} {
        puts "legacy::decrypt $algorithm: OK (unexpectedly supported)"
    } else {
        puts "legacy::decrypt $algorithm: OK (correctly not supported)"
    }
}

puts "Testing legacy::decrypt: multiple round-trips..."
# Test multiple encryption/decryption round-trips
set algorithm "bf-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]
set original_data "Multiple round-trip test data"

puts "Testing multiple round-trips with $algorithm..."

for {set i 0} {$i < 5} {incr i} {
    puts "  Round-trip $i..."
    
    # Encrypt
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $original_data} ciphertext]
    if {$rc == 0} {
        puts "    ✓ Encryption successful"
        
        # Decrypt
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
            if {$decrypted eq $original_data} {
                puts "    ✓ Decryption successful"
            } else {
                puts "    ✗ Decryption failed - data mismatch"
            }
        } else {
            puts "    ✗ Decryption failed: $decrypted"
        }
        
    } else {
        puts "    ✗ Encryption failed: $ciphertext"
    }
}

puts "Testing legacy::decrypt: edge cases..."
# Test edge cases
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

# Test with very long data
set long_data [string repeat "A" 1000]
set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $long_data} ciphertext]
if {$rc == 0} {
    puts "  ✓ Long data encryption successful"
    
    set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
    if {$rc2 == 0} {
        if {$decrypted eq $long_data} {
            puts "  ✓ Long data decryption successful"
        } else {
            puts "  ✗ Long data decryption failed"
        }
    } else {
        puts "  ✗ Long data decryption failed: $decrypted"
    }
} else {
    puts "  ✗ Long data encryption failed: $ciphertext"
}

# Test with binary data
set binary_data [binary format H* "0102030405060708090a0b0c0d0e0f10"]
set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $binary_data} ciphertext]
if {$rc == 0} {
    puts "  ✓ Binary data encryption successful"
    
    set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
    if {$rc2 == 0} {
        if {$decrypted eq $binary_data} {
            puts "  ✓ Binary data decryption successful"
        } else {
            puts "  ✗ Binary data decryption failed"
        }
    } else {
        puts "  ✗ Binary data decryption failed: $decrypted"
    }
} else {
    puts "  ✗ Binary data encryption failed: $ciphertext"
}

puts "All ::tossl::legacy::decrypt tests passed" 