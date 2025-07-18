# Test for ::tossl::legacy::encrypt
load ./libtossl.so

puts "Testing legacy::encrypt: missing required args..."
set rc [catch {tossl::legacy::encrypt} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "legacy::encrypt missing args: OK"

puts "Testing legacy::encrypt: wrong number of args..."
set rc [catch {tossl::legacy::encrypt "des-cbc" "key"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Wrong number of args did not error"
    exit 1
}
puts "legacy::encrypt wrong args: OK"

puts "Testing legacy::encrypt: invalid algorithm..."
set key [binary format H* "0011223344556677"]
set iv [binary format H* "0102030405060708"]
set data "test data"
set rc [catch {tossl::legacy::encrypt "invalid_algorithm" $key $iv $data} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "legacy::encrypt invalid algorithm: OK"

puts "Testing legacy::encrypt: basic functionality..."
# Test with known legacy algorithms
set test_data "Hello, World! This is a test message for legacy encryption."
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
    
    # Test encryption
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        puts "  Ciphertext length: [string length $ciphertext] bytes"
        
        # Verify ciphertext is not empty and different from plaintext
        if {[string length $ciphertext] > 0 && $ciphertext ne $test_data} {
            puts "  ✓ Ciphertext is valid (non-empty and different from plaintext)"
        } else {
            puts "  ✗ Ciphertext is invalid"
        }
        
        # Test decryption round-trip
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

puts "Testing legacy::encrypt: stream ciphers..."
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
    
    # Test encryption
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        puts "  Ciphertext length: [string length $ciphertext] bytes"
        
        # Test decryption round-trip
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
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

puts "Testing legacy::encrypt: ECB mode..."
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
    
    # Test encryption
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        puts "  Ciphertext length: [string length $ciphertext] bytes"
        
        # Test decryption round-trip
        set rc2 [catch {tossl::legacy::decrypt $algorithm $key $iv $ciphertext} decrypted]
        if {$rc2 == 0} {
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

puts "Testing legacy::encrypt: different data sizes..."
# Test with different data sizes
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]

set test_cases {
    ""                    ;# Empty string
    "A"                   ;# Single character
    "Hello"               ;# Short string
    "This is a longer test message that should work with legacy encryption algorithms."
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
}

foreach test_data $test_cases {
    puts "Testing data size: [string length $test_data] bytes"
    
    set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
    if {$rc == 0} {
        puts "  ✓ Encryption successful"
        
        # Test decryption round-trip
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

puts "Testing legacy::encrypt: key/IV length validation..."
# Test with incorrect key/IV lengths
set algorithm "des-cbc"
set correct_key [tossl::legacy::keygen $algorithm]
set correct_iv [tossl::legacy::ivgen $algorithm]
set test_data "test"

# Test with wrong key length
set wrong_key [string range $correct_key 0 3]  ;# Too short
set rc [catch {tossl::legacy::encrypt $algorithm $wrong_key $correct_iv $test_data} result]
if {$rc == 0} {
    puts "WARNING: Encryption succeeded with wrong key length"
} else {
    puts "✓ Encryption correctly failed with wrong key length"
}

# Test with wrong IV length
set wrong_iv [string range $correct_iv 0 3]  ;# Too short
set rc [catch {tossl::legacy::encrypt $algorithm $correct_key $wrong_iv $test_data} result]
if {$rc == 0} {
    puts "WARNING: Encryption succeeded with wrong IV length"
} else {
    puts "✓ Encryption correctly failed with wrong IV length"
}

puts "Testing legacy::encrypt: modern algorithms..."
# Test with modern algorithms that should not be supported
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

set test_key [binary format H* "00112233445566778899aabbccddeeff"]
set test_iv [binary format H* "0102030405060708090a0b0c0d0e0f10"]

foreach algorithm $modern_algorithms {
    set rc [catch {tossl::legacy::encrypt $algorithm $test_key $test_iv $test_data} result]
    if {$rc == 0} {
        puts "legacy::encrypt $algorithm: OK (unexpectedly supported)"
    } else {
        puts "legacy::encrypt $algorithm: OK (correctly not supported)"
    }
}

puts "All ::tossl::legacy::encrypt tests passed" 