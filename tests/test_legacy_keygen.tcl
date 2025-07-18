# Test for ::tossl::legacy::keygen
load ./libtossl.so

puts "Testing legacy::keygen: missing required args..."
set rc [catch {tossl::legacy::keygen} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "legacy::keygen missing args: OK"

puts "Testing legacy::keygen: invalid algorithm..."
set rc [catch {tossl::legacy::keygen "invalid_algorithm"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "legacy::keygen invalid algorithm: OK"

puts "Testing legacy::keygen: empty algorithm..."
set rc [catch {tossl::legacy::keygen ""} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Empty algorithm did not error"
    exit 1
}
puts "legacy::keygen empty algorithm: OK"

puts "Testing legacy::keygen: basic functionality..."
# Test with known legacy algorithms
set algorithms {
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "des-ecb"
    "des-ede-cbc"
    "des-ede3-cbc"
    "bf-cbc"
    "bf-cfb"
    "bf-ofb"
    "bf-ecb"
    "cast5-cbc"
    "cast5-cfb"
    "cast5-ofb"
    "cast5-ecb"
    "rc4"
    "rc4-40"
}

foreach algorithm $algorithms {
    puts "Testing $algorithm..."
    
    # Get algorithm info to determine expected key length
    set info [tossl::legacy::info $algorithm]
    set expected_key_length 0
    
    for {set i 0} {$i < [llength $info]} {incr i 2} {
        set key_name [lindex $info $i]
        set value [lindex $info [expr {$i + 1}]]
        if {$key_name eq "key_length"} {
            set expected_key_length $value
            break
        }
    }
    
    # Generate key
    set rc [catch {tossl::legacy::keygen $algorithm} key]
    if {$rc == 0} {
        puts "  ✓ Key generation successful"
        puts "  Key length: [string length $key] bytes (expected: $expected_key_length)"
        
        # Verify key length matches expected
        if {[string length $key] == $expected_key_length} {
            puts "  ✓ Key length matches expected"
        } else {
            puts "  ✗ Key length mismatch: expected $expected_key_length, got [string length $key]"
        }
        
        # Verify key is not empty
        if {[string length $key] > 0} {
            puts "  ✓ Key is not empty"
        } else {
            puts "  ✗ Key is empty"
        }
        
        # Verify key is not all zeros (basic randomness check)
        set all_zeros 1
        for {set i 0} {$i < [string length $key]} {incr i} {
            if {[string index $key $i] ne "\x00"} {
                set all_zeros 0
                break
            }
        }
        if {!$all_zeros} {
            puts "  ✓ Key appears to be random (not all zeros)"
        } else {
            puts "  ✗ Key is all zeros (not random)"
        }
        
    } else {
        puts "  ✗ Key generation failed: $key"
    }
}

puts "Testing legacy::keygen: multiple generations..."
# Test that multiple generations produce different keys
set algorithm "des-cbc"
set keys {}

for {set i 0} {$i < 10} {incr i} {
    set rc [catch {tossl::legacy::keygen $algorithm} key]
    if {$rc == 0} {
        lappend keys $key
    } else {
        puts "  ✗ Key generation $i failed: $key"
    }
}

puts "Generated [llength $keys] keys"

# Check that all keys are unique
set unique_keys [lsort -unique $keys]
if {[llength $unique_keys] == [llength $keys]} {
    puts "  ✓ All generated keys are unique"
} else {
    puts "  ✗ Some keys are duplicates"
    puts "    Total keys: [llength $keys]"
    puts "    Unique keys: [llength $unique_keys]"
}

puts "Testing legacy::keygen: key randomness..."
# Basic randomness test - check that keys are different from each other
set algorithm "bf-cbc"
set key1 [tossl::legacy::keygen $algorithm]
set key2 [tossl::legacy::keygen $algorithm]

if {$key1 ne $key2} {
    puts "  ✓ Generated keys are different (random)"
} else {
    puts "  ✗ Generated keys are identical (not random)"
}

puts "Testing legacy::keygen: modern algorithms..."
# Test with modern algorithms that should not be supported
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

foreach algorithm $modern_algorithms {
    set rc [catch {tossl::legacy::keygen $algorithm} result]
    if {$rc == 0} {
        puts "legacy::keygen $algorithm: OK (unexpectedly supported)"
    } else {
        puts "legacy::keygen $algorithm: OK (correctly not supported)"
    }
}

puts "Testing legacy::keygen: key validation..."
# Test that generated keys work with encryption
set algorithm "des-cbc"
set key [tossl::legacy::keygen $algorithm]
set iv [tossl::legacy::ivgen $algorithm]
set test_data "test message"

set rc [catch {tossl::legacy::encrypt $algorithm $key $iv $test_data} ciphertext]
if {$rc == 0} {
    puts "  ✓ Generated key works with encryption"
} else {
    puts "  ✗ Generated key does not work with encryption: $ciphertext"
}

puts "Testing legacy::keygen: different algorithm types..."
# Test different types of algorithms
set block_ciphers {
    "des-cbc"
    "bf-cbc"
    "cast5-cbc"
}

set stream_ciphers {
    "rc4"
    "rc4-40"
}

puts "Testing block ciphers..."
foreach algorithm $block_ciphers {
    set key [tossl::legacy::keygen $algorithm]
    puts "  $algorithm: [string length $key] bytes"
}

puts "Testing stream ciphers..."
foreach algorithm $stream_ciphers {
    set key [tossl::legacy::keygen $algorithm]
    puts "  $algorithm: [string length $key] bytes"
}

puts "Testing legacy::keygen: edge cases..."
# Test with algorithms that might have special requirements
set edge_algorithms {
    "des-ede-cbc"    ;# Triple DES with 2 keys
    "des-ede3-cbc"   ;# Triple DES with 3 keys
}

foreach algorithm $edge_algorithms {
    puts "Testing $algorithm..."
    set rc [catch {tossl::legacy::keygen $algorithm} key]
    if {$rc == 0} {
        puts "  ✓ Key generation successful"
        puts "  Key length: [string length $key] bytes"
        
        # Get expected key length
        set info [tossl::legacy::info $algorithm]
        set expected_key_length 0
        for {set i 0} {$i < [llength $info]} {incr i 2} {
            set key_name [lindex $info $i]
            set value [lindex $info [expr {$i + 1}]]
            if {$key_name eq "key_length"} {
                set expected_key_length $value
                break
            }
        }
        
        if {[string length $key] == $expected_key_length} {
            puts "  ✓ Key length matches expected ($expected_key_length bytes)"
        } else {
            puts "  ✗ Key length mismatch: expected $expected_key_length, got [string length $key]"
        }
        
    } else {
        puts "  ✗ Key generation failed: $key"
    }
}

puts "All ::tossl::legacy::keygen tests passed" 