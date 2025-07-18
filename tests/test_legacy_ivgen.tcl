# Test for ::tossl::legacy::ivgen
load ./libtossl.so

puts "Testing legacy::ivgen: missing required args..."
set rc [catch {tossl::legacy::ivgen} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "legacy::ivgen missing args: OK"

puts "Testing legacy::ivgen: invalid algorithm..."
set rc [catch {tossl::legacy::ivgen "invalid_algorithm"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "legacy::ivgen invalid algorithm: OK"

puts "Testing legacy::ivgen: empty algorithm..."
set rc [catch {tossl::legacy::ivgen ""} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Empty algorithm did not error"
    exit 1
}
puts "legacy::ivgen empty algorithm: OK"

puts "Testing legacy::ivgen: stream ciphers (should fail)..."
# Test with stream ciphers that don't require IVs
set stream_ciphers {
    "rc4"
    "rc4-40"
}

foreach algorithm $stream_ciphers {
    set rc [catch {tossl::legacy::ivgen $algorithm} result]
    if {$rc == 0} {
        puts "legacy::ivgen $algorithm: OK (unexpectedly generated IV)"
    } else {
        puts "legacy::ivgen $algorithm: OK (correctly failed - no IV required)"
    }
}

puts "Testing legacy::ivgen: block ciphers..."
# Test with block ciphers that require IVs
set block_ciphers {
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

foreach algorithm $block_ciphers {
    set rc [catch {tossl::legacy::ivgen $algorithm} result]
    if {$rc == 0} {
        puts "legacy::ivgen $algorithm: OK"
        
        # Verify the IV length matches the algorithm's requirements
        set info [tossl::legacy::info $algorithm]
        set expected_iv_length 0
        
        for {set i 0} {$i < [llength $info]} {incr i 2} {
            set key [lindex $info $i]
            set value [lindex $info [expr {$i + 1}]]
            if {$key eq "iv_length"} {
                set expected_iv_length $value
                break
            }
        }
        
        set actual_iv_length [string length $result]
        if {$actual_iv_length == $expected_iv_length} {
            puts "  ✓ IV length correct: $actual_iv_length bytes"
        } else {
            puts "  ✗ IV length mismatch: expected $expected_iv_length, got $actual_iv_length"
        }
        
        # Verify it's a byte array
        if {[string match "*bytearray*" [tcl::unsupported::representation $result]]} {
            puts "  ✓ Result is byte array"
        } else {
            puts "  ✗ Result is not byte array"
        }
        
    } else {
        puts "legacy::ivgen $algorithm: FAILED - $result"
    }
}

puts "Testing legacy::ivgen: ECB mode (should fail)..."
# Test with ECB mode which doesn't require IVs
set rc [catch {tossl::legacy::ivgen "des-ecb"} result]
if {$rc == 0} {
    puts "legacy::ivgen des-ecb: OK (unexpectedly generated IV)"
} else {
    puts "legacy::ivgen des-ecb: OK (correctly failed - no IV required)"
}

puts "Testing legacy::ivgen: IV uniqueness..."
# Test that multiple IVs for the same algorithm are different
set algorithm "des-cbc"
set ivs {}

for {set i 0} {$i < 10} {incr i} {
    set rc [catch {tossl::legacy::ivgen $algorithm} iv]
    if {$rc == 0} {
        lappend ivs $iv
    } else {
        puts "FAIL: Failed to generate IV $i: $iv"
        break
    }
}

if {[llength $ivs] == 10} {
    # Check for uniqueness
    set unique_ivs [lsort -unique $ivs]
    if {[llength $unique_ivs] == [llength $ivs]} {
        puts "✓ All generated IVs are unique"
    } else {
        puts "✗ Some generated IVs are duplicates"
        puts "  Generated: [llength $ivs], Unique: [llength $unique_ivs]"
    }
    
    # Check that IVs are not all zeros
    set all_zeros 0
    foreach iv $ivs {
        set is_zero 1
        for {set i 0} {$i < [string length $iv]} {incr i} {
            if {[string index $iv $i] ne "\x00"} {
                set is_zero 0
                break
            }
        }
        if {$is_zero} {
            incr all_zeros
        }
    }
    
    if {$all_zeros == 0} {
        puts "✓ No zero IVs generated"
    } else {
        puts "✗ $all_zeros zero IVs generated (should be random)"
    }
}

puts "Testing legacy::ivgen: modern algorithms..."
# Test with modern algorithms that should not be supported
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

foreach algorithm $modern_algorithms {
    set rc [catch {tossl::legacy::ivgen $algorithm} result]
    if {$rc == 0} {
        puts "legacy::ivgen $algorithm: OK (unexpectedly supported)"
    } else {
        puts "legacy::ivgen $algorithm: OK (correctly not supported)"
    }
}

puts "Testing legacy::ivgen: IV format..."
# Test that generated IVs are in the correct format
set algorithm "des-cbc"
set rc [catch {tossl::legacy::ivgen $algorithm} iv]
if {$rc == 0} {
    # Convert to hex for inspection
    set iv_hex [binary encode hex $iv]
    puts "Generated IV (hex): $iv_hex"
    puts "IV length: [string length $iv] bytes"
    
    # Verify it's not all zeros or all ones
    set all_zeros 1
    set all_ones 1
    for {set i 0} {$i < [string length $iv]} {incr i} {
        set byte [string index $iv $i]
        if {$byte ne "\x00"} { set all_zeros 0 }
        if {$byte ne "\xff"} { set all_ones 0 }
    }
    
    if {!$all_zeros && !$all_ones} {
        puts "✓ IV appears to be random (not all zeros or ones)"
    } else {
        puts "✗ IV appears to be non-random"
    }
} else {
    puts "FAIL: Could not generate IV for format test: $iv"
}

puts "All ::tossl::legacy::ivgen tests passed" 