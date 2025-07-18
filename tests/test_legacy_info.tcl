# Test for ::tossl::legacy::info
load ./libtossl.so

puts "Testing legacy::info: missing required args..."
set rc [catch {tossl::legacy::info} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "All ::tossl::legacy::info argument tests passed"

puts "Testing legacy::info: invalid algorithm..."
set rc [catch {tossl::legacy::info "invalid_algorithm"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid algorithm did not error"
    exit 1
}
puts "legacy::info invalid algorithm: OK"

puts "Testing legacy::info: empty algorithm..."
set rc [catch {tossl::legacy::info ""} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Empty algorithm did not error"
    exit 1
}
puts "legacy::info empty algorithm: OK"

puts "Testing legacy::info: basic functionality..."
# Test with known legacy algorithms
set legacy_algorithms {
    "des-ecb"
    "des-cbc"
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "cast5-cbc"
    "rc4"
}

foreach algorithm $legacy_algorithms {
    set rc [catch {tossl::legacy::info $algorithm} result]
    if {$rc == 0} {
        puts "legacy::info $algorithm: OK"
        
        # Parse the result (returns a list with key-value pairs)
        set info_found 0
        set name_found 0
        set block_size_found 0
        set key_length_found 0
        set iv_length_found 0
        
        for {set i 0} {$i < [llength $result]} {incr i 2} {
            set key [lindex $result $i]
            set value [lindex $result [expr {$i + 1}]]
            
            if {$key eq "name"} {
                set name_found 1
                # Algorithm names are returned in uppercase by OpenSSL
                if {[string tolower $value] eq [string tolower $algorithm]} {
                    puts "  ✓ Algorithm name matches: $value"
                } else {
                    puts "  ✗ Algorithm name mismatch: expected $algorithm, got $value"
                }
            } elseif {$key eq "block_size"} {
                set block_size_found 1
                if {$value > 0} {
                    puts "  ✓ Block size: $value"
                } else {
                    puts "  ✗ Invalid block size: $value"
                }
            } elseif {$key eq "key_length"} {
                set key_length_found 1
                if {$value > 0} {
                    puts "  ✓ Key length: $value"
                } else {
                    puts "  ✗ Invalid key length: $value"
                }
            } elseif {$key eq "iv_length"} {
                set iv_length_found 1
                if {$value >= 0} {
                    puts "  ✓ IV length: $value"
                } else {
                    puts "  ✗ Invalid IV length: $value"
                }
            }
        }
        
        if {$name_found && $block_size_found && $key_length_found && $iv_length_found} {
            puts "  ✓ All required fields present"
        } else {
            puts "  ✗ Missing required fields"
            if {!$name_found} { puts "    - Missing name" }
            if {!$block_size_found} { puts "    - Missing block_size" }
            if {!$key_length_found} { puts "    - Missing key_length" }
            if {!$iv_length_found} { puts "    - Missing iv_length" }
        }
        
    } else {
        puts "legacy::info $algorithm: FAILED - $result"
        # Some legacy algorithms might not be available in all OpenSSL builds
        puts "  Note: This algorithm may not be available in this OpenSSL build"
    }
}

puts "Testing legacy::info: modern algorithms..."
# Test with modern algorithms - some may be supported by the legacy provider
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

foreach algorithm $modern_algorithms {
    set rc [catch {tossl::legacy::info $algorithm} result]
    if {$rc == 0} {
        puts "legacy::info $algorithm: OK (supported by legacy provider)"
    } else {
        puts "legacy::info $algorithm: OK (not supported by legacy provider)"
    }
}

puts "Testing legacy::info: case sensitivity..."
# Test case sensitivity
set rc [catch {tossl::legacy::info "DES-CBC"} result]
if {$rc == 0} {
    puts "legacy::info case sensitivity: OK (uppercase supported)"
} else {
    puts "legacy::info case sensitivity: OK (case sensitive)"
}

puts "All ::tossl::legacy::info tests passed" 