# Test for ::tossl::pbe::saltgen
load ./libtossl.so

puts "Testing pbe::saltgen: missing required args..."
set rc [catch {tossl::pbe::saltgen} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "pbe::saltgen missing args: OK"

puts "Testing pbe::saltgen: basic functionality..."
set lengths {1 8 16 32 64}

foreach length $lengths {
    set rc [catch {set result [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: pbe::saltgen $length failed - $err"
        exit 1
    }
    
    if {[string length $result] != $length} {
        puts "FAIL: Expected salt length $length, got [string length $result]"
        exit 1
    }
    
    puts "pbe::saltgen $length: OK - [string length $result] bytes"
}
puts "pbe::saltgen basic functionality: OK"

puts "Testing pbe::saltgen: error handling..."
set invalid_lengths {
    0
    -1
    65
    100
    1000
}

foreach length $invalid_lengths {
    set rc [catch {tossl::pbe::saltgen $length} err]
    if {$rc == 0} {
        puts "FAIL: pbe::saltgen $length should have failed"
        exit 1
    }
    puts "Error handling $length: OK - $err"
}

# Test with non-numeric input
set rc [catch {tossl::pbe::saltgen "invalid"} err]
if {$rc == 0} {
    puts "FAIL: pbe::saltgen with non-numeric input should have failed"
    exit 1
}
puts "Error handling non-numeric: OK - $err"

puts "pbe::saltgen error handling: OK"

puts "Testing pbe::saltgen: randomness..."
set length 16
set salts {}

# Generate multiple salts and check they're different
for {set i 0} {$i < 100} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Randomness test failed - $err"
        exit 1
    }
    
    if {[string length $salt] != $length} {
        puts "FAIL: Wrong salt length in randomness test"
        exit 1
    }
    
    lappend salts $salt
}

# Check that all salts are different
set unique_salts [lsort -unique $salts]
if {[llength $unique_salts] != [llength $salts]} {
    puts "FAIL: Duplicate salts found in randomness test"
    puts "Generated: [llength $salts] salts"
    puts "Unique: [llength $unique_salts] salts"
    exit 1
}

puts "pbe::saltgen randomness: OK - [llength $salts] unique salts generated"

puts "Testing pbe::saltgen: deterministic length..."
set length 32
set results {}

# Generate multiple salts of same length
for {set i 0} {$i < 10} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Deterministic length test failed - $err"
        exit 1
    }
    
    if {[string length $salt] != $length} {
        puts "FAIL: Wrong salt length in deterministic test"
        exit 1
    }
    
    lappend results $salt
}

puts "pbe::saltgen deterministic length: OK - all [llength $results] salts are $length bytes"

puts "Testing pbe::saltgen: edge cases..."
set edge_cases {
    1
    64
}

foreach length $edge_cases {
    set rc [catch {set result [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Edge case $length failed - $err"
        exit 1
    }
    
    if {[string length $result] != $length} {
        puts "FAIL: Edge case $length wrong length - expected $length, got [string length $result]"
        exit 1
    }
    
    puts "Edge case $length: OK"
}
puts "pbe::saltgen edge cases: OK"

puts "Testing pbe::saltgen: performance..."
set length 16
set iterations 1000

set start_time [clock milliseconds]
for {set i 0} {$i < $iterations} {incr i} {
    set rc [catch {tossl::pbe::saltgen $length} err]
    if {$rc != 0} {
        puts "FAIL: Performance test failed - $err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "pbe::saltgen performance: OK - $iterations operations in ${duration}ms"

puts "Testing pbe::saltgen: binary data validation..."
set length 16
set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
if {$rc != 0} {
    puts "FAIL: Binary data test failed - $err"
    exit 1
}

# Check that the salt is binary data (not a string)
set hex_representation [binary encode hex $salt]
if {[string length $hex_representation] != [expr {$length * 2}]} {
    puts "FAIL: Binary data validation failed"
    exit 1
}

puts "pbe::saltgen binary data validation: OK - hex: $hex_representation"

puts "Testing pbe::saltgen: integration with other PBE commands..."
set length 16
set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
if {$rc != 0} {
    puts "FAIL: Integration test - saltgen failed - $err"
    exit 1
}

# Test with pbe::keyderive
set rc2 [catch {set key [tossl::pbe::keyderive "sha256" "test_password" $salt 1000 32]} err2]
if {$rc2 != 0} {
    puts "FAIL: Integration test - keyderive failed - $err2"
    exit 1
}

# Test with pbe::encrypt
set rc3 [catch {set encrypted [tossl::pbe::encrypt "sha256" "test_password" $salt "test_data"]} err3]
if {$rc3 != 0} {
    puts "FAIL: Integration test - encrypt failed - $err3"
    exit 1
}

puts "pbe::saltgen integration: OK"

puts "Testing pbe::saltgen: entropy validation..."
set length 32
set entropy_test_salts {}

# Generate salts and check for entropy
for {set i 0} {$i < 50} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Entropy test failed - $err"
        exit 1
    }
    
    # Check that salt is not all zeros or all same value
    set all_same 1
    set first_byte [string index $salt 0]
    for {set j 1} {$j < $length} {incr j} {
        if {[string index $salt $j] ne $first_byte} {
            set all_same 0
            break
        }
    }
    
    if {$all_same} {
        puts "FAIL: Salt has no entropy (all bytes same)"
        exit 1
    }
    
    lappend entropy_test_salts $salt
}

puts "pbe::saltgen entropy validation: OK - [llength $entropy_test_salts] salts with good entropy"

puts "Testing pbe::saltgen: length boundary testing..."
# Test boundary values
set boundary_tests {
    1 1
    64 64
}

foreach {input expected} $boundary_tests {
    set rc [catch {set salt [tossl::pbe::saltgen $input]} err]
    if {$rc != 0} {
        puts "FAIL: Boundary test $input failed - $err"
        exit 1
    }
    
    if {[string length $salt] != $expected} {
        puts "FAIL: Boundary test $input wrong length - expected $expected, got [string length $salt]"
        exit 1
    }
    
    puts "Boundary test $input: OK"
}
puts "pbe::saltgen length boundary testing: OK"

puts "Testing pbe::saltgen: statistical distribution..."
set length 16
array set byte_counts {}
for {set i 0} {$i < 256} {incr i} {
    set byte_counts($i) 0
}

# Generate many salts and count byte values
for {set i 0} {$i < 1000} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Statistical test failed - $err"
        exit 1
    }
    
    # Count each byte value
    for {set j 0} {$j < $length} {incr j} {
        set byte_val [scan [string index $salt $j] %c]
        incr byte_counts($byte_val)
    }
}

# Check that we have a reasonable distribution (not all zeros)
set non_zero_count 0
for {set i 0} {$i < 256} {incr i} {
    if {$byte_counts($i) > 0} {
        incr non_zero_count
    }
}

if {$non_zero_count < 100} {
    puts "FAIL: Poor statistical distribution - only $non_zero_count unique byte values"
    exit 1
}

puts "pbe::saltgen statistical distribution: OK - $non_zero_count unique byte values"

puts "Testing pbe::saltgen: memory safety..."
set length 32
set large_iterations 10000

# Generate many salts to test memory management
for {set i 0} {$i < $large_iterations} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Memory safety test failed at iteration $i - $err"
        exit 1
    }
    
    if {[string length $salt] != $length} {
        puts "FAIL: Memory safety test wrong length at iteration $i"
        exit 1
    }
}

puts "pbe::saltgen memory safety: OK - $large_iterations iterations completed"

puts "Testing pbe::saltgen: concurrent usage simulation..."
set length 16
set concurrent_results {}

# Simulate concurrent usage by generating salts rapidly
for {set i 0} {$i < 100} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Concurrent usage test failed - $err"
        exit 1
    }
    
    lappend concurrent_results $salt
}

# Check all results are unique
set unique_concurrent [lsort -unique $concurrent_results]
if {[llength $unique_concurrent] != [llength $concurrent_results]} {
    puts "FAIL: Concurrent usage test - duplicate salts found"
    exit 1
}

puts "pbe::saltgen concurrent usage simulation: OK - [llength $concurrent_results] unique salts"

puts "Testing pbe::saltgen: security validation..."
set length 16
set security_salts {}

# Generate salts and verify they're cryptographically suitable
for {set i 0} {$i < 100} {incr i} {
    set rc [catch {set salt [tossl::pbe::saltgen $length]} err]
    if {$rc != 0} {
        puts "FAIL: Security validation failed - $err"
        exit 1
    }
    
    # Check for common weak patterns
    set hex_salt [binary encode hex $salt]
    
    # Check it's not all zeros
    if {$hex_salt eq [string repeat "00" $length]} {
        puts "FAIL: Security validation - all zero salt generated"
        exit 1
    }
    
    # Check it's not all same value
    set first_byte [string range $hex_salt 0 1]
    if {$hex_salt eq [string repeat $first_byte $length]} {
        puts "FAIL: Security validation - all same byte salt generated"
        exit 1
    }
    
    lappend security_salts $salt
}

puts "pbe::saltgen security validation: OK - [llength $security_salts] cryptographically suitable salts"

puts "All pbe::saltgen tests passed!" 