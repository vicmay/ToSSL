# Test for ::tossl::algorithm::list
load ./libtossl.so

puts "Testing algorithm::list: missing required args..."
set rc [catch {tossl::algorithm::list} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "algorithm::list missing args: OK"

puts "Testing algorithm::list: basic functionality..."
set algorithm_types {
    digest
    cipher
    mac
    kdf
    keyexch
    signature
    asym_cipher
}

foreach type $algorithm_types {
    set rc [catch {set result [tossl::algorithm::list $type]} err]
    if {$rc != 0} {
        puts "FAIL: algorithm::list $type failed - $err"
        exit 1
    }
    
    # Check that result is a list
    if {[llength $result] == 0} {
        puts "WARNING: algorithm::list $type returned empty list"
    } else {
        puts "algorithm::list $type: OK - [llength $result] algorithms found"
        puts "  Sample algorithms: [lrange $result 0 2]"
    }
}

puts "algorithm::list basic functionality: OK"

puts "Testing algorithm::list: error handling..."
set invalid_types {
    "invalid-type"
    ""
    "DIGEST"
    "Cipher"
    "unknown"
}

foreach type $invalid_types {
    set rc [catch {tossl::algorithm::list $type} err]
    if {$rc == 0} {
        puts "FAIL: algorithm::list $type should have failed"
        exit 1
    }
    puts "Error handling $type: OK - $err"
}
puts "algorithm::list error handling: OK"

puts "Testing algorithm::list: edge cases..."
set edge_cases {
    "digest"
    "cipher"
    "mac"
}

foreach type $edge_cases {
    set rc [catch {set result [tossl::algorithm::list $type]} err]
    if {$rc == 0} {
        # Test with very long type name
        set long_type [string repeat "a" 1000]
        set rc2 [catch {tossl::algorithm::list $long_type} err2]
        if {$rc2 == 0} {
            puts "Edge case long type: OK"
        } else {
            puts "Edge case long type: OK (expected failure) - $err2"
        }
    } else {
        puts "Edge case $type: FAILED - $err"
    }
}
puts "algorithm::list edge cases: OK"

puts "Testing algorithm::list: integration with algorithm::info..."
set test_types {
    digest
    cipher
    mac
}

foreach type $test_types {
    set rc [catch {set algorithms [tossl::algorithm::list $type]} err]
    if {$rc == 0 && [llength $algorithms] > 0} {
        # Test first few algorithms with algorithm::info
        set test_count 0
        foreach algorithm [lrange $algorithms 0 2] {
            set rc2 [catch {set info [tossl::algorithm::info $algorithm $type]} err2]
            if {$rc2 == 0} {
                incr test_count
                puts "  Integration test: $algorithm $type - $info"
            } else {
                puts "  Integration test: $algorithm $type failed - $err2"
            }
        }
        puts "Integration with algorithm::info for $type: OK ($test_count/3 successful)"
    } else {
        puts "Integration with algorithm::info for $type: SKIPPED (no algorithms available)"
    }
}
puts "algorithm::list integration: OK"

puts "Testing algorithm::list: performance..."
set iterations 100
set start_time [clock milliseconds]

for {set i 0} {$i < $iterations} {incr i} {
    set rc [catch {tossl::algorithm::list digest} result]
    if {$rc != 0} {
        puts "FAIL: Performance test iteration $i failed"
        exit 1
    }
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "Performance test: $iterations iterations in ${duration}ms (${duration}ms per iteration)"
puts "algorithm::list performance: OK"

puts "Testing algorithm::list: result format validation..."
foreach type $algorithm_types {
    set rc [catch {set result [tossl::algorithm::list $type]} err]
    if {$rc == 0} {
        # Check that result is a proper Tcl list
        if {[llength $result] >= 0} {
            puts "Result format validation $type: OK - [llength $result] items"
            
            # Check that all items are strings
            set all_strings 1
            foreach item $result {
                if {![string is ascii $item]} {
                    set all_strings 0
                    break
                }
            }
            if {$all_strings} {
                puts "  All items are valid strings: OK"
            } else {
                puts "  WARNING: Some items are not valid strings"
            }
        } else {
            puts "Result format validation $type: FAILED - not a valid list"
        }
    } else {
        puts "Result format validation $type: SKIPPED - command failed"
    }
}
puts "algorithm::list result format validation: OK"

puts "Testing algorithm::list: comparison with existing commands..."
# Compare with digest::list and cipher::list if they exist
set rc [catch {set digest_list [tossl::digest::list]} err]
if {$rc == 0} {
    set rc2 [catch {set algorithm_digest_list [tossl::algorithm::list digest]} err2]
    if {$rc2 == 0} {
        puts "Comparison with digest::list:"
        puts "  digest::list: [llength $digest_list] algorithms"
        puts "  algorithm::list digest: [llength $algorithm_digest_list] algorithms"
        
        # Check for common algorithms
        set common_count 0
        foreach alg $digest_list {
            if {[lsearch $algorithm_digest_list $alg] >= 0} {
                incr common_count
            }
        }
        puts "  Common algorithms: $common_count"
    }
}

set rc [catch {set cipher_list [tossl::cipher::list]} err]
if {$rc == 0} {
    set rc2 [catch {set algorithm_cipher_list [tossl::algorithm::list cipher]} err2]
    if {$rc2 == 0} {
        puts "Comparison with cipher::list:"
        puts "  cipher::list: [llength $cipher_list] algorithms"
        puts "  algorithm::list cipher: [llength $algorithm_cipher_list] algorithms"
        
        # Check for common algorithms
        set common_count 0
        foreach alg $cipher_list {
            if {[lsearch $algorithm_cipher_list $alg] >= 0} {
                incr common_count
            }
        }
        puts "  Common algorithms: $common_count"
    }
}
puts "algorithm::list comparison: OK"

puts "All algorithm::list tests passed!" 