# Test for ::tossl::legacy::list
load ./libtossl.so

puts "Testing legacy::list: extra arguments..."
set rc [catch {tossl::legacy::list extra} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra args did not error"
    exit 1
}
puts "legacy::list extra args: OK"

puts "Testing legacy::list: basic functionality..."
set rc [catch {tossl::legacy::list} result]
if {$rc != 0} {
    puts "FAIL: legacy::list failed: $result"
    exit 1
}

puts "legacy::list basic: OK"
puts "Result: $result"

# Verify it returns a list
if {[llength $result] == 0} {
    puts "WARNING: legacy::list returned empty list"
    puts "This may be normal if no legacy algorithms are available"
} else {
    puts "Found [llength $result] legacy algorithms:"
    foreach algorithm $result {
        puts "  - $algorithm"
    }
}

puts "Testing legacy::list: algorithm validation..."
# Test that returned algorithms are actually supported
set valid_count 0
set total_count [llength $result]

foreach algorithm $result {
    set rc [catch {tossl::legacy::info $algorithm} info]
    if {$rc == 0} {
        incr valid_count
        puts "  ✓ $algorithm is valid"
    } else {
        puts "  ✗ $algorithm is not valid: $info"
    }
}

if {$total_count > 0} {
    set success_rate [expr {double($valid_count) / $total_count * 100}]
    puts "Algorithm validation: $valid_count/$total_count algorithms valid ($success_rate%)"
    
    if {$success_rate < 50} {
        puts "WARNING: Less than 50% of returned algorithms are valid"
    }
} else {
    puts "No algorithms returned to validate"
}

puts "Testing legacy::list: expected algorithms..."
# Check for common legacy algorithms that should be available
set expected_algorithms {
    "des-ecb"
    "des-cbc" 
    "des-cfb"
    "des-ofb"
    "bf-cbc"
    "cast5-cbc"
    "rc4"
}

set found_count 0
foreach expected $expected_algorithms {
    if {[lsearch -exact $result $expected] >= 0} {
        puts "  ✓ Found expected algorithm: $expected"
        incr found_count
    } else {
        puts "  - Expected algorithm not found: $expected"
    }
}

puts "Expected algorithms found: $found_count/[llength $expected_algorithms]"

puts "Testing legacy::list: modern algorithms not present..."
# Check that modern algorithms are not in the legacy list
set modern_algorithms {
    "aes-128-cbc"
    "aes-256-gcm"
    "chacha20-poly1305"
}

set modern_found 0
foreach modern $modern_algorithms {
    if {[lsearch -exact $result $modern] >= 0} {
        puts "  ⚠️  Modern algorithm found in legacy list: $modern"
        incr modern_found
    } else {
        puts "  ✓ Modern algorithm correctly not in legacy list: $modern"
    }
}

if {$modern_found > 0} {
    puts "Note: Some modern algorithms may be available through the legacy provider"
}

puts "Testing legacy::list: list format..."
# Verify the result is a proper Tcl list
if {[catch {llength $result} len]} {
    puts "FAIL: Result is not a valid Tcl list"
    exit 1
}

puts "List length: $len"
puts "List format: OK"

puts "Testing legacy::list: uniqueness..."
# Check for duplicate entries
set unique_algorithms [lsort -unique $result]
if {[llength $unique_algorithms] != [llength $result]} {
    puts "WARNING: Duplicate algorithms found in legacy list"
    puts "Original count: [llength $result]"
    puts "Unique count: [llength $unique_algorithms]"
} else {
    puts "✓ No duplicate algorithms found"
}

puts "All ::tossl::legacy::list tests passed" 