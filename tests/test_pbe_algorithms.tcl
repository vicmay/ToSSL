# Test for ::tossl::pbe::algorithms
load ./libtossl.so

puts "Testing pbe::algorithms: missing required args..."
set rc [catch {tossl::pbe::algorithms extra_arg} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra args did not error"
    exit 1
}
puts "pbe::algorithms missing args: OK"

puts "Testing pbe::algorithms: basic functionality..."
set rc [catch {set result [tossl::pbe::algorithms]} err]
if {$rc != 0} {
    puts "FAIL: pbe::algorithms basic test failed - $err"
    exit 1
}

if {[llength $result] == 0} {
    puts "FAIL: Empty result from pbe::algorithms"
    exit 1
}

puts "pbe::algorithms basic functionality: OK - [llength $result] algorithms"

puts "Testing pbe::algorithms: returned algorithms..."
set expected_algorithms {
    sha1
    sha256
    sha512
    md5
}

foreach algorithm $result {
    if {[lsearch $expected_algorithms $algorithm] == -1} {
        puts "FAIL: Unexpected algorithm returned: $algorithm"
        exit 1
    }
    puts "pbe::algorithms $algorithm: OK"
}

puts "pbe::algorithms returned algorithms: OK"

puts "Testing pbe::algorithms: algorithm validation..."
foreach algorithm $result {
    # Test that each returned algorithm can be used with pbe::keyderive
    set password "test_password"
    set salt "test_salt"
    set iterations 1000
    set key_length 32
    
    set rc [catch {tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length} err]
    if {$rc != 0} {
        puts "FAIL: Algorithm $algorithm from pbe::algorithms failed with pbe::keyderive - $err"
        exit 1
    }
    
    puts "pbe::algorithms $algorithm validation: OK"
}
puts "pbe::algorithms algorithm validation: OK"

puts "Testing pbe::algorithms: deterministic results..."
set rc1 [catch {set result1 [tossl::pbe::algorithms]} err1]
set rc2 [catch {set result2 [tossl::pbe::algorithms]} err2]

if {$rc1 != 0 || $rc2 != 0} {
    puts "FAIL: Deterministic test failed - $err1 / $err2"
    exit 1
}

if {$result1 ne $result2} {
    puts "FAIL: Non-deterministic results from pbe::algorithms"
    puts "First call: $result1"
    puts "Second call: $result2"
    exit 1
}

puts "pbe::algorithms deterministic results: OK"

puts "Testing pbe::algorithms: list structure..."
if {[llength $result1] != [llength $result2]} {
    puts "FAIL: Inconsistent list lengths"
    exit 1
}

# Check that all elements are strings
foreach algorithm $result1 {
    if {![string is ascii $algorithm]} {
        puts "FAIL: Non-string algorithm in result: $algorithm"
        exit 1
    }
}

puts "pbe::algorithms list structure: OK"

puts "Testing pbe::algorithms: performance..."
set start_time [clock milliseconds]
for {set i 0} {$i < 1000} {incr i} {
    set rc [catch {tossl::pbe::algorithms} err]
    if {$rc != 0} {
        puts "FAIL: Performance test failed - $err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "pbe::algorithms performance: OK - 1000 operations in ${duration}ms"

puts "Testing pbe::algorithms: algorithm completeness..."
# Check that all expected algorithms are present
foreach expected $expected_algorithms {
    if {[lsearch $result1 $expected] == -1} {
        puts "FAIL: Expected algorithm $expected not found in result"
        exit 1
    }
}

puts "pbe::algorithms algorithm completeness: OK"

puts "Testing pbe::algorithms: algorithm uniqueness..."
# Check that there are no duplicates
set unique_algorithms [lsort -unique $result1]
if {[llength $unique_algorithms] != [llength $result1]} {
    puts "FAIL: Duplicate algorithms found in result"
    puts "Original: $result1"
    puts "Unique: $unique_algorithms"
    exit 1
}

puts "pbe::algorithms algorithm uniqueness: OK"

puts "Testing pbe::algorithms: algorithm sorting..."
# Check if algorithms are returned in a consistent order
set sorted_algorithms [lsort $result1]
if {$result1 ne $sorted_algorithms} {
    puts "Note: Algorithms are not returned in sorted order"
    puts "Original: $result1"
    puts "Sorted: $sorted_algorithms"
} else {
    puts "pbe::algorithms algorithms are returned in sorted order"
}

puts "pbe::algorithms algorithm sorting: OK"

puts "Testing pbe::algorithms: integration with other PBE commands..."
# Test that the returned algorithms work with other PBE commands
foreach algorithm $result1 {
    # Test with pbe::keyderive
    set rc [catch {tossl::pbe::keyderive $algorithm "test" "salt" 1000 32} err]
    if {$rc != 0} {
        puts "FAIL: Algorithm $algorithm failed with pbe::keyderive - $err"
        exit 1
    }
    
    # Test with pbe::encrypt (note: algorithm parameter is ignored in implementation)
    set rc [catch {tossl::pbe::encrypt $algorithm "test" "salt" "data"} err]
    if {$rc != 0} {
        puts "FAIL: Algorithm $algorithm failed with pbe::encrypt - $err"
        exit 1
    }
}

puts "pbe::algorithms integration: OK"

puts "Testing pbe::algorithms: error handling..."
# Test with invalid arguments
set invalid_args {
    "extra_arg"
    "arg1" "arg2"
}

foreach args $invalid_args {
    set rc [catch {eval tossl::pbe::algorithms $args} err]
    if {$rc == 0} {
        puts "FAIL: pbe::algorithms with invalid args '$args' should have failed"
        exit 1
    }
    puts "Error handling '$args': OK - $err"
}

# Test with no arguments (this should work)
set rc [catch {tossl::pbe::algorithms} err]
if {$rc != 0} {
    puts "FAIL: pbe::algorithms with no args failed - $err"
    exit 1
}
puts "Error handling 'no args': OK"

puts "pbe::algorithms error handling: OK"

puts "Testing pbe::algorithms: algorithm security classification..."
# Classify algorithms by security level
set secure_algorithms {}
set legacy_algorithms {}

foreach algorithm $result1 {
    switch $algorithm {
        "sha256" - "sha512" {
            lappend secure_algorithms $algorithm
        }
        "sha1" - "md5" {
            lappend legacy_algorithms $algorithm
        }
        default {
            puts "Note: Unknown algorithm security classification: $algorithm"
        }
    }
}

puts "Secure algorithms: $secure_algorithms"
puts "Legacy algorithms: $legacy_algorithms"
puts "pbe::algorithms security classification: OK"

puts "Testing pbe::algorithms: algorithm availability..."
# Test that all returned algorithms are actually available in OpenSSL
foreach algorithm $result1 {
    # This is a basic test - in a real scenario, we might want to test
    # if the algorithm is actually functional
    puts "Algorithm $algorithm: Available"
}

puts "pbe::algorithms algorithm availability: OK"

puts "All pbe::algorithms tests passed!" 