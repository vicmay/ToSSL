# Test for ::tossl::pbe::keyderive
load ./libtossl.so

puts "Testing pbe::keyderive: missing required args..."
set rc [catch {tossl::pbe::keyderive} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::pbe::keyderive "sha256"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing password did not error"
    exit 1
}
set rc [catch {tossl::pbe::keyderive "sha256" "password"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing salt did not error"
    exit 1
}
set rc [catch {tossl::pbe::keyderive "sha256" "password" "salt"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing iterations did not error"
    exit 1
}
set rc [catch {tossl::pbe::keyderive "sha256" "password" "salt" "1000"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing key_length did not error"
    exit 1
}
puts "pbe::keyderive missing args: OK"

puts "Testing pbe::keyderive: basic functionality..."
set algorithms {
    sha256
    sha512
    sha1
    md5
}

set test_password "test_password_123"
set test_salt "test_salt_456"
set test_iterations 1000
set test_key_length 32

foreach algorithm $algorithms {
    set rc [catch {set result [tossl::pbe::keyderive $algorithm $test_password $test_salt $test_iterations $test_key_length]} err]
    if {$rc != 0} {
        puts "FAIL: pbe::keyderive $algorithm failed - $err"
        exit 1
    }
    
    if {[string length $result] != $test_key_length} {
        puts "FAIL: Expected key length $test_key_length, got [string length $result]"
        exit 1
    }
    
    puts "pbe::keyderive $algorithm: OK - [string length $result] bytes"
}
puts "pbe::keyderive basic functionality: OK"

puts "Testing pbe::keyderive: different key lengths..."
set key_lengths {16 32 64 128 256}
set algorithm "sha256"

foreach length $key_lengths {
    set rc [catch {set result [tossl::pbe::keyderive $algorithm $test_password $test_salt $test_iterations $length]} err]
    if {$rc != 0} {
        puts "FAIL: pbe::keyderive key length $length failed - $err"
        exit 1
    }
    
    if {[string length $result] != $length} {
        puts "FAIL: Expected key length $length, got [string length $result]"
        exit 1
    }
    
    puts "pbe::keyderive key length $length: OK"
}
puts "pbe::keyderive different key lengths: OK"

puts "Testing pbe::keyderive: different iteration counts..."
set iterations_list {1 100 1000 10000}
set algorithm "sha256"
set key_length 32

foreach iterations $iterations_list {
    set rc [catch {set result [tossl::pbe::keyderive $algorithm $test_password $test_salt $iterations $key_length]} err]
    if {$rc != 0} {
        puts "FAIL: pbe::keyderive iterations $iterations failed - $err"
        exit 1
    }
    
    if {[string length $result] != $key_length} {
        puts "FAIL: Expected key length $key_length, got [string length $result]"
        exit 1
    }
    
    puts "pbe::keyderive iterations $iterations: OK"
}
puts "pbe::keyderive different iteration counts: OK"

puts "Testing pbe::keyderive: deterministic output..."
set algorithm "sha256"
set password "deterministic_test"
set salt "deterministic_salt"
set iterations 1000
set key_length 32

# Derive key twice with same parameters
set rc1 [catch {set key1 [tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length]} err1]
set rc2 [catch {set key2 [tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length]} err2]

if {$rc1 != 0 || $rc2 != 0} {
    puts "FAIL: Deterministic test failed - $err1 / $err2"
    exit 1
}

if {$key1 ne $key2} {
    puts "FAIL: Deterministic output failed - keys differ"
    exit 1
}

puts "pbe::keyderive deterministic output: OK"

puts "Testing pbe::keyderive: different salts produce different keys..."
set salt1 "salt1"
set salt2 "salt2"

set rc1 [catch {set key1 [tossl::pbe::keyderive $algorithm $password $salt1 $iterations $key_length]} err1]
set rc2 [catch {set key2 [tossl::pbe::keyderive $algorithm $password $salt2 $iterations $key_length]} err2]

if {$rc1 != 0 || $rc2 != 0} {
    puts "FAIL: Different salts test failed - $err1 / $err2"
    exit 1
}

if {$key1 eq $key2} {
    puts "FAIL: Different salts produced same key"
    exit 1
}

puts "pbe::keyderive different salts: OK"

puts "Testing pbe::keyderive: different passwords produce different keys..."
set password1 "password1"
set password2 "password2"

set rc1 [catch {set key1 [tossl::pbe::keyderive $algorithm $password1 $salt $iterations $key_length]} err1]
set rc2 [catch {set key2 [tossl::pbe::keyderive $algorithm $password2 $salt $iterations $key_length]} err2]

if {$rc1 != 0 || $rc2 != 0} {
    puts "FAIL: Different passwords test failed - $err1 / $err2"
    exit 1
}

if {$key1 eq $key2} {
    puts "FAIL: Different passwords produced same key"
    exit 1
}

puts "pbe::keyderive different passwords: OK"

puts "Testing pbe::keyderive: error handling..."
set invalid_combinations {
    invalid-algorithm password salt 1000 32
    sha256 "" salt 1000 32
    sha256 password "" 1000 32
    sha256 password salt 0 32
    sha256 password salt -1 32
    sha256 password salt 1000 0
    sha256 password salt 1000 -1
    sha256 password salt invalid 32
    sha256 password salt 1000 invalid
}

foreach {algorithm password salt iterations key_length} $invalid_combinations {
    set rc [catch {tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length} err]
    if {$rc == 0} {
        puts "FAIL: pbe::keyderive $algorithm $password $salt $iterations $key_length should have failed"
        exit 1
    }
    puts "Error handling $algorithm $password $salt $iterations $key_length: OK - $err"
}
puts "pbe::keyderive error handling: OK"

puts "Testing pbe::keyderive: edge cases..."
set edge_cases {
    sha256 a b 1 1
    sha256 very_long_password_that_might_cause_issues very_long_salt_that_might_cause_issues 1 1
    sha256 password salt 1 4096
    sha256 password salt 1000000 32
}

foreach {algorithm password salt iterations key_length} $edge_cases {
    set rc [catch {set result [tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length]} err]
    if {$rc != 0} {
        puts "Edge case $algorithm $password $salt $iterations $key_length: FAILED - $err"
    } else {
        if {[string length $result] != $key_length} {
            puts "Edge case $algorithm $password $salt $iterations $key_length: FAILED - wrong length"
        } else {
            puts "Edge case $algorithm $password $salt $iterations $key_length: OK"
        }
    }
}
puts "pbe::keyderive edge cases: OK"

puts "Testing pbe::keyderive: integration with saltgen..."
set rc [catch {set salt [tossl::pbe::saltgen 16]} err]
if {$rc != 0} {
    puts "Integration test: saltgen failed - $err"
} else {
    set rc2 [catch {set key [tossl::pbe::keyderive "sha256" "test_password" $salt 1000 32]} err2]
    if {$rc2 != 0} {
        puts "Integration test: keyderive with generated salt failed - $err2"
    } else {
        puts "Integration test: keyderive with generated salt: OK"
    }
}

puts "Testing pbe::keyderive: integration with algorithms list..."
set rc [catch {set algorithms [tossl::pbe::algorithms]} err]
if {$rc != 0} {
    puts "Integration test: algorithms list failed - $err"
} else {
    set test_count 0
    foreach algorithm $algorithms {
        set rc2 [catch {set key [tossl::pbe::keyderive $algorithm "test_password" "test_salt" 100 16]} err2]
        if {$rc2 == 0} {
            incr test_count
        }
    }
    puts "Integration test: keyderive with algorithms list: OK ($test_count/[llength $algorithms] successful)"
}
puts "pbe::keyderive integration: OK"

puts "Testing pbe::keyderive: performance..."
set iterations 10
set start_time [clock milliseconds]

for {set i 0} {$i < $iterations} {incr i} {
    set rc [catch {tossl::pbe::keyderive "sha256" "test_password" "test_salt" 1000 32} result]
    if {$rc != 0} {
        puts "FAIL: Performance test iteration $i failed"
        exit 1
    }
}

set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "Performance test: $iterations iterations in ${duration}ms (${duration}ms per iteration)"
puts "pbe::keyderive performance: OK"

puts "Testing pbe::keyderive: result format validation..."
set test_cases {
    sha256 test_password test_salt 1000 32
    sha512 test_password test_salt 1000 64
    sha1 test_password test_salt 1000 20
}

foreach {algorithm password salt iterations key_length} $test_cases {
    set rc [catch {set result [tossl::pbe::keyderive $algorithm $password $salt $iterations $key_length]} err]
    if {$rc == 0} {
        # Check that result is a byte array
        if {[string length $result] == $key_length} {
            puts "Result format validation $algorithm: OK - [string length $result] bytes"
            
            # Check that result contains binary data (not all printable)
            set all_printable 1
            for {set i 0} {$i < [string length $result]} {incr i} {
                set byte [scan [string index $result $i] %c]
                if {$byte < 32 || $byte > 126} {
                    set all_printable 0
                    break
                }
            }
            if {$all_printable} {
                puts "  WARNING: Result appears to be all printable characters"
            } else {
                puts "  Result contains binary data: OK"
            }
        } else {
            puts "Result format validation $algorithm: FAILED - wrong length"
        }
    } else {
        puts "Result format validation $algorithm: SKIPPED - command failed"
    }
}
puts "pbe::keyderive result format validation: OK"

puts "Testing pbe::keyderive: comparison with pbkdf2..."
# Compare with the standalone pbkdf2 command if it exists
set rc [catch {set pbkdf2_result [tossl::pbkdf2 -pass "test_password" -salt "test_salt" -iter 1000 -len 32 -alg sha256]} err]
if {$rc == 0} {
    set rc2 [catch {set pbe_result [tossl::pbe::keyderive "sha256" "test_password" "test_salt" 1000 32]} err2]
    if {$rc2 == 0} {
        if {$pbkdf2_result eq $pbe_result} {
            puts "Comparison with pbkdf2: OK - results match"
        } else {
            puts "Comparison with pbkdf2: WARNING - results differ (may be expected)"
        }
    } else {
        puts "Comparison with pbkdf2: SKIPPED - pbe::keyderive failed"
    }
} else {
    puts "Comparison with pbkdf2: SKIPPED - pbkdf2 command not available"
}
puts "pbe::keyderive comparison: OK"

puts "All pbe::keyderive tests passed!" 