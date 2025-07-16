load [file join [file dirname [info script]] ../libtossl.so]
# Test suite for ::tossl::argon2
# This file tests the ::tossl::argon2 command for basic functionality, error handling, and edge cases.

proc toHex {bytes} {
    binary scan $bytes H* hex
    return $hex
}

proc test_argon2_basic {} {
    puts "[info level 0]: test_argon2_basic"
    set result [catch {::tossl::argon2 -pass password -salt salt -t 2 -m 16 -p 1 -len 32} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: Argon2 not supported in this build"
            return -1
        }
        puts "FAIL: argon2 basic failed: $out"
        return 1
    }
    if {[string length $out] != 32} {
        puts "FAIL: argon2 output length unexpected: [string length $out] (expected 32)"
        puts "Output (hex): [toHex $out]"
        return 1
    }
    puts "PASS: argon2 basic output (hex): [toHex $out]"
    return 0
}

proc test_argon2_invalid_params {} {
    puts "[info level 0]: test_argon2_invalid_params"
    set result [catch {::tossl::argon2} out]
    if {$result == 0} {
        puts "FAIL: argon2 accepted missing params"
        return 1
    }
    puts "PASS: argon2 invalid params error: $out"
    return 0
}

proc test_argon2_edge_cases {} {
    puts "[info level 0]: test_argon2_edge_cases"
    set result [catch {::tossl::argon2 -pass "" -salt "" -t 1 -m 8 -p 1 -len 16} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: Argon2 not supported in this build"
            return -1
        }
        puts "FAIL: argon2 edge case empty input: $out"
        return 1
    }
    puts "PASS: argon2 edge case empty input"
    return 0
}

set failures 0
set skipped 0
foreach test {test_argon2_basic test_argon2_invalid_params test_argon2_edge_cases} {
    set res [$test]
    if {$res == 1} {incr failures}
    if {$res == -1} {incr skipped}
}

if {$failures == 0 && $skipped == 0} {
    puts "ALL TESTS PASSED"
    exit 0
} elseif {$failures == 0 && $skipped > 0} {
    puts "ALL TESTS PASSED ($skipped SKIPPED)"
    exit 0
} else {
    puts "SOME TESTS FAILED: $failures ($skipped SKIPPED)"
    exit 1
} 