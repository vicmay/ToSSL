load [file join [file dirname [info script]] ../libtossl.so]

proc toHex {bytes} {
    binary scan $bytes H* hex
    return $hex
}

proc test_pbkdf2_basic {} {
    puts "[info level 0]: test_pbkdf2_basic"
    set result [catch {::tossl::pbkdf2 -pass password -salt salt -iter 10000 -len 32 -digest sha256} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: PBKDF2 not supported in this build"
            return -1
        }
        puts "FAIL: pbkdf2 basic failed: $out"
        return 1
    }
    if {[string length $out] != 32} {
        puts "FAIL: pbkdf2 output length unexpected: [string length $out] (expected 32)"
        puts "Output (hex): [toHex $out]"
        return 1
    }
    puts "PASS: pbkdf2 basic output (hex): [toHex $out]"
    return 0
}

proc test_pbkdf2_invalid_params {} {
    puts "[info level 0]: test_pbkdf2_invalid_params"
    set result [catch {::tossl::pbkdf2} out]
    if {$result == 0} {
        puts "FAIL: pbkdf2 accepted missing params"
        return 1
    }
    puts "PASS: pbkdf2 invalid params error: $out"
    return 0
}

proc test_pbkdf2_edge_cases {} {
    puts "[info level 0]: test_pbkdf2_edge_cases"
    set result [catch {::tossl::pbkdf2 -pass "" -salt "" -iter 1 -len 16 -digest sha256} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: PBKDF2 not supported in this build"
            return -1
        }
        puts "FAIL: pbkdf2 edge case empty input: $out"
        return 1
    }
    puts "PASS: pbkdf2 edge case empty input"
    return 0
}

set failures 0
set skipped 0
foreach test {test_pbkdf2_basic test_pbkdf2_invalid_params test_pbkdf2_edge_cases} {
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