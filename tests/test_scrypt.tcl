load [file join [file dirname [info script]] ../libtossl.so]

proc toHex {bytes} {
    binary scan $bytes H* hex
    return $hex
}

proc test_scrypt_basic {} {
    puts "[info level 0]: test_scrypt_basic"
    set result [catch {::tossl::scrypt -pass password -salt salt -n 16384 -r 8 -p 1 -len 32} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: Scrypt not supported in this build"
            return -1
        }
        puts "FAIL: scrypt basic failed: $out"
        return 1
    }
    if {[string length $out] != 32} {
        puts "FAIL: scrypt output length unexpected: [string length $out] (expected 32)"
        puts "Output (hex): [toHex $out]"
        return 1
    }
    puts "PASS: scrypt basic output (hex): [toHex $out]"
    return 0
}

proc test_scrypt_invalid_params {} {
    puts "[info level 0]: test_scrypt_invalid_params"
    set result [catch {::tossl::scrypt} out]
    if {$result == 0} {
        puts "FAIL: scrypt accepted missing params"
        return 1
    }
    puts "PASS: scrypt invalid params error: $out"
    return 0
}

proc test_scrypt_edge_cases {} {
    puts "[info level 0]: test_scrypt_edge_cases"
    set result [catch {::tossl::scrypt -pass "" -salt "" -n 1024 -r 8 -p 1 -len 16} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: Scrypt not supported in this build"
            return -1
        }
        puts "FAIL: scrypt edge case empty input: $out"
        return 1
    }
    puts "PASS: scrypt edge case empty input"
    return 0
}

set failures 0
set skipped 0
foreach test {test_scrypt_basic test_scrypt_invalid_params test_scrypt_edge_cases} {
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