load [file join [file dirname [info script]] ../libtossl.so]

proc test_cryptolog_basic {} {
    puts "[info level 0]: test_cryptolog_basic"
    set result [catch {::tossl::cryptolog status} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out]} {
            puts "SKIP: cryptolog not supported in this build"
            return -1
        }
        puts "FAIL: cryptolog basic failed: $out"
        return 1
    }
    puts "PASS: cryptolog status: $out"
    return 0
}

proc test_cryptolog_invalid_params {} {
    puts "[info level 0]: test_cryptolog_invalid_params"
    set result [catch {::tossl::cryptolog} out]
    if {$result == 0} {
        puts "FAIL: cryptolog accepted missing params"
        return 1
    }
    puts "PASS: cryptolog invalid params error: $out"
    return 0
}

proc test_cryptolog_edge_cases {} {
    puts "[info level 0]: test_cryptolog_edge_cases"
    set result [catch {::tossl::cryptolog clear} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out]} {
            puts "SKIP: cryptolog not supported in this build"
            return -1
        }
        puts "FAIL: cryptolog edge case clear failed: $out"
        return 1
    }
    puts "PASS: cryptolog clear: $out"
    return 0
}

set failures 0
set skipped 0
foreach test {test_cryptolog_basic test_cryptolog_invalid_params test_cryptolog_edge_cases} {
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