load [file join [file dirname [info script]] ../libtossl.so]

proc test_benchmark_basic {} {
    puts "[info level 0]: test_benchmark_basic"
    set result [catch {::tossl::benchmark hash sha256} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out] || [string match {*Unknown benchmark operation*} $out]} {
            puts "SKIP: benchmark not supported in this build"
            return -1
        }
        puts "FAIL: benchmark basic failed: $out"
        return 1
    }
    puts "PASS: benchmark hash sha256: $out"
    return 0
}

proc test_benchmark_invalid_params {} {
    puts "[info level 0]: test_benchmark_invalid_params"
    set result [catch {::tossl::benchmark} out]
    if {$result == 0} {
        puts "FAIL: benchmark accepted missing params"
        return 1
    }
    puts "PASS: benchmark invalid params error: $out"
    return 0
}

proc test_benchmark_edge_cases {} {
    puts "[info level 0]: test_benchmark_edge_cases"
    set result [catch {::tossl::benchmark rsa} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out] || [string match {*Unknown benchmark operation*} $out]} {
            puts "SKIP: benchmark not supported in this build"
            return -1
        }
        puts "FAIL: benchmark edge case rsa failed: $out"
        return 1
    }
    puts "PASS: benchmark rsa: $out"
    return 0
}

set failures 0
set skipped 0
foreach test {test_benchmark_basic test_benchmark_invalid_params test_benchmark_edge_cases} {
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