load [file join [file dirname [info script]] ../libtossl.so]

proc toHex {bytes} {
    binary scan $bytes H* hex
    return $hex
}

proc test_hmac_basic {} {
    puts "[info level 0]: test_hmac_basic"
    set key [binary format a* [binary format H* 00112233445566778899aabbccddeeff]]
    set data [binary format a* "hello world"]
    puts "DEBUG: key type: [tcl::unsupported::representation $key]"
    puts "DEBUG: data type: [tcl::unsupported::representation $data]"
    puts "DEBUG: args: ::tossl::hmac -alg sha256 -key $key $data"
    puts "DEBUG: arg count: [llength [list -alg sha256 -key $key $data]]"
    set result [catch {eval ::tossl::hmac -alg sha256 -key $key $data} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: HMAC not supported in this build"
            return -1
        }
        puts "FAIL: hmac basic failed: $out"
        return 1
    }
    if {[string length $out] != 64} {
        puts "FAIL: hmac output length unexpected: [string length $out] (expected 64 hex chars)"
        puts "Output: $out"
        return 1
    }
    puts "PASS: hmac basic output: $out"
    return 0
}

proc test_hmac_invalid_params {} {
    puts "[info level 0]: test_hmac_invalid_params"
    set result [catch {::tossl::hmac} out]
    if {$result == 0} {
        puts "FAIL: hmac accepted missing params"
        return 1
    }
    puts "PASS: hmac invalid params error: $out"
    return 0
}

proc test_hmac_edge_cases {} {
    puts "[info level 0]: test_hmac_edge_cases"
    set key [binary format a* ""]
    set data [binary format a* ""]
    puts "DEBUG: key type: [tcl::unsupported::representation $key]"
    puts "DEBUG: data type: [tcl::unsupported::representation $data]"
    puts "DEBUG: args: ::tossl::hmac -alg sha256 -key $key $data"
    puts "DEBUG: arg count: [llength [list -alg sha256 -key $key $data]]"
    set result [catch {eval ::tossl::hmac -alg sha256 -key $key $data} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out]} {
            puts "SKIP: HMAC not supported in this build"
            return -1
        }
        if {[string match {*wrong # args*} $out] || [string match {*missing*} $out]} {
            puts "PASS: hmac edge case empty input error as expected: $out"
            return 0
        }
        puts "FAIL: hmac edge case empty input: $out"
        return 1
    }
    puts "FAIL: hmac edge case empty input should have errored"
    return 1
}

set failures 0
set skipped 0
foreach test {test_hmac_basic test_hmac_invalid_params test_hmac_edge_cases} {
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