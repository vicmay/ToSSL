load [file join [file dirname [info script]] ../libtossl.so]

proc toHex {bytes} {
    binary scan $bytes H* hex
    return $hex
}

proc test_decrypt_basic {} {
    puts "[info level 0]: test_decrypt_basic"
    set key [binary format H* 00112233445566778899aabbccddeeff]
    set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
    set plaintext [binary format a* "Secret message!"]
    set ciphertext [::tossl::encrypt -alg aes-128-cbc -key $key -iv $iv -format binary $plaintext]
    set result [catch {::tossl::decrypt -alg aes-128-cbc -key $key -iv $iv $ciphertext} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out]} {
            puts "SKIP: decrypt not supported in this build"
            return -1
        }
        puts "FAIL: decrypt basic failed: $out"
        return 1
    }
    if {![string equal $out $plaintext]} {
        puts "FAIL: decrypt output mismatch: $out"
        return 1
    }
    puts "PASS: decrypt roundtrip"
    return 0
}

proc test_decrypt_invalid_params {} {
    puts "[info level 0]: test_decrypt_invalid_params"
    set result [catch {::tossl::decrypt} out]
    if {$result == 0} {
        puts "FAIL: decrypt accepted missing params"
        return 1
    }
    puts "PASS: decrypt invalid params error: $out"
    return 0
}

proc test_decrypt_edge_cases {} {
    puts "[info level 0]: test_decrypt_edge_cases"
    set key [binary format H* 00112233445566778899aabbccddeeff]
    set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
    set result [catch {::tossl::decrypt -alg aes-128-cbc -key $key -iv $iv ""} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out]} {
            puts "SKIP: decrypt not supported in this build"
            return -1
        }
        puts "PASS: decrypt edge case empty input error: $out"
        return 0
    }
    puts "FAIL: decrypt edge case empty input should have errored"
    return 1
}

set failures 0
set skipped 0
foreach test {test_decrypt_basic test_decrypt_invalid_params test_decrypt_edge_cases} {
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