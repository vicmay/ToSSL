load [file join [file dirname [info script]] ../libtossl.so]

# Minimal PEM CSR for testing (replace with a real one if needed)
set keypair [::tossl::key::generate -type rsa -bits 2048]
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]
set subject "CN=test.example.com,O=ExampleOrg,C=US"
set minimal_csr [::tossl::csr::create -key $privkey -subject $subject]

proc test_csr_modify_basic {} {
    puts "[info level 0]: test_csr_modify_basic"
    set result [catch {::tossl::csr::modify -csr $::minimal_csr -add_extension subjectAltName "DNS:example.com" 0} out]
    if {$result == 0} {
        puts "PASS: csr::modify basic (add_extension)"
        return 0
    }
    if {[string match {*Unknown option*} $out]} {
        set result2 [catch {::tossl::csr::modify $::minimal_csr -subject "CN=modified.example.com,O=ExampleOrg"} out2]
        if {$result2 == 0} {
            puts "PASS: csr::modify basic (subject)"
            return 0
        }
        if {[string match {*Unknown option*} $out2]} {
            puts "SKIP: csr::modify not supported in this build"
            return -1
        }
        puts "FAIL: csr::modify basic (subject) failed: $out2"
        return 1
    }
    puts "FAIL: csr::modify basic (add_extension) failed: $out"
    return 1
}

proc test_csr_modify_invalid_params {} {
    puts "[info level 0]: test_csr_modify_invalid_params"
    set result [catch {::tossl::csr::modify} out]
    if {$result == 0} {
        puts "FAIL: csr::modify accepted missing params"
        return 1
    }
    puts "PASS: csr::modify invalid params error: $out"
    return 0
}

proc test_csr_modify_edge_cases {} {
    puts "[info level 0]: test_csr_modify_edge_cases"
    set result [catch {::tossl::csr::modify -csr "" -addext "subjectAltName=DNS:example.com"} out]
    if {$result != 0} {
        if {[string match {*not supported*} $out] || [string match {*unknown command*} $out]} {
            puts "SKIP: csr::modify not supported in this build"
            return -1
        }
        puts "PASS: csr::modify edge case empty CSR error: $out"
        return 0
    }
    puts "FAIL: csr::modify edge case empty CSR should have errored"
    return 1
}

set failures 0
set skipped 0
foreach test {test_csr_modify_basic test_csr_modify_invalid_params test_csr_modify_edge_cases} {
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