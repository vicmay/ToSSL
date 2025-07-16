# tests/test_dsa_generate_params.tcl ;# Test for ::tossl::dsa::generate_params

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Helper to check if PEM looks like DSA parameters
proc is_dsa_params_pem {pem} {
    return [string match "-----BEGIN DSA PARAMETERS*" $pem]
}

# Default: no arguments
set rc [catch {set pem [tossl::dsa::generate_params]} res]
if {$rc == 0 && [is_dsa_params_pem $pem]} {
    puts ";# PASS: generate default params"
} else {
    puts stderr ";# FAIL: generate default params: $res"
    exit 1
}

# Valid bits: 1024
set rc [catch {set pem [tossl::dsa::generate_params -bits 1024]} res]
if {$rc == 0 && [is_dsa_params_pem $pem]} {
    puts ";# PASS: generate 1024-bit params"
} else {
    puts stderr ";# FAIL: generate 1024-bit params: $res"
    exit 2
}

# Valid bits: 3072
set rc [catch {set pem [tossl::dsa::generate_params -bits 3072]} res]
if {$rc == 0 && [is_dsa_params_pem $pem]} {
    puts ";# PASS: generate 3072-bit params"
} else {
    puts stderr ";# FAIL: generate 3072-bit params: $res"
    exit 3
}

# Invalid bits: 0
set rc [catch {tossl::dsa::generate_params -bits 0} res]
if {$rc != 0} {
    puts ";# PASS: error on bits=0"
} else {
    puts stderr ";# FAIL: expected error on bits=0"
    exit 4
}

# Invalid bits: negative
set rc [catch {tossl::dsa::generate_params -bits -2048} res]
if {$rc != 0} {
    puts ";# PASS: error on negative bits"
} else {
    puts stderr ";# FAIL: expected error on negative bits"
    exit 5
}

# Invalid bits: non-integer
set rc [catch {tossl::dsa::generate_params -bits foo} res]
if {$rc != 0} {
    puts ";# PASS: error on non-integer bits"
} else {
    puts stderr ";# FAIL: expected error on non-integer bits"
    exit 6
}

# Extra/unknown argument
set rc [catch {tossl::dsa::generate_params -foo bar} res]
if {$rc != 0} {
    puts ";# PASS: error on unknown argument"
} else {
    puts stderr ";# FAIL: expected error on unknown argument"
    exit 7
}

# All tests passed.
puts ";# All tests passed."
exit 0 