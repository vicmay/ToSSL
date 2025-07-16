# tests/test_dsa_validate.tcl ;# Test for ::tossl::dsa::validate

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Generate DSA key
set dsa_rc [catch {set keys [tossl::key::generate -type dsa -bits 2048]} dsa_keys]
if {$dsa_rc != 0} {
    puts ";# SKIP: DSA not supported on this build"
    exit 0
}
set priv [dict get $keys private]
set pub  [dict get $keys public]

# Normal case: validate private key
set rc [catch {set result [tossl::dsa::validate -key $priv]} res]
if {$rc == 0 && $result == 1} {
    puts ";# PASS: validate private key (valid)"
} else {
    puts stderr ";# FAIL: validate private key: $res"
    exit 1
}

# Normal case: validate public key
set rc [catch {set result [tossl::dsa::validate -key $pub]} res]
if {$rc == 0 && $result == 1} {
    puts ";# PASS: validate public key (valid)"
} else {
    puts stderr ";# FAIL: validate public key: $res"
    exit 2
}

# Error: invalid key string
set rc [catch {tossl::dsa::validate -key "notakey"} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid key string"
} else {
    puts stderr ";# FAIL: expected error on invalid key string"
    exit 3
}

# Error: wrong key type (RSA)
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_pub [dict get $rsa_keys public]
set rc [catch {tossl::dsa::validate -key $rsa_pub} res]
if {$rc != 0} {
    puts ";# PASS: error on non-DSA key"
} else {
    puts stderr ";# FAIL: expected error on non-DSA key"
    exit 4
}

# Error: truncated DSA key
set truncated [string range $priv 0 20]
set rc [catch {tossl::dsa::validate -key $truncated} res]
if {$rc != 0} {
    puts ";# PASS: error on truncated DSA key"
} else {
    puts stderr ";# FAIL: expected error on truncated DSA key"
    exit 5
}

# Error: missing argument
set rc [catch {tossl::dsa::validate} res]
if {$rc != 0} {
    puts ";# PASS: error on missing argument"
} else {
    puts stderr ";# FAIL: expected error on missing argument"
    exit 6
}

puts ";# All tests passed."
exit 0 