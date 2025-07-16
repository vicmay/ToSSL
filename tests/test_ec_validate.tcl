# tests/test_ec_validate.tcl ;# Test for ::tossl::ec::validate

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate EC key to get a valid key
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Normal case: validate private key
set rc [catch {set result [tossl::ec::validate $priv]} res]
if {$rc == 0 && $result == 1} {
    puts ";# PASS: validate private key (valid)"
} else {
    puts stderr ";# FAIL: validate private key: $res"
    exit 1
}

# Normal case: validate public key
set rc [catch {set result [tossl::ec::validate $pub]} res]
if {$rc == 0 && $result == 1} {
    puts ";# PASS: validate public key (valid)"
} else {
    puts stderr ";# FAIL: validate public key: $res"
    exit 2
}

# Error: invalid key string
set rc [catch {tossl::ec::validate "notakey"} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid key string"
} else {
    puts stderr ";# FAIL: expected error on invalid key string"
    exit 3
}

# Error: wrong key type (RSA)
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_pub [dict get $rsa_keys public]
set rc [catch {tossl::ec::validate $rsa_pub} res]
if {$rc != 0} {
    puts ";# PASS: error on non-EC key"
} else {
    puts stderr ";# FAIL: expected error on non-EC key"
    exit 4
}

# Error: truncated EC key
set truncated [string range $priv 0 20]
set rc [catch {tossl::ec::validate $truncated} res]
if {$rc != 0} {
    puts ";# PASS: error on truncated EC key"
} else {
    puts stderr ";# FAIL: expected error on truncated EC key"
    exit 5
}

puts ";# All tests passed."
exit 0 