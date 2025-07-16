# tests/test_ec_components.tcl ;# Test for ::tossl::ec::components

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate EC key to get a valid key
set keys [tossl::key::generate -type ec -curve $curve]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Test extracting components from private key
set rc [catch {set comps [tossl::ec::components $priv]} res]
if {$rc == 0} {
    if {![dict exists $comps curve] || ![dict exists $comps public] || ![dict exists $comps private]} {
        puts stderr ";# FAIL: missing fields in private key components: $comps"
        exit 1
    }
    puts ";# PASS: components from private key"
} else {
    puts stderr ";# FAIL: error extracting components from private key: $res"
    exit 2
}

# Test extracting components from public key
set rc [catch {set comps [tossl::ec::components $pub]} res]
if {$rc == 0} {
    if {![dict exists $comps curve] || ![dict exists $comps public]} {
        puts stderr ";# FAIL: missing fields in public key components: $comps"
        exit 3
    }
    if {[dict exists $comps private]} {
        puts stderr ";# FAIL: public key should not have private field: $comps"
        exit 4
    }
    puts ";# PASS: components from public key"
} else {
    puts stderr ";# FAIL: error extracting components from public key: $res"
    exit 5
}

# Error: invalid key
set rc [catch {tossl::ec::components "notakey"} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid key"
} else {
    puts stderr ";# FAIL: expected error on invalid key"
    exit 6
}

# Error: wrong key type (RSA)
set rsa_keys [tossl::key::generate -type rsa -bits 2048]
set rsa_pub [dict get $rsa_keys public]
set rc [catch {tossl::ec::components $rsa_pub} res]
if {$rc != 0} {
    puts ";# PASS: error on non-EC key"
} else {
    puts stderr ";# FAIL: expected error on non-EC key"
    exit 7
}

puts ";# All tests passed."
exit 0 