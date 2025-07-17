# Test for ::tossl::key::write
load ./libtossl.so

;# Generate RSA key
set rsa [tossl::key::generate -type rsa -bits 2048]
set priv_rsa [dict get $rsa private]
set pub_rsa [dict get $rsa public]
set type_rsa [dict get $rsa type]
set bits_rsa [dict get $rsa bits]

puts "DEBUG: priv_rsa length = [string length $priv_rsa]"
puts "DEBUG: priv_rsa head = [string range $priv_rsa 0 60]"

;# Write private key PEM
set priv_pem [tossl::key::write -key $priv_rsa -format pem -type private]
if {$priv_pem ne $priv_rsa} {
    puts "FAIL: RSA private PEM write"
    exit 1
}
puts "RSA private PEM write: OK"

;# Write public key PEM
set pub_pem [tossl::key::write -key $pub_rsa -format pem -type public]
if {$pub_pem ne $pub_rsa} {
    puts "FAIL: RSA public PEM write"
    exit 1
}
puts "RSA public PEM write: OK"

;# Write private key DER
set priv_der [tossl::key::write -key $priv_rsa -format der -type private]
puts "DEBUG: priv_der length = [string length $priv_der]"
puts "DEBUG: priv_der hex head = [binary encode hex [string range $priv_der 0 16]]"
if {[string length $priv_der] < 200} {
    puts "FAIL: RSA private DER write (too short)"
    exit 1
}
puts "RSA private DER write: OK"

;# Write public key DER
set pub_der [tossl::key::write -key $pub_rsa -format der -type public]
if {[string length $pub_der] < 40} {
    puts "FAIL: RSA public DER write (too short)"
    exit 1
}
puts "RSA public DER write: OK"

;# Repeat for EC key
set ec [tossl::key::generate -type ec -curve prime256v1]
set priv_ec [dict get $ec private]
set pub_ec [dict get $ec public]
set type_ec [dict get $ec type]
set bits_ec [dict get $ec bits]
set curve_ec [dict get $ec curve]

set priv_pem_ec [tossl::key::write -key $priv_ec -format pem -type private]
if {$priv_pem_ec ne $priv_ec} {
    puts "FAIL: EC private PEM write"
    exit 1
}
puts "EC private PEM write: OK"

set pub_pem_ec [tossl::key::write -key $pub_ec -format pem -type public]
if {$pub_pem_ec ne $pub_ec} {
    puts "FAIL: EC public PEM write"
    exit 1
}
puts "EC public PEM write: OK"

set priv_der_ec [tossl::key::write -key $priv_ec -format der -type private]
if {[string length $priv_der_ec] < 40} {
    puts "FAIL: EC private DER write (too short)"
    exit 1
}
puts "EC private DER write: OK"

set pub_der_ec [tossl::key::write -key $pub_ec -format der -type public]
if {[string length $pub_der_ec] < 40} {
    puts "FAIL: EC public DER write (too short)"
    exit 1
}
puts "EC public DER write: OK"

;# DSA (if supported)
if {[catch {set dsa [tossl::key::generate -type dsa -bits 1024]} err]} {
    puts "DSA not supported: $err"
} else {
    set priv_dsa [dict get $dsa private]
    set pub_dsa [dict get $dsa public]
    set type_dsa [dict get $dsa type]
    set bits_dsa [dict get $dsa bits]
    set priv_pem_dsa [tossl::key::write -key $priv_dsa -format pem -type private]
    if {$priv_pem_dsa ne $priv_dsa} {
        puts "FAIL: DSA private PEM write"
        exit 1
    }
    puts "DSA private PEM write: OK"
    set pub_pem_dsa [tossl::key::write -key $pub_dsa -format pem -type public]
    if {$pub_pem_dsa ne $pub_dsa} {
        puts "FAIL: DSA public PEM write"
        exit 1
    }
    puts "DSA public PEM write: OK"
    set priv_der_dsa [tossl::key::write -key $priv_dsa -format der -type private]
    if {[string length $priv_der_dsa] < 40} {
        puts "FAIL: DSA private DER write (too short)"
        exit 1
    }
    puts "DSA private DER write: OK"
    set pub_der_dsa [tossl::key::write -key $pub_dsa -format der -type public]
    if {[string length $pub_der_dsa] < 40} {
        puts "FAIL: DSA public DER write (too short)"
        exit 1
    }
    puts "DSA public DER write: OK"
}

;# Error: missing fields (empty string)
if {[catch {tossl::key::write -key "" -format pem -type private} err]} {
    puts "Missing field error: $err"
} else {
    puts "FAIL: Missing field did not error"
    exit 1
}

;# Error: unknown type (invalid PEM)
if {[catch {tossl::key::write -key "not a key" -format pem -type private} err]} {
    puts "Unknown type error: $err"
} else {
    puts "FAIL: Unknown type did not error"
    exit 1
}

puts "All ::tossl::key::write tests passed" 