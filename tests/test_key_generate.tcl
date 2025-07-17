# Test for ::tossl::key::generate
load ./libtossl.so

;# Test RSA key generation (default)
set rsa [tossl::key::generate]
if {![dict exists $rsa private] || ![dict exists $rsa public]} {
    puts "FAIL: RSA key missing fields"
    exit 1
}
puts "RSA default: OK"

;# Test RSA key generation with custom bits
set rsa2 [tossl::key::generate -type rsa -bits 3072]
if {![dict exists $rsa2 private] || ![dict exists $rsa2 public]} {
    puts "FAIL: RSA 3072 key missing fields"
    exit 1
}
puts "RSA 3072: OK"

;# Test EC key generation (default curve)
set ec [tossl::key::generate -type ec]
if {![dict exists $ec private] || ![dict exists $ec public]} {
    puts "FAIL: EC key missing fields"
    exit 1
}
puts "EC default: OK"

;# Test EC key generation with custom curve
set ec2 [tossl::key::generate -type ec -curve secp384r1]
if {![dict exists $ec2 private] || ![dict exists $ec2 public]} {
    puts "FAIL: EC secp384r1 key missing fields"
    exit 1
}
puts "EC secp384r1: OK"

;# Test DSA key generation (if supported)
if {[catch {set dsa [tossl::key::generate -type dsa -bits 1024]} err]} {
    puts "DSA not supported: $err"
} else {
    if {![dict exists $dsa private] || ![dict exists $dsa public]} {
        puts "FAIL: DSA key missing fields"
        exit 1
    }
    puts "DSA 1024: OK"
}

;# Error: invalid type
if {[catch {tossl::key::generate -type foo} err]} {
    puts "Invalid type error: $err"
} else {
    puts "FAIL: Invalid type did not error"
    exit 1
}

;# Error: invalid bits
if {[catch {tossl::key::generate -type rsa -bits 123} err]} {
    puts "Invalid bits error: $err"
} else {
    puts "FAIL: Invalid bits did not error"
    exit 1
}

puts "All ::tossl::key::generate tests passed" 