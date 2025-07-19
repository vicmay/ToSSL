# Test for ::tossl::rsa::sign
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::sign..."

# 1. Basic RSA sign/verify roundtrip
puts "\n1. Testing basic RSA sign/verify roundtrip..."
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "Hello, World!"
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256]
set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256]
if {$result == 1} {
    puts "PASS: Basic RSA sign/verify roundtrip"
} else {
    puts stderr "FAIL: Basic RSA sign/verify roundtrip"
    incr ::errors
}

# 2. Test with different digest algorithms
puts "\n2. Testing different digest algorithms..."
set algorithms {sha1 sha256 sha384 sha512}
foreach alg $algorithms {
    set sig [tossl::rsa::sign -key $priv -data $data -alg $alg]
    set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg $alg]
    if {$result == 1} {
        puts "PASS: RSA sign/verify with $alg"
    } else {
        puts stderr "FAIL: RSA sign/verify with $alg"
        incr ::errors
    }
}

# 3. Test with PSS padding
puts "\n3. Testing PSS padding..."
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256 -padding pss]
set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256 -padding pss]
if {$result == 1} {
    puts "PASS: RSA sign/verify with PSS padding"
} else {
    puts stderr "FAIL: RSA sign/verify with PSS padding"
    incr ::errors
}

# 4. Test with PKCS1 padding (default)
puts "\n4. Testing PKCS1 padding..."
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256 -padding pkcs1]
set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256 -padding pkcs1]
if {$result == 1} {
    puts "PASS: RSA sign/verify with PKCS1 padding"
} else {
    puts stderr "FAIL: RSA sign/verify with PKCS1 padding"
    incr ::errors
}

# 5. Test with binary data
puts "\n5. Testing with binary data..."
set data_bin [binary format H* "deadbeefcafebabe"]
set sig [tossl::rsa::sign -key $priv -data $data_bin -alg sha256]
set result [tossl::rsa::verify -key $pub -data $data_bin -sig $sig -alg sha256]
if {$result == 1} {
    puts "PASS: RSA sign/verify with binary data"
} else {
    puts stderr "FAIL: RSA sign/verify with binary data"
    incr ::errors
}

# 6. Error handling tests
puts "\n6. Testing error handling..."
if {[catch {tossl::rsa::sign} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::sign -key $priv -data $data -alg invalid} err]} {
    puts "PASS: invalid algorithm (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid algorithm should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::sign -key "invalid" -data $data -alg sha256} err]} {
    puts "PASS: invalid key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid key should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::sign -key $priv -data $data -alg sha256 -padding invalid} err]} {
    puts "PASS: invalid padding (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid padding should have errored"
    incr ::errors
}

puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::sign tests passed"
} 