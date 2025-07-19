# Test for ::tossl::rsa::verify
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::verify..."

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
        puts "PASS: RSA verify with $alg"
    } else {
        puts stderr "FAIL: RSA verify with $alg"
        incr ::errors
    }
}

# 3. Test with PSS padding
puts "\n3. Testing PSS padding..."
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256 -padding pss]
set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256 -padding pss]
if {$result == 1} {
    puts "PASS: RSA verify with PSS padding"
} else {
    puts stderr "FAIL: RSA verify with PSS padding"
    incr ::errors
}

# 4. Test with PKCS1 padding (default)
puts "\n4. Testing PKCS1 padding..."
set sig [tossl::rsa::sign -key $priv -data $data -alg sha256 -padding pkcs1]
set result [tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256 -padding pkcs1]
if {$result == 1} {
    puts "PASS: RSA verify with PKCS1 padding"
} else {
    puts stderr "FAIL: RSA verify with PKCS1 padding"
    incr ::errors
}

# 5. Test with wrong data (should fail)
puts "\n5. Testing with wrong data..."
set wrong_data "Wrong data!"
set result [tossl::rsa::verify -key $pub -data $wrong_data -sig $sig -alg sha256 -padding pkcs1]
if {$result == 0} {
    puts "PASS: RSA verify with wrong data (correctly failed)"
} else {
    puts stderr "FAIL: RSA verify with wrong data (should have failed)"
    incr ::errors
}

# 6. Test with wrong signature (should fail)
puts "\n6. Testing with wrong signature..."
set wrong_sig [string repeat "A" [string length $sig]]
set result [tossl::rsa::verify -key $pub -data $data -sig $wrong_sig -alg sha256 -padding pkcs1]
if {$result == 0} {
    puts "PASS: RSA verify with wrong signature (correctly failed)"
} else {
    puts stderr "FAIL: RSA verify with wrong signature (should have failed)"
    incr ::errors
}

# 7. Test with wrong key (should fail)
puts "\n7. Testing with wrong key..."
set wrong_keys [tossl::key::generate -type rsa -bits 2048]
set wrong_pub [dict get $wrong_keys public]
set result [tossl::rsa::verify -key $wrong_pub -data $data -sig $sig -alg sha256 -padding pkcs1]
if {$result == 0} {
    puts "PASS: RSA verify with wrong key (correctly failed)"
} else {
    puts stderr "FAIL: RSA verify with wrong key (should have failed)"
    incr ::errors
}

# 8. Error handling tests
puts "\n8. Testing error handling..."
if {[catch {tossl::rsa::verify} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}
# Test with missing algorithm (should use default sha256)
set result [tossl::rsa::verify -key $pub -data $data -sig $sig]
if {$result == 1} {
    puts "PASS: missing algorithm (uses default sha256)"
} else {
    puts stderr "FAIL: missing algorithm should use default sha256"
    incr ::errors
}
if {[catch {tossl::rsa::verify -key "invalid" -data $data -sig $sig -alg sha256} err]} {
    puts "PASS: invalid key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid key should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::verify -key $pub -data $data -sig $sig -alg sha256 -padding invalid} err]} {
    puts "PASS: invalid padding (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid padding should have errored"
    incr ::errors
}

puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::verify tests passed"
} 