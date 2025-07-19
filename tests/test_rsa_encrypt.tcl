# Test for ::tossl::rsa::encrypt
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::encrypt..."

# 1. Basic RSA encrypt/decrypt roundtrip (PKCS1)
puts "\n1. Testing basic RSA encrypt/decrypt roundtrip (PKCS1)..."
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "Hello, World!"
set ciphertext [tossl::rsa::encrypt -key $pub -data $data -padding pkcs1]
set plaintext [tossl::rsa::decrypt -key $priv -data $ciphertext -padding pkcs1]
if {$plaintext eq $data} {
    puts "PASS: Basic RSA encrypt/decrypt roundtrip (PKCS1)"
} else {
    puts stderr "FAIL: Basic RSA encrypt/decrypt roundtrip (PKCS1)"
    incr ::errors
}

# 2. Basic RSA encrypt/decrypt roundtrip (OAEP)
puts "\n2. Testing basic RSA encrypt/decrypt roundtrip (OAEP)..."
set ciphertext [tossl::rsa::encrypt -key $pub -data $data -padding oaep]
set plaintext [tossl::rsa::decrypt -key $priv -data $ciphertext -padding oaep]
if {$plaintext eq $data} {
    puts "PASS: Basic RSA encrypt/decrypt roundtrip (OAEP)"
} else {
    puts stderr "FAIL: Basic RSA encrypt/decrypt roundtrip (OAEP)"
    incr ::errors
}

# 3. Test with binary data
puts "\n3. Testing with binary data..."
set data_bin [binary format H* "deadbeefcafebabe"]
set ciphertext [tossl::rsa::encrypt -key $pub -data $data_bin -padding pkcs1]
set plaintext [tossl::rsa::decrypt -key $priv -data $ciphertext -padding pkcs1]
if {$plaintext eq $data_bin} {
    puts "PASS: RSA encrypt/decrypt with binary data"
} else {
    puts stderr "FAIL: RSA encrypt/decrypt with binary data"
    incr ::errors
}

# 4. Error handling tests
puts "\n4. Testing error handling..."
if {[catch {tossl::rsa::encrypt} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::encrypt -key $pub -data $data -padding invalid} err]} {
    puts "PASS: invalid padding (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid padding should have errored"
    incr ::errors
}
if {[catch {tossl::rsa::encrypt -key "invalid" -data $data -padding pkcs1} err]} {
    puts "PASS: invalid key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid key should have errored"
    incr ::errors
}
puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::encrypt tests passed"
} 