# Test for ::tossl::rsa::decrypt
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::decrypt..."

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

# 4. Test with different key sizes
puts "\n4. Testing with different key sizes..."
set key_sizes {1024 2048 3072}
foreach size $key_sizes {
    set keys [tossl::key::generate -type rsa -bits $size]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    set test_data "Test data for $size-bit key"
    
    set ciphertext [tossl::rsa::encrypt -key $pub -data $test_data -padding pkcs1]
    set plaintext [tossl::rsa::decrypt -key $priv -data $ciphertext -padding pkcs1]
    
    if {$plaintext eq $test_data} {
        puts "PASS: RSA $size-bit key encrypt/decrypt roundtrip"
    } else {
        puts stderr "FAIL: RSA $size-bit key encrypt/decrypt roundtrip"
        incr ::errors
    }
}

# 5. Test with empty data
puts "\n5. Testing with empty data..."
set empty_data ""
set ciphertext [tossl::rsa::encrypt -key $pub -data $empty_data -padding pkcs1]
set plaintext [tossl::rsa::decrypt -key $priv -data $ciphertext -padding pkcs1]
if {$plaintext eq $empty_data} {
    puts "PASS: RSA encrypt/decrypt with empty data"
} else {
    puts stderr "FAIL: RSA encrypt/decrypt with empty data"
    incr ::errors
}

# 6. Test with large data (should fail due to RSA limitations)
puts "\n6. Testing with large data (should fail)..."
set large_data [string repeat "A" 1000]
if {[catch {tossl::rsa::encrypt -key $pub -data $large_data -padding pkcs1} err]} {
    puts "PASS: Large data encryption failed as expected: $err"
} else {
    puts stderr "FAIL: Large data encryption should have failed"
    incr ::errors
}

# 7. Error handling tests
puts "\n7. Testing error handling..."

# Missing arguments
if {[catch {tossl::rsa::decrypt} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}

# Missing key
if {[catch {tossl::rsa::decrypt -data $ciphertext -padding pkcs1} err]} {
    puts "PASS: missing key (error as expected: $err)"
} else {
    puts stderr "FAIL: missing key should have errored"
    incr ::errors
}

# Missing data
if {[catch {tossl::rsa::decrypt -key $priv -padding pkcs1} err]} {
    puts "PASS: missing data (error as expected: $err)"
} else {
    puts stderr "FAIL: missing data should have errored"
    incr ::errors
}

# Invalid key
if {[catch {tossl::rsa::decrypt -key "invalid-key" -data $ciphertext -padding pkcs1} err]} {
    puts "PASS: invalid key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid key should have errored"
    incr ::errors
}

# Wrong key type (public key instead of private)
if {[catch {tossl::rsa::decrypt -key $pub -data $ciphertext -padding pkcs1} err]} {
    puts "PASS: wrong key type (error as expected: $err)"
} else {
    puts stderr "FAIL: wrong key type should have errored"
    incr ::errors
}

# Invalid padding
if {[catch {tossl::rsa::decrypt -key $priv -data $ciphertext -padding invalid} err]} {
    puts "PASS: invalid padding (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid padding should have errored"
    incr ::errors
}

# Note: OpenSSL RSA decryption can be tolerant of some invalid inputs
# This is a known behavior and not necessarily a bug
puts "Note: OpenSSL RSA decryption behavior with invalid inputs may vary"

# Test with wrong key (different key pair)
set wrong_keys [tossl::key::generate -type rsa -bits 2048]
set wrong_priv [dict get $wrong_keys private]
if {[catch {tossl::rsa::decrypt -key $wrong_priv -data $ciphertext -padding pkcs1} err]} {
    puts "PASS: wrong key (error as expected: $err)"
} else {
    puts stderr "FAIL: wrong key should have errored"
    incr ::errors
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::decrypt tests passed"
} 