# Test for ::tossl::rsa::generate
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::generate..."

# 1. Basic RSA key generation (default 2048 bits)
puts "\n1. Testing basic RSA key generation (default)..."
if {[catch {set keys [tossl::rsa::generate]} err]} {
    puts stderr "FAIL: Basic RSA key generation failed: $err"
    incr ::errors
} else {
    if {[dict exists $keys private] && [dict exists $keys public]} {
        puts "PASS: Basic RSA key generation"
    } else {
        puts stderr "FAIL: Basic RSA key generation missing fields"
        incr ::errors
    }
}

# 2. RSA key generation with different bit sizes
puts "\n2. Testing RSA key generation with different bit sizes..."
set bit_sizes {1024 2048 3072 4096}
foreach bits $bit_sizes {
    if {[catch {set keys [tossl::rsa::generate -bits $bits]} err]} {
        puts stderr "FAIL: RSA $bits-bit key generation failed: $err"
        incr ::errors
    } else {
        if {[dict exists $keys private] && [dict exists $keys public]} {
            puts "PASS: RSA $bits-bit key generation"
        } else {
            puts stderr "FAIL: RSA $bits-bit key generation missing fields"
            incr ::errors
        }
    }
}

# 3. Validate generated keys
puts "\n3. Testing validation of generated keys..."
set keys [tossl::rsa::generate -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]

# Validate private key
if {[catch {set valid_priv [tossl::rsa::validate -key $priv]} err]} {
    puts stderr "FAIL: Private key validation failed: $err"
    incr ::errors
} else {
    if {$valid_priv == 1} {
        puts "PASS: Generated private key is valid"
    } else {
        puts stderr "FAIL: Generated private key is invalid"
        incr ::errors
    }
}

# Validate public key
if {[catch {set valid_pub [tossl::rsa::validate -key $pub]} err]} {
    puts stderr "FAIL: Public key validation failed: $err"
    incr ::errors
} else {
    if {$valid_pub == 1} {
        puts "PASS: Generated public key is valid"
    } else {
        puts stderr "FAIL: Generated public key is invalid"
        incr ::errors
    }
}

# 4. Test key functionality (encrypt/decrypt roundtrip)
puts "\n4. Testing key functionality (encrypt/decrypt roundtrip)..."
set test_data "Hello, RSA!"
if {[catch {
    set ciphertext [tossl::rsa::encrypt -key $pub -data $test_data -padding pkcs1]
    set decrypted [tossl::rsa::decrypt -key $priv -data $ciphertext -padding pkcs1]
} err]} {
    puts stderr "FAIL: Key functionality test failed: $err"
    incr ::errors
} else {
    if {$decrypted eq $test_data} {
        puts "PASS: Key functionality test (encrypt/decrypt roundtrip)"
    } else {
        puts stderr "FAIL: Key functionality test failed - data mismatch"
        incr ::errors
    }
}

# 5. Test key functionality (sign/verify roundtrip)
puts "\n5. Testing key functionality (sign/verify roundtrip)..."
if {[catch {
    set signature [tossl::rsa::sign -key $priv -data $test_data -alg sha256]
    set verified [tossl::rsa::verify -key $pub -data $test_data -sig $signature -alg sha256]
} err]} {
    puts stderr "FAIL: Key functionality test (sign/verify) failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Key functionality test (sign/verify roundtrip)"
    } else {
        puts stderr "FAIL: Key functionality test (sign/verify) failed - verification failed"
        incr ::errors
    }
}

# 6. Test key components extraction
puts "\n6. Testing key components extraction..."
if {[catch {set components [tossl::rsa::components -key $priv]} err]} {
    puts stderr "FAIL: Key components extraction failed: $err"
    incr ::errors
} else {
    if {[dict exists $components n] && [dict exists $components e] && [dict exists $components d]} {
        puts "PASS: Key components extraction"
    } else {
        puts stderr "FAIL: Key components extraction missing required fields"
        incr ::errors
    }
}

# 7. Error handling tests
puts "\n7. Testing error handling..."

# Invalid bit size (too small)
if {[catch {tossl::rsa::generate -bits 100} err]} {
    puts "PASS: Invalid bit size (too small) - error as expected: $err"
} else {
    puts stderr "FAIL: Invalid bit size (too small) should have errored"
    incr ::errors
}

# Invalid bit size (negative)
if {[catch {tossl::rsa::generate -bits -100} err]} {
    puts "PASS: Invalid bit size (negative) - error as expected: $err"
} else {
    puts stderr "FAIL: Invalid bit size (negative) should have errored"
    incr ::errors
}

# Invalid bit size (non-numeric)
if {[catch {tossl::rsa::generate -bits "invalid"} err]} {
    puts "PASS: Invalid bit size (non-numeric) - error as expected: $err"
} else {
    puts stderr "FAIL: Invalid bit size (non-numeric) should have errored"
    incr ::errors
}

# Wrong option
if {[catch {tossl::rsa::generate -wrong 2048} err]} {
    puts "PASS: Wrong option - error as expected: $err"
} else {
    puts stderr "FAIL: Wrong option should have errored"
    incr ::errors
}

# Too many arguments
if {[catch {tossl::rsa::generate -bits 2048 extra} err]} {
    puts "PASS: Too many arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too many arguments should have errored"
    incr ::errors
}

# 8. Test multiple key generations (ensure uniqueness)
puts "\n8. Testing multiple key generations (uniqueness)..."
set keys1 [tossl::rsa::generate -bits 2048]
set keys2 [tossl::rsa::generate -bits 2048]
set priv1 [dict get $keys1 private]
set priv2 [dict get $keys2 private]

if {$priv1 ne $priv2} {
    puts "PASS: Multiple key generations produce different keys"
} else {
    puts stderr "FAIL: Multiple key generations produced identical keys"
    incr ::errors
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::generate tests passed"
} 