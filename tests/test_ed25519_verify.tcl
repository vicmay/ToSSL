# Test for ::tossl::ed25519::verify
load ./libtossl.so

set errors 0

puts "Testing ::tossl::ed25519::verify..."

# 1. Basic sign/verify roundtrip
puts "\n1. Testing basic sign/verify roundtrip..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data "Hello, Ed25519!"
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Basic sign/verify roundtrip failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Basic sign/verify roundtrip"
    } else {
        puts stderr "FAIL: Basic sign/verify roundtrip - verification failed"
        incr ::errors
    }
}

# 2. Test with different data
puts "\n2. Testing with different data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data1 "First message"
    set data2 "Second message"
    set sig1 [tossl::ed25519::sign $priv $data1]
    set sig2 [tossl::ed25519::sign $priv $data2]
    
    set verify1 [tossl::ed25519::verify $pub $data1 $sig1]
    set verify2 [tossl::ed25519::verify $pub $data2 $sig2]
    set verify_wrong1 [tossl::ed25519::verify $pub $data1 $sig2]
    set verify_wrong2 [tossl::ed25519::verify $pub $data2 $sig1]
} err]} {
    puts stderr "FAIL: Different data test failed: $err"
    incr ::errors
} else {
    if {$verify1 == 1 && $verify2 == 1 && $verify_wrong1 == 0 && $verify_wrong2 == 0} {
        puts "PASS: Different data test"
    } else {
        puts stderr "FAIL: Different data test - unexpected verification results"
        incr ::errors
    }
}

# 3. Test with empty data
puts "\n3. Testing with empty data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data ""
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Empty data test failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Empty data test"
    } else {
        puts stderr "FAIL: Empty data test - verification failed"
        incr ::errors
    }
}

# 4. Test with binary data
puts "\n4. Testing with binary data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data [binary format H* "0102030405060708090a0b0c0d0e0f10"]
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Binary data test failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Binary data test"
    } else {
        puts stderr "FAIL: Binary data test - verification failed"
        incr ::errors
    }
}

# 5. Test with large data
puts "\n5. Testing with large data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data [string repeat "A" 1000]
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Large data test failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Large data test"
    } else {
        puts stderr "FAIL: Large data test - verification failed"
        incr ::errors
    }
}

# 6. Test with modified signature
puts "\n6. Testing with modified signature..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data "Test message"
    set sig [tossl::ed25519::sign $priv $data]
    
    # Modify the signature slightly
    set modified_sig [string replace $sig 0 0 [binary format c [expr {[scan [string index $sig 0] %c] ^ 1}]]]
    set verified [tossl::ed25519::verify $pub $data $modified_sig]
} err]} {
    puts stderr "FAIL: Modified signature test failed: $err"
    incr ::errors
} else {
    if {$verified == 0} {
        puts "PASS: Modified signature test"
    } else {
        puts stderr "FAIL: Modified signature test - verification should have failed"
        incr ::errors
    }
}

# 7. Test with modified data
puts "\n7. Testing with modified data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data "Original message"
    set sig [tossl::ed25519::sign $priv $data]
    
    # Modify the data slightly
    set modified_data "Modified message"
    set verified [tossl::ed25519::verify $pub $modified_data $sig]
} err]} {
    puts stderr "FAIL: Modified data test failed: $err"
    incr ::errors
} else {
    if {$verified == 0} {
        puts "PASS: Modified data test"
    } else {
        puts stderr "FAIL: Modified data test - verification should have failed"
        incr ::errors
    }
}

# 8. Test with wrong key
puts "\n8. Testing with wrong key..."
if {[catch {
    set priv1 [tossl::ed25519::generate]
    set pub1 [tossl::key::getpub -key $priv1]
    set priv2 [tossl::ed25519::generate]
    set pub2 [tossl::key::getpub -key $priv2]
    set data "Test message"
    set sig [tossl::ed25519::sign $priv1 $data]
    
    # Try to verify with wrong public key
    set verified [tossl::ed25519::verify $pub2 $data $sig]
} err]} {
    puts stderr "FAIL: Wrong key test failed: $err"
    incr ::errors
} else {
    if {$verified == 0} {
        puts "PASS: Wrong key test"
    } else {
        puts stderr "FAIL: Wrong key test - verification should have failed"
        incr ::errors
    }
}

# 9. Error handling tests
puts "\n9. Testing error handling..."

# Missing arguments
if {[catch {tossl::ed25519::verify} err]} {
    puts "PASS: Missing arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Missing arguments should have errored"
    incr ::errors
}

# Too few arguments
if {[catch {tossl::ed25519::verify "key"} err]} {
    puts "PASS: Too few arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too few arguments should have errored"
    incr ::errors
}

# Too many arguments
if {[catch {tossl::ed25519::verify "key" "data" "sig" "extra"} err]} {
    puts "PASS: Too many arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too many arguments should have errored"
    incr ::errors
}

# Invalid public key
if {[catch {tossl::ed25519::verify "invalid_key" "data" "signature"} err]} {
    puts "PASS: Invalid public key - error as expected: $err"
} else {
    puts stderr "FAIL: Invalid public key should have errored"
    incr ::errors
}

# Non-Ed25519 key
if {[catch {
    set rsa_keys [tossl::rsa::generate -bits 2048]
    set rsa_pub [dict get $rsa_keys public]
    tossl::ed25519::verify $rsa_pub "data" "signature"
} err]} {
    puts "PASS: Non-Ed25519 key - error as expected: $err"
} else {
    puts stderr "FAIL: Non-Ed25519 key should have errored"
    incr ::errors
}

# 10. Test multiple key pairs
puts "\n10. Testing multiple key pairs..."
if {[catch {
    set priv1 [tossl::ed25519::generate]
    set pub1 [tossl::key::getpub -key $priv1]
    set priv2 [tossl::ed25519::generate]
    set pub2 [tossl::key::getpub -key $priv2]
    set data "Test message"
    
    set sig1 [tossl::ed25519::sign $priv1 $data]
    set sig2 [tossl::ed25519::sign $priv2 $data]
    
    set verify1_1 [tossl::ed25519::verify $pub1 $data $sig1]
    set verify1_2 [tossl::ed25519::verify $pub1 $data $sig2]
    set verify2_1 [tossl::ed25519::verify $pub2 $data $sig1]
    set verify2_2 [tossl::ed25519::verify $pub2 $data $sig2]
} err]} {
    puts stderr "FAIL: Multiple key pairs test failed: $err"
    incr ::errors
} else {
    if {$verify1_1 == 1 && $verify1_2 == 0 && $verify2_1 == 0 && $verify2_2 == 1} {
        puts "PASS: Multiple key pairs test"
    } else {
        puts stderr "FAIL: Multiple key pairs test - unexpected verification results"
        incr ::errors
    }
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::ed25519::verify tests passed"
} 