# Test for ::tossl::ed25519::sign
load ./libtossl.so

set errors 0

puts "Testing ::tossl::ed25519::sign..."

# 1. Basic signing test
puts "\n1. Testing basic signing..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data "Hello, Ed25519!"
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Basic signing failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Basic signing"
    } else {
        puts stderr "FAIL: Basic signing - empty signature"
        incr ::errors
    }
}

# 2. Test with empty data
puts "\n2. Testing with empty data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data ""
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Empty data signing failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Empty data signing"
    } else {
        puts stderr "FAIL: Empty data signing - empty signature"
        incr ::errors
    }
}

# 3. Test with binary data
puts "\n3. Testing with binary data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data [binary format H* "0102030405060708090a0b0c0d0e0f10"]
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Binary data signing failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Binary data signing"
    } else {
        puts stderr "FAIL: Binary data signing - empty signature"
        incr ::errors
    }
}

# 4. Test with large data
puts "\n4. Testing with large data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data [string repeat "A" 1000]
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Large data signing failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Large data signing"
    } else {
        puts stderr "FAIL: Large data signing - empty signature"
        incr ::errors
    }
}

# 5. Test signature verification roundtrip
puts "\n5. Testing signature verification roundtrip..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data "Test message for verification"
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Signature verification roundtrip failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Signature verification roundtrip"
    } else {
        puts stderr "FAIL: Signature verification roundtrip - verification failed"
        incr ::errors
    }
}

# 6. Test deterministic signatures (same data should produce same signature)
puts "\n6. Testing deterministic signatures..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data "Deterministic test"
    set sig1 [tossl::ed25519::sign $priv $data]
    set sig2 [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Deterministic signatures test failed: $err"
    incr ::errors
} else {
    if {$sig1 eq $sig2} {
        puts "PASS: Deterministic signatures"
    } else {
        puts stderr "FAIL: Deterministic signatures - signatures differ"
        incr ::errors
    }
}

# 7. Test different keys produce different signatures
puts "\n7. Testing different keys produce different signatures..."
if {[catch {
    set priv1 [tossl::ed25519::generate]
    set priv2 [tossl::ed25519::generate]
    set data "Same data, different keys"
    set sig1 [tossl::ed25519::sign $priv1 $data]
    set sig2 [tossl::ed25519::sign $priv2 $data]
} err]} {
    puts stderr "FAIL: Different keys test failed: $err"
    incr ::errors
} else {
    if {$sig1 ne $sig2} {
        puts "PASS: Different keys produce different signatures"
    } else {
        puts stderr "FAIL: Different keys produce different signatures - signatures are identical"
        incr ::errors
    }
}

# 8. Test signature length consistency
puts "\n8. Testing signature length consistency..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data1 "Short message"
    set data2 "This is a much longer message that should still produce the same signature length"
    set sig1 [tossl::ed25519::sign $priv $data1]
    set sig2 [tossl::ed25519::sign $priv $data2]
} err]} {
    puts stderr "FAIL: Signature length consistency test failed: $err"
    incr ::errors
} else {
    if {[string length $sig1] == [string length $sig2]} {
        puts "PASS: Signature length consistency"
    } else {
        puts stderr "FAIL: Signature length consistency - different lengths"
        incr ::errors
    }
}

# 9. Test multiple signatures with same key
puts "\n9. Testing multiple signatures with same key..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data1 "First message"
    set data2 "Second message"
    set data3 "Third message"
    set sig1 [tossl::ed25519::sign $priv $data1]
    set sig2 [tossl::ed25519::sign $priv $data2]
    set sig3 [tossl::ed25519::sign $priv $data3]
} err]} {
    puts stderr "FAIL: Multiple signatures test failed: $err"
    incr ::errors
} else {
    if {[string length $sig1] > 0 && [string length $sig2] > 0 && [string length $sig3] > 0} {
        puts "PASS: Multiple signatures with same key"
    } else {
        puts stderr "FAIL: Multiple signatures with same key - empty signatures"
        incr ::errors
    }
}

# 10. Error handling tests
puts "\n10. Testing error handling..."

# Missing arguments
if {[catch {tossl::ed25519::sign} err]} {
    puts "PASS: Missing arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Missing arguments should have errored"
    incr ::errors
}

# Too few arguments
if {[catch {tossl::ed25519::sign "key"} err]} {
    puts "PASS: Too few arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too few arguments should have errored"
    incr ::errors
}

# Too many arguments
if {[catch {tossl::ed25519::sign "key" "data" "extra"} err]} {
    puts "PASS: Too many arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too many arguments should have errored"
    incr ::errors
}

# Invalid private key
if {[catch {tossl::ed25519::sign "invalid_key" "data"} err]} {
    puts "PASS: Invalid private key - error as expected: $err"
} else {
    puts stderr "FAIL: Invalid private key should have errored"
    incr ::errors
}

# Non-Ed25519 key
if {[catch {
    set rsa_keys [tossl::rsa::generate -bits 2048]
    set rsa_priv [dict get $rsa_keys private]
    tossl::ed25519::sign $rsa_priv "data"
} err]} {
    puts "PASS: Non-Ed25519 key - error as expected: $err"
} else {
    puts stderr "FAIL: Non-Ed25519 key should have errored"
    incr ::errors
}

# Public key instead of private key
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    tossl::ed25519::sign $pub "data"
} err]} {
    puts "PASS: Public key instead of private key - error as expected: $err"
} else {
    puts stderr "FAIL: Public key instead of private key should have errored"
    incr ::errors
}

# 11. Test with special characters in data
puts "\n11. Testing with special characters in data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Special characters test failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Special characters in data"
    } else {
        puts stderr "FAIL: Special characters in data - empty signature"
        incr ::errors
    }
}

# 12. Test with Unicode data
puts "\n12. Testing with Unicode data..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set data "Unicode: 你好世界 🌍"
    set sig [tossl::ed25519::sign $priv $data]
} err]} {
    puts stderr "FAIL: Unicode data test failed: $err"
    incr ::errors
} else {
    if {[string length $sig] > 0} {
        puts "PASS: Unicode data"
    } else {
        puts stderr "FAIL: Unicode data - empty signature"
        incr ::errors
    }
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::ed25519::sign tests passed"
} 