# Test for ::tossl::ed25519::generate
load ./libtossl.so

set errors 0

puts "Testing ::tossl::ed25519::generate..."

# 1. Basic key generation
puts "\n1. Testing basic key generation..."
if {[catch {set priv [tossl::ed25519::generate]} err]} {
    puts stderr "FAIL: Basic key generation failed: $err"
    incr ::errors
} else {
    if {[string length $priv] > 0} {
        puts "PASS: Basic key generation"
    } else {
        puts stderr "FAIL: Basic key generation - empty key"
        incr ::errors
    }
}

# 2. Test key format (should be PEM)
puts "\n2. Testing key format..."
if {[catch {set priv [tossl::ed25519::generate]} err]} {
    puts stderr "FAIL: Key format test failed: $err"
    incr ::errors
} else {
    if {[string match "*-----BEGIN PRIVATE KEY-----*" $priv] && [string match "*-----END PRIVATE KEY-----*" $priv]} {
        puts "PASS: Key format (PEM)"
    } else {
        puts stderr "FAIL: Key format - not PEM format"
        incr ::errors
    }
}

# 3. Test key uniqueness
puts "\n3. Testing key uniqueness..."
if {[catch {
    set priv1 [tossl::ed25519::generate]
    set priv2 [tossl::ed25519::generate]
} err]} {
    puts stderr "FAIL: Key uniqueness test failed: $err"
    incr ::errors
} else {
    if {$priv1 ne $priv2} {
        puts "PASS: Key uniqueness"
    } else {
        puts stderr "FAIL: Key uniqueness - identical keys generated"
        incr ::errors
    }
}

# 4. Test key functionality (sign/verify roundtrip)
puts "\n4. Testing key functionality (sign/verify roundtrip)..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set data "Test message"
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Key functionality test failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Key functionality (sign/verify roundtrip)"
    } else {
        puts stderr "FAIL: Key functionality test - verification failed"
        incr ::errors
    }
}

# 5. Test multiple key generations
puts "\n5. Testing multiple key generations..."
if {[catch {
    set keys {}
    for {set i 0} {$i < 5} {incr i} {
        lappend keys [tossl::ed25519::generate]
    }
} err]} {
    puts stderr "FAIL: Multiple key generations test failed: $err"
    incr ::errors
} else {
    set unique_keys [lsort -unique $keys]
    if {[llength $unique_keys] == 5} {
        puts "PASS: Multiple key generations"
    } else {
        puts stderr "FAIL: Multiple key generations - duplicate keys found"
        incr ::errors
    }
}

# 6. Test key parsing and validation
puts "\n6. Testing key parsing and validation..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    
    # Test that we can parse the private key
    set parsed_priv [tossl::key::parse $priv]
    set parsed_pub [tossl::key::parse $pub]
} err]} {
    puts stderr "FAIL: Key parsing test failed: $err"
    incr ::errors
} else {
    if {[dict exists $parsed_priv type] && [dict get $parsed_priv type] eq "unknown" && [dict get $parsed_priv bits] == 256} {
        puts "PASS: Key parsing and validation"
    } else {
        puts stderr "FAIL: Key parsing and validation - wrong key type or bits"
        incr ::errors
    }
}

# 7. Test key fingerprint
puts "\n7. Testing key fingerprint..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    set fp_pub [tossl::key::fingerprint -key $pub]
} err]} {
    puts stderr "FAIL: Key fingerprint test failed: $err"
    incr ::errors
} else {
    if {[string length $fp_pub] > 0} {
        puts "PASS: Key fingerprint"
    } else {
        puts stderr "FAIL: Key fingerprint - empty fingerprint"
        incr ::errors
    }
}

# 8. Test key conversion
puts "\n8. Testing key conversion..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set converted [tossl::key::convert -key $priv -from pem -to pem -type private]
} err]} {
    puts stderr "FAIL: Key conversion test failed: $err"
    incr ::errors
} else {
    if {[string length $converted] > 0} {
        puts "PASS: Key conversion"
    } else {
        puts stderr "FAIL: Key conversion - empty result"
        incr ::errors
    }
}

# 9. Test with different data types
puts "\n9. Testing with different data types..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    
    # Test string data
    set data1 "Hello, Ed25519!"
    set sig1 [tossl::ed25519::sign $priv $data1]
    set verify1 [tossl::ed25519::verify $pub $data1 $sig1]
    
    # Test binary data
    set data2 [binary format H* "0102030405060708090a0b0c0d0e0f10"]
    set sig2 [tossl::ed25519::sign $priv $data2]
    set verify2 [tossl::ed25519::verify $pub $data2 $sig2]
    
    # Test empty data
    set data3 ""
    set sig3 [tossl::ed25519::sign $priv $data3]
    set verify3 [tossl::ed25519::verify $pub $data3 $sig3]
} err]} {
    puts stderr "FAIL: Different data types test failed: $err"
    incr ::errors
} else {
    if {$verify1 == 1 && $verify2 == 1 && $verify3 == 1} {
        puts "PASS: Different data types"
    } else {
        puts stderr "FAIL: Different data types - verification failed"
        incr ::errors
    }
}

# 10. Error handling tests
puts "\n10. Testing error handling..."

# Too many arguments
if {[catch {tossl::ed25519::generate extra} err]} {
    puts "PASS: Too many arguments - error as expected: $err"
} else {
    puts stderr "FAIL: Too many arguments should have errored"
    incr ::errors
}

# Test that generated keys are valid Ed25519 keys
puts "\n11. Testing generated keys are valid Ed25519 keys..."
if {[catch {
    set priv [tossl::ed25519::generate]
    set pub [tossl::key::getpub -key $priv]
    
    # Try to use with Ed25519 operations
    set data "Test data"
    set sig [tossl::ed25519::sign $priv $data]
    set verified [tossl::ed25519::verify $pub $data $sig]
} err]} {
    puts stderr "FAIL: Valid Ed25519 keys test failed: $err"
    incr ::errors
} else {
    if {$verified == 1} {
        puts "PASS: Generated keys are valid Ed25519 keys"
    } else {
        puts stderr "FAIL: Generated keys are valid Ed25519 keys - verification failed"
        incr ::errors
    }
}

# 12. Test key size consistency
puts "\n12. Testing key size consistency..."
if {[catch {
    set keys {}
    for {set i 0} {$i < 10} {incr i} {
        lappend keys [tossl::ed25519::generate]
    }
    
    set lengths {}
    foreach key $keys {
        lappend lengths [string length $key]
    }
    
    set unique_lengths [lsort -unique $lengths]
} err]} {
    puts stderr "FAIL: Key size consistency test failed: $err"
    incr ::errors
} else {
    if {[llength $unique_lengths] == 1} {
        puts "PASS: Key size consistency"
    } else {
        puts stderr "FAIL: Key size consistency - different key sizes"
        incr ::errors
    }
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::ed25519::generate tests passed"
} 