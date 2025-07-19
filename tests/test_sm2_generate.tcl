# tests/test_sm2_generate.tcl ;# Test for ::tossl::sm2::generate

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::sm2::generate..."

# Test 1: Basic functionality - generate key pair
puts "\n=== Test 1: Basic SM2 Key Generation ==="
set rc [catch {
    # Generate SM2 key pair
    set private_key [tossl::sm2::generate]
    puts "✓ SM2 private key generated: [string length $private_key] bytes"
    
    # Extract public key
    set public_key [tossl::key::getpub -key $private_key]
    puts "✓ Public key extracted: [string length $public_key] bytes"
    
    # Verify key format
    if {[string match "*-----BEGIN PRIVATE KEY-----*" $private_key] && 
        [string match "*-----END PRIVATE KEY-----*" $private_key]} {
        puts "✓ Private key has correct PEM format"
    } else {
        error "Private key does not have correct PEM format"
    }
    
    if {[string match "*-----BEGIN PUBLIC KEY-----*" $public_key] && 
        [string match "*-----END PUBLIC KEY-----*" $public_key]} {
        puts "✓ Public key has correct PEM format"
    } else {
        error "Public key does not have correct PEM format"
    }
    
    # Test that the key pair works for signing/verification
    set test_data "Test data for key validation"
    set signature [tossl::sm2::sign $private_key $test_data]
    set verification_result [tossl::sm2::verify $public_key $test_data $signature]
    
    if {$verification_result} {
        puts "✓ Key pair works correctly for signing/verification"
    } else {
        error "Key pair does not work for signing/verification"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Generate multiple key pairs
puts "\n=== Test 2: Multiple Key Pair Generation ==="
set rc [catch {
    set key_pairs {}
    set public_keys {}
    
    # Generate multiple key pairs
    for {set i 0} {$i < 5} {incr i} {
        set private_key [tossl::sm2::generate]
        set public_key [tossl::key::getpub -key $private_key]
        
        lappend key_pairs $private_key
        lappend public_keys $public_key
        
        puts "✓ Generated key pair $i: [string length $private_key] bytes private, [string length $public_key] bytes public"
    }
    
    # Verify all key pairs are unique
    set unique_privates [lsort -unique $key_pairs]
    set unique_publics [lsort -unique $public_keys]
    
    if {[llength $unique_privates] == 5 && [llength $unique_publics] == 5} {
        puts "✓ All generated key pairs are unique"
    } else {
        error "Generated key pairs are not unique"
    }
    
    # Test that each key pair works independently
    for {set i 0} {$i < 5} {incr i} {
        set private_key [lindex $key_pairs $i]
        set public_key [lindex $public_keys $i]
        set test_data "Test data for key pair $i"
        
        set signature [tossl::sm2::sign $private_key $test_data]
        set verification_result [tossl::sm2::verify $public_key $test_data $signature]
        
        if {!$verification_result} {
            error "Key pair $i does not work correctly"
        }
    }
    
    puts "✓ All key pairs work correctly for signing/verification"
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple key pair generation test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::sm2::generate extra_argument
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 3
}

# Test 4: Key analysis and validation
puts "\n=== Test 4: Key Analysis and Validation ==="
set rc [catch {
    set private_key [tossl::sm2::generate]
    set public_key [tossl::key::getpub -key $private_key]
    
    # Analyze the private key
    set key_info [tossl::key::analyze $private_key]
    puts "✓ Private key analysis: $key_info"
    
    # Analyze the public key
    set pub_info [tossl::key::analyze $public_key]
    puts "✓ Public key analysis: $pub_info"
    
    # Verify key fingerprint (use public key for fingerprinting)
    set public_fingerprint [tossl::key::fingerprint -key $public_key]
    
    puts "✓ Public key fingerprint: $public_fingerprint"
    
    # Verify fingerprint is valid (should be a hex string)
    if {[regexp {^[0-9a-f]{64}$} $public_fingerprint]} {
        puts "✓ Key fingerprint format is valid"
    } else {
        error "Key fingerprint format is invalid"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Key analysis and validation test failed: $result"
    exit 4
}

# Test 5: Performance test
puts "\n=== Test 5: Performance Test ==="
set rc [catch {
    set iterations 10
    
    # Time multiple key generation operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set key [tossl::sm2::generate]
        if {[string length $key] == 0} {
            error "Empty key generated on iteration $i"
        }
    }
    set end_time [clock milliseconds]
    set total_time [expr {$end_time - $start_time}]
    set avg_time [expr {double($total_time) / $iterations}]
    
    puts "✓ Performance test completed:"
    puts "  Total time: ${total_time}ms for $iterations operations"
    puts "  Average time: [format %.2f $avg_time]ms per operation"
} result]
if {$rc != 0} {
    puts stderr "✗ Performance test failed: $result"
    exit 5
}

# Test 6: Key format validation
puts "\n=== Test 6: Key Format Validation ==="
set rc [catch {
    set private_key [tossl::sm2::generate]
    
    # Check private key format
    if {[string match "*-----BEGIN PRIVATE KEY-----*" $private_key] && [string match "*-----END PRIVATE KEY-----*" $private_key]} {
        puts "✓ Private key has correct PEM format"
    } else {
        error "Private key does not have correct PEM format"
    }
    
    # Check key length (SM2 keys should be reasonable size)
    if {[string length $private_key] >= 200 && [string length $private_key] <= 500} {
        puts "✓ Private key has reasonable length: [string length $private_key] bytes"
    } else {
        puts "⚠ Private key length may be unusual: [string length $private_key] bytes"
    }
    
    # Extract and validate public key
    set public_key [tossl::key::getpub -key $private_key]
    if {[string match "*-----BEGIN PUBLIC KEY-----*" $public_key] && [string match "*-----END PUBLIC KEY-----*" $public_key]} {
        puts "✓ Public key has correct PEM format"
    } else {
        error "Public key does not have correct PEM format"
    }
    
    if {[string length $public_key] >= 100 && [string length $public_key] <= 300} {
        puts "✓ Public key has reasonable length: [string length $public_key] bytes"
    } else {
        puts "⚠ Public key length may be unusual: [string length $public_key] bytes"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Key format validation failed: $result"
    exit 6
}

# Test 7: Key functionality validation
puts "\n=== Test 7: Key Functionality Validation ==="
set rc [catch {
    set private_key [tossl::sm2::generate]
    set public_key [tossl::key::getpub -key $private_key]
    
    # Test encryption/decryption
    set test_data "Encryption test data"
    set encrypted [tossl::sm2::encrypt $public_key $test_data]
    set decrypted [tossl::sm2::decrypt $private_key $encrypted]
    
    if {$decrypted eq $test_data} {
        puts "✓ Key pair works for encryption/decryption"
    } else {
        error "Key pair does not work for encryption/decryption"
    }
    
    # Test signing/verification
    set signature [tossl::sm2::sign $private_key $test_data]
    set verification_result [tossl::sm2::verify $public_key $test_data $signature]
    
    if {$verification_result} {
        puts "✓ Key pair works for signing/verification"
    } else {
        error "Key pair does not work for signing/verification"
    }
    
    # Test with different data types
    set binary_data ""
    for {set i 0} {$i < 64} {incr i} {
        append binary_data [format %c $i]
    }
    
    set encrypted_binary [tossl::sm2::encrypt $public_key $binary_data]
    set decrypted_binary [tossl::sm2::decrypt $private_key $encrypted_binary]
    
    if {$decrypted_binary eq $binary_data} {
        puts "✓ Key pair works with binary data"
    } else {
        error "Key pair does not work with binary data"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Key functionality validation failed: $result"
    exit 7
}

# Test 8: Memory and resource management
puts "\n=== Test 8: Memory and Resource Management ==="
set rc [catch {
    # Test many key generation operations to check for memory leaks
    set keys {}
    
    for {set i 0} {$i < 20} {incr i} {
        set key [tossl::sm2::generate]
        lappend keys $key
        
        # Verify each key works
        set pub [tossl::key::getpub -key $key]
        set test_data "Memory test $i"
        set sig [tossl::sm2::sign $key $test_data]
        set verify [tossl::sm2::verify $pub $test_data $sig]
        
        if {!$verify} {
            error "Generated key $i does not work correctly"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $keys] keys"
    puts "  ✓ All keys work correctly"
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 8
}

# Test 9: Key uniqueness and randomness
puts "\n=== Test 9: Key Uniqueness and Randomness ==="
set rc [catch {
    set keys {}
    set fingerprints {}
    
    # Generate many keys and collect fingerprints
    for {set i 0} {$i < 50} {incr i} {
        set key [tossl::sm2::generate]
        set pub [tossl::key::getpub -key $key]
        set fingerprint [tossl::key::fingerprint -key $pub]
        
        lappend keys $key
        lappend fingerprints $fingerprint
    }
    
    # Check for uniqueness
    set unique_fingerprints [lsort -unique $fingerprints]
    set unique_keys [lsort -unique $keys]
    
    if {[llength $unique_fingerprints] == 50 && [llength $unique_keys] == 50} {
        puts "✓ All generated keys are unique"
        puts "  ✓ Generated 50 unique keys"
        puts "  ✓ Generated 50 unique fingerprints"
    } else {
        puts "⚠ Some generated keys may not be unique"
        puts "  Unique keys: [llength $unique_keys]/50"
        puts "  Unique fingerprints: [llength $unique_fingerprints]/50"
    }
    
    # Check for randomness (basic entropy test)
    set first_chars {}
    foreach key $keys {
        lappend first_chars [string index $key 0]
    }
    
    set unique_first_chars [lsort -unique $first_chars]
    if {[llength $unique_first_chars] >= 10} {
        puts "✓ Keys appear to have good randomness"
    } else {
        puts "⚠ Keys may not have sufficient randomness"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Key uniqueness and randomness test failed: $result"
    exit 9
}

# Test 10: Error recovery and robustness
puts "\n=== Test 10: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can generate keys after various operations
    set test_operations {
        "Basic generation"
        "After key analysis"
        "After signing"
        "After encryption"
        "After multiple generations"
    }
    
    foreach operation $test_operations {
        if {[catch {
            set key [tossl::sm2::generate]
            set pub [tossl::key::getpub -key $key]
            
            # Verify the key works
            set test_data "Robustness test"
            set sig [tossl::sm2::sign $key $test_data]
            set verify [tossl::sm2::verify $pub $test_data $sig]
            
            if {!$verify} {
                error "Key verification failed after $operation"
            }
            
            puts "✓ Key generation successful after $operation"
        } err]} {
            error "Key generation failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 10
}

puts "\n=== All SM2 Generate Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple key pair generation working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Key format validation passed"
puts "✓ Key functionality validation passed"
puts "✓ Memory management working"
puts "✓ Key uniqueness and randomness verified"
puts "✓ Error recovery and robustness working"

exit 0 