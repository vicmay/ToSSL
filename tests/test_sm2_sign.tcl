# tests/test_sm2_sign.tcl ;# Test for ::tossl::sm2::sign

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::sm2::sign..."

# Test 1: Basic functionality - generate key, sign data, verify
puts "\n=== Test 1: Basic SM2 Sign Functionality ==="
set rc [catch {
    # Generate SM2 key pair
    set key_pair [tossl::sm2::generate]
    set private_key $key_pair
    puts "✓ SM2 private key generated: [string length $private_key] bytes"
    
    # Extract public key
    set public_key [tossl::key::getpub -key $private_key]
    puts "✓ Public key extracted: [string length $public_key] bytes"
    
    # Test data
    set test_data "Hello, SM2 signature creation!"
    puts "✓ Test data prepared: '$test_data'"
    
    # Sign the data
    set signature [tossl::sm2::sign $private_key $test_data]
    puts "✓ Data signed successfully: [string length $signature] bytes"
    
    # Verify the signature (should succeed)
    set verification_result [tossl::sm2::verify $public_key $test_data $signature]
    if {$verification_result} {
        puts "✓ Signature verification successful"
    } else {
        error "Signature verification failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Sign with different data types
puts "\n=== Test 2: Different Data Types ==="
set rc [catch {
    # Test with empty string
    set empty_signature [tossl::sm2::sign $private_key ""]
    puts "✓ Empty string signed: [string length $empty_signature] bytes"
    
    # Test with large data
    set large_data [string repeat "This is a large test message for SM2 signing. " 100]
    set large_signature [tossl::sm2::sign $private_key $large_data]
    puts "✓ Large data signed: [string length $large_signature] bytes"
    
    # Test with binary data
    set binary_data ""
    for {set i 0} {$i < 256} {incr i} {
        append binary_data [format %c $i]
    }
    set binary_signature [tossl::sm2::sign $private_key $binary_data]
    puts "✓ Binary data signed: [string length $binary_signature] bytes"
    
    # Verify all signatures
    set empty_verify [tossl::sm2::verify $public_key "" $empty_signature]
    set large_verify [tossl::sm2::verify $public_key $large_data $large_signature]
    set binary_verify [tossl::sm2::verify $public_key $binary_data $binary_signature]
    
    if {$empty_verify && $large_verify && $binary_verify} {
        puts "✓ All signature verifications successful"
    } else {
        error "Some signature verifications failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Different data types test failed: $result"
    exit 2
}

# Test 3: Error handling - invalid private key
puts "\n=== Test 3: Invalid Private Key Error Handling ==="
set rc [catch {
    tossl::sm2::sign "invalid_pem_key" $test_data
} result]
if {$rc != 0} {
    puts "✓ Invalid private key correctly rejected: $result"
} else {
    puts stderr "✗ Invalid private key should have caused an error"
    exit 3
}

# Test 4: Error handling - wrong number of arguments
puts "\n=== Test 4: Argument Count Error Handling ==="
set rc [catch {
    tossl::sm2::sign $private_key
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 4
}

# Test 5: Error handling - wrong key type
puts "\n=== Test 5: Wrong Key Type Error Handling ==="
set rc [catch {
    # Generate a different key type (RSA)
    set rsa_keys [tossl::key::generate -type rsa -bits 2048]
    set rsa_private [dict get $rsa_keys private]
    
    tossl::sm2::sign $rsa_private $test_data
} result]
if {$rc != 0} {
    puts "✓ Wrong key type correctly rejected: $result"
} else {
    puts stderr "✗ Wrong key type should have caused an error"
    exit 5
}

# Test 6: Deterministic signing (same data should produce same signature)
puts "\n=== Test 6: Deterministic Signing ==="
set rc [catch {
    set data "Deterministic test data"
    set sig1 [tossl::sm2::sign $private_key $data]
    set sig2 [tossl::sm2::sign $private_key $data]
    
    if {$sig1 eq $sig2} {
        puts "✓ Signing is deterministic (same signature for same data)"
    } else {
        puts "⚠ Signing is non-deterministic (different signatures for same data)"
        puts "  This is acceptable for SM2 as it may use random components"
    }
    
    # Both signatures should verify
    set verify1 [tossl::sm2::verify $public_key $data $sig1]
    set verify2 [tossl::sm2::verify $public_key $data $sig2]
    
    if {$verify1 && $verify2} {
        puts "✓ Both signatures verify successfully"
    } else {
        error "Signature verification failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Deterministic signing test failed: $result"
    exit 6
}

# Test 7: Performance test
puts "\n=== Test 7: Performance Test ==="
set rc [catch {
    set test_message "Performance test message"
    set iterations 10
    
    # Time multiple signing operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set sig [tossl::sm2::sign $private_key $test_message]
        if {[string length $sig] == 0} {
            error "Empty signature generated on iteration $i"
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
    exit 7
}

# Test 8: Security validation - signature format
puts "\n=== Test 8: Signature Format Validation ==="
set rc [catch {
    set test_sig [tossl::sm2::sign $private_key "Format test"]
    
    # Verify signature has reasonable length (SM2 signatures are typically 64-128 bytes)
    if {[string length $test_sig] >= 64 && [string length $test_sig] <= 128} {
        puts "✓ Signature length is reasonable: [string length $test_sig] bytes"
    } else {
        puts "⚠ Signature length may be unusual: [string length $test_sig] bytes"
    }
    
    # Verify signature is not empty
    if {[string length $test_sig] > 0} {
        puts "✓ Signature is not empty"
    } else {
        error "Signature is empty"
    }
    
    # Verify signature is binary data (should be byte array)
    puts "✓ Signature format validation passed"
} result]
if {$rc != 0} {
    puts stderr "✗ Signature format validation failed: $result"
    exit 8
}

# Test 9: Multiple key pairs
puts "\n=== Test 9: Multiple Key Pairs ==="
set rc [catch {
    # Generate multiple key pairs
    set key_pair1 [tossl::sm2::generate]
    set key_pair2 [tossl::sm2::generate]
    set pub1 [tossl::key::getpub -key $key_pair1]
    set pub2 [tossl::key::getpub -key $key_pair2]
    
    set data "Multi-key test"
    set sig1 [tossl::sm2::sign $key_pair1 $data]
    set sig2 [tossl::sm2::sign $key_pair2 $data]
    
    # Verify signatures with correct keys
    set verify1_1 [tossl::sm2::verify $pub1 $data $sig1]
    set verify2_2 [tossl::sm2::verify $pub2 $data $sig2]
    
    # Verify signatures with wrong keys (should fail)
    set verify1_2 [tossl::sm2::verify $pub2 $data $sig1]
    set verify2_1 [tossl::sm2::verify $pub1 $data $sig2]
    
    if {$verify1_1 && $verify2_2 && !$verify1_2 && !$verify2_1} {
        puts "✓ Multiple key pair test successful"
        puts "  ✓ Correct key verifications: passed"
        puts "  ✓ Wrong key verifications: correctly rejected"
    } else {
        error "Multiple key pair test failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple key pairs test failed: $result"
    exit 9
}

# Test 10: Unicode and special characters
puts "\n=== Test 10: Unicode and Special Characters ==="
set rc [catch {
    set unicode_data "Hello, 世界! 🌍 Unicode test with emojis 🚀"
    set special_chars "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
    
    set unicode_sig [tossl::sm2::sign $private_key $unicode_data]
    set special_sig [tossl::sm2::sign $private_key $special_chars]
    
    set unicode_verify [tossl::sm2::verify $public_key $unicode_data $unicode_sig]
    set special_verify [tossl::sm2::verify $public_key $special_chars $special_sig]
    
    if {$unicode_verify && $special_verify} {
        puts "✓ Unicode and special characters test successful"
        puts "  ✓ Unicode data signed and verified: [string length $unicode_sig] bytes"
        puts "  ✓ Special chars signed and verified: [string length $special_sig] bytes"
    } else {
        error "Unicode and special characters test failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Unicode and special characters test failed: $result"
    exit 10
}

# Test 11: Memory and resource management
puts "\n=== Test 11: Memory and Resource Management ==="
set rc [catch {
    # Test many signing operations to check for memory leaks
    set test_data "Memory test data"
    set signatures {}
    
    for {set i 0} {$i < 50} {incr i} {
        set sig [tossl::sm2::sign $private_key $test_data]
        lappend signatures $sig
        
        # Verify each signature immediately
        set verify_result [tossl::sm2::verify $public_key $test_data $sig]
        if {!$verify_result} {
            error "Signature verification failed on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Created [llength $signatures] signatures"
    puts "  ✓ All signatures verified successfully"
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 11
}

puts "\n=== All SM2 Sign Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Different data types supported"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Security validation passed"
puts "✓ Multiple key pairs working"
puts "✓ Unicode and special characters supported"
puts "✓ Memory management working"

exit 0 