# tests/test_sm2_verify.tcl ;# Test for ::tossl::sm2::verify

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::sm2::verify..."

# Test 1: Basic functionality - generate key, sign, verify
puts "\n=== Test 1: Basic SM2 Verify Functionality ==="
set rc [catch {
    # Generate SM2 key pair
    set key_pair [tossl::sm2::generate]
    set private_key $key_pair
    puts "✓ SM2 private key generated: [string length $private_key] bytes"
    
    # Extract public key
    set public_key [tossl::key::getpub -key $private_key]
    puts "✓ Public key extracted: [string length $public_key] bytes"
    
    # Test data
    set test_data "Hello, SM2 signature verification!"
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

# Test 2: Verify with tampered signature
puts "\n=== Test 2: Tampered Signature Detection ==="
set rc [catch {
    # Tamper with the signature (change last byte)
    set tampered_signature [string range $signature 0 end-2][format %c [expr {[scan [string index $signature end] %c] + 1}]]
    
    set verification_result [tossl::sm2::verify $public_key $test_data $tampered_signature]
    if {!$verification_result} {
        puts "✓ Tampered signature correctly rejected"
    } else {
        error "Tampered signature was incorrectly accepted"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Tampered signature test failed: $result"
    exit 2
}

# Test 3: Verify with tampered data
puts "\n=== Test 3: Tampered Data Detection ==="
set rc [catch {
    set tampered_data "Hello, SM2 signature verification! (tampered)"
    
    set verification_result [tossl::sm2::verify $public_key $tampered_data $signature]
    if {!$verification_result} {
        puts "✓ Tampered data correctly rejected"
    } else {
        error "Tampered data was incorrectly accepted"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Tampered data test failed: $result"
    exit 3
}

# Test 4: Verify with wrong public key
puts "\n=== Test 4: Wrong Public Key Detection ==="
set rc [catch {
    # Generate a different key pair
    set wrong_key_pair [tossl::sm2::generate]
    set wrong_public_key [tossl::key::getpub -key $wrong_key_pair]
    
    set verification_result [tossl::sm2::verify $wrong_public_key $test_data $signature]
    if {!$verification_result} {
        puts "✓ Wrong public key correctly rejected"
    } else {
        error "Wrong public key was incorrectly accepted"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Wrong public key test failed: $result"
    exit 4
}

# Test 5: Error handling - invalid public key
puts "\n=== Test 5: Invalid Public Key Error Handling ==="
set rc [catch {
    tossl::sm2::verify "invalid_pem_key" $test_data $signature
} result]
if {$rc != 0} {
    puts "✓ Invalid public key correctly rejected: $result"
} else {
    puts stderr "✗ Invalid public key should have caused an error"
    exit 5
}

# Test 6: Error handling - wrong number of arguments
puts "\n=== Test 6: Argument Count Error Handling ==="
set rc [catch {
    tossl::sm2::verify $public_key $test_data
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 6
}

# Test 7: Empty data verification
puts "\n=== Test 7: Empty Data Verification ==="
set rc [catch {
    # Sign empty data
    set empty_signature [tossl::sm2::sign $private_key ""]
    puts "✓ Empty data signed successfully: [string length $empty_signature] bytes"
    
    # Verify empty data signature
    set verification_result [tossl::sm2::verify $public_key "" $empty_signature]
    if {$verification_result} {
        puts "✓ Empty data signature verification successful"
    } else {
        error "Empty data signature verification failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Empty data verification test failed: $result"
    exit 7
}

# Test 8: Large data verification
puts "\n=== Test 8: Large Data Verification ==="
set rc [catch {
    # Create large test data
    set large_data [string repeat "This is a large test message for SM2 signature verification. " 100]
    puts "✓ Large test data prepared: [string length $large_data] bytes"
    
    # Sign large data
    set large_signature [tossl::sm2::sign $private_key $large_data]
    puts "✓ Large data signed successfully: [string length $large_signature] bytes"
    
    # Verify large data signature
    set verification_result [tossl::sm2::verify $public_key $large_data $large_signature]
    if {$verification_result} {
        puts "✓ Large data signature verification successful"
    } else {
        error "Large data signature verification failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Large data verification test failed: $result"
    exit 8
}

# Test 9: Binary data verification
puts "\n=== Test 9: Binary Data Verification ==="
set rc [catch {
    # Create binary test data
    set binary_data ""
    for {set i 0} {$i < 256} {incr i} {
        append binary_data [format %c $i]
    }
    puts "✓ Binary test data prepared: [string length $binary_data] bytes"
    
    # Sign binary data
    set binary_signature [tossl::sm2::sign $private_key $binary_data]
    puts "✓ Binary data signed successfully: [string length $binary_signature] bytes"
    
    # Verify binary data signature
    set verification_result [tossl::sm2::verify $public_key $binary_data $binary_signature]
    if {$verification_result} {
        puts "✓ Binary data signature verification successful"
    } else {
        error "Binary data signature verification failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Binary data verification test failed: $result"
    exit 9
}

# Test 10: Performance test
puts "\n=== Test 10: Performance Test ==="
set rc [catch {
    set test_message "Performance test message"
    set iterations 10
    
    # Time multiple verification operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set sig [tossl::sm2::sign $private_key $test_message]
        set result [tossl::sm2::verify $public_key $test_message $sig]
        if {!$result} {
            error "Performance test verification failed on iteration $i"
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
    exit 10
}

# Test 11: Security validation - signature format
puts "\n=== Test 11: Signature Format Validation ==="
set rc [catch {
    # Verify signature has reasonable length (SM2 signatures are typically 64-128 bytes)
    if {[string length $signature] >= 64 && [string length $signature] <= 128} {
        puts "✓ Signature length is reasonable: [string length $signature] bytes"
    } else {
        puts "⚠ Signature length may be unusual: [string length $signature] bytes"
    }
    
    # Verify signature is not empty
    if {[string length $signature] > 0} {
        puts "✓ Signature is not empty"
    } else {
        error "Signature is empty"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Signature format validation failed: $result"
    exit 11
}

puts "\n=== All SM2 Verify Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Tamper detection working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Security validation passed"

exit 0 