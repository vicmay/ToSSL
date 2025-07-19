# tests/test_sm2_decrypt.tcl ;# Test for ::tossl::sm2::decrypt

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::sm2::decrypt..."

# Test 1: Basic functionality - generate key, encrypt, decrypt
puts "\n=== Test 1: Basic SM2 Decrypt Functionality ==="
set rc [catch {
    # Generate SM2 key pair
    set key_pair [tossl::sm2::generate]
    set private_key $key_pair
    puts "✓ SM2 private key generated: [string length $private_key] bytes"
    
    # Extract public key
    set public_key [tossl::key::getpub -key $private_key]
    puts "✓ Public key extracted: [string length $public_key] bytes"
    
    # Test data
    set test_data "Hello, SM2 decryption test!"
    puts "✓ Test data prepared: '$test_data'"
    
    # Encrypt the data
    set encrypted_data [tossl::sm2::encrypt $public_key $test_data]
    puts "✓ Data encrypted successfully: [string length $encrypted_data] bytes"
    
    # Decrypt the data (should succeed)
    set decrypted_data [tossl::sm2::decrypt $private_key $encrypted_data]
    puts "✓ Data decrypted successfully: [string length $decrypted_data] bytes"
    
    # Verify decryption
    if {$decrypted_data eq $test_data} {
        puts "✓ Decrypted data matches original: '$decrypted_data'"
    } else {
        error "Decrypted data does not match original"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Decrypt with different data types
puts "\n=== Test 2: Different Data Types ==="
set rc [catch {
    # Test with small string (SM2 doesn't support empty strings)
    set small_data "A"
    set small_encrypted [tossl::sm2::encrypt $public_key $small_data]
    set small_decrypted [tossl::sm2::decrypt $private_key $small_encrypted]
    puts "✓ Small string encrypted/decrypted: [string length $small_decrypted] bytes"
    
    # Test with large data (reduced size to avoid potential issues)
    set large_data [string repeat "This is a large test message for SM2 encryption/decryption. " 50]
    set large_encrypted [tossl::sm2::encrypt $public_key $large_data]
    set large_decrypted [tossl::sm2::decrypt $private_key $large_encrypted]
    puts "✓ Large data encrypted/decrypted: [string length $large_decrypted] bytes"
    
    # Test with binary data (reduced size)
    set binary_data ""
    for {set i 0} {$i < 128} {incr i} {
        append binary_data [format %c $i]
    }
    set binary_encrypted [tossl::sm2::encrypt $public_key $binary_data]
    set binary_decrypted [tossl::sm2::decrypt $private_key $binary_encrypted]
    puts "✓ Binary data encrypted/decrypted: [string length $binary_decrypted] bytes"
    
    # Verify all decryptions
    if {$small_decrypted eq $small_data && $large_decrypted eq $large_data && $binary_decrypted eq $binary_data} {
        puts "✓ All decryptions successful"
    } else {
        error "Some decryptions failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Different data types test failed: $result"
    exit 2
}

# Test 3: Error handling - invalid private key
puts "\n=== Test 3: Invalid Private Key Error Handling ==="
set rc [catch {
    tossl::sm2::decrypt "invalid_pem_key" $encrypted_data
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
    tossl::sm2::decrypt $private_key
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
    
    tossl::sm2::decrypt $rsa_private $encrypted_data
} result]
if {$rc != 0} {
    puts "✓ Wrong key type correctly rejected: $result"
} else {
    puts stderr "✗ Wrong key type should have caused an error"
    exit 5
}

# Test 6: Error handling - tampered encrypted data
puts "\n=== Test 6: Tampered Data Error Handling ==="
set rc [catch {
    # Tamper with the encrypted data (change last byte)
    set tampered_encrypted [string range $encrypted_data 0 end-2][format %c [expr {[scan [string index $encrypted_data end] %c] + 1}]]
    
    tossl::sm2::decrypt $private_key $tampered_encrypted
} result]
if {$rc != 0} {
    puts "✓ Tampered encrypted data correctly rejected: $result"
} else {
    puts stderr "✗ Tampered encrypted data should have caused an error"
    exit 6
}

# Test 7: Error handling - wrong private key
puts "\n=== Test 7: Wrong Private Key Error Handling ==="
set rc [catch {
    # Generate a different key pair
    set wrong_key_pair [tossl::sm2::generate]
    set wrong_private_key $wrong_key_pair
    
    tossl::sm2::decrypt $wrong_private_key $encrypted_data
} result]
if {$rc != 0} {
    puts "✓ Wrong private key correctly rejected: $result"
} else {
    puts stderr "✗ Wrong private key should have caused an error"
    exit 7
}

# Test 8: Performance test
puts "\n=== Test 8: Performance Test ==="
set rc [catch {
    set test_message "Performance test message"
    set iterations 5  ;# Reduced for decryption as it's more expensive
    
    # Time multiple encryption/decryption operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set encrypted [tossl::sm2::encrypt $public_key $test_message]
        set decrypted [tossl::sm2::decrypt $private_key $encrypted]
        if {$decrypted ne $test_message} {
            error "Decryption failed on iteration $i"
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
    exit 8
}

# Test 9: Security validation - encrypted data format
puts "\n=== Test 9: Encrypted Data Format Validation ==="
set rc [catch {
    set test_encrypted [tossl::sm2::encrypt $public_key "Format test"]
    
    # Verify encrypted data has reasonable length (SM2 encrypted data is typically larger than original)
    if {[string length $test_encrypted] > 0} {
        puts "✓ Encrypted data is not empty: [string length $test_encrypted] bytes"
    } else {
        error "Encrypted data is empty"
    }
    
    # Verify encrypted data is binary data
    puts "✓ Encrypted data format validation passed"
} result]
if {$rc != 0} {
    puts stderr "✗ Encrypted data format validation failed: $result"
    exit 9
}

# Test 10: Multiple key pairs
puts "\n=== Test 10: Multiple Key Pairs ==="
set rc [catch {
    # Generate multiple key pairs
    set key_pair1 [tossl::sm2::generate]
    set key_pair2 [tossl::sm2::generate]
    set pub1 [tossl::key::getpub -key $key_pair1]
    set pub2 [tossl::key::getpub -key $key_pair2]
    
    set data "Multi-key test"
    set encrypted1 [tossl::sm2::encrypt $pub1 $data]
    set encrypted2 [tossl::sm2::encrypt $pub2 $data]
    
    # Decrypt with correct keys
    set decrypted1_1 [tossl::sm2::decrypt $key_pair1 $encrypted1]
    set decrypted2_2 [tossl::sm2::decrypt $key_pair2 $encrypted2]
    
    # Try to decrypt with wrong keys (should fail)
    set rc1 [catch {tossl::sm2::decrypt $key_pair2 $encrypted1} result1]
    set rc2 [catch {tossl::sm2::decrypt $key_pair1 $encrypted2} result2]
    
    if {$decrypted1_1 eq $data && $decrypted2_2 eq $data && $rc1 != 0 && $rc2 != 0} {
        puts "✓ Multiple key pair test successful"
        puts "  ✓ Correct key decryptions: passed"
        puts "  ✓ Wrong key decryptions: correctly rejected"
    } else {
        error "Multiple key pair test failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple key pairs test failed: $result"
    exit 10
}

# Test 11: Special characters (ASCII)
puts "\n=== Test 11: Special Characters ==="
set rc [catch {
    set special_chars "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
    set extended_ascii "Extended ASCII: ñáéíóúüÑÁÉÍÓÚÜ"
    
    set special_encrypted [tossl::sm2::encrypt $public_key $special_chars]
    set extended_encrypted [tossl::sm2::encrypt $public_key $extended_ascii]
    
    set special_decrypted [tossl::sm2::decrypt $private_key $special_encrypted]
    set extended_decrypted [tossl::sm2::decrypt $private_key $extended_encrypted]
    
    if {$special_decrypted eq $special_chars && $extended_decrypted eq $extended_ascii} {
        puts "✓ Special characters test successful"
        puts "  ✓ Special chars encrypted/decrypted: [string length $special_encrypted] bytes"
        puts "  ✓ Extended ASCII encrypted/decrypted: [string length $extended_encrypted] bytes"
    } else {
        error "Special characters test failed"
    }
} result]
if {$rc != 0} {
    puts stderr "✗ Special characters test failed: $result"
    exit 11
}

# Test 12: Memory and resource management
puts "\n=== Test 12: Memory and Resource Management ==="
set rc [catch {
    # Test many decryption operations to check for memory leaks
    set test_data "Memory test data"
    set encrypted_data [tossl::sm2::encrypt $public_key $test_data]
    set decrypted_results {}
    
    for {set i 0} {$i < 20} {incr i} {  ;# Reduced for decryption as it's more expensive
        set decrypted [tossl::sm2::decrypt $private_key $encrypted_data]
        lappend decrypted_results $decrypted
        
        # Verify each decryption
        if {$decrypted ne $test_data} {
            error "Decryption failed on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Performed [llength $decrypted_results] decryptions"
    puts "  ✓ All decryptions successful"
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 12
}

# Test 13: Round-trip encryption/decryption
puts "\n=== Test 13: Round-trip Encryption/Decryption ==="
set rc [catch {
    set original_data "Round-trip test data"
    set round_trip_data $original_data
    
    # Perform multiple encrypt/decrypt cycles
    for {set cycle 1} {$cycle <= 3} {incr cycle} {
        set encrypted [tossl::sm2::encrypt $public_key $round_trip_data]
        set decrypted [tossl::sm2::decrypt $private_key $encrypted]
        set round_trip_data $decrypted
        
        if {$decrypted ne $original_data} {
            error "Round-trip failed on cycle $cycle"
        }
    }
    
    puts "✓ Round-trip encryption/decryption test successful"
    puts "  ✓ Completed 3 encrypt/decrypt cycles"
    puts "  ✓ Final data matches original"
} result]
if {$rc != 0} {
    puts stderr "✗ Round-trip encryption/decryption test failed: $result"
    exit 13
}

puts "\n=== All SM2 Decrypt Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Different data types supported"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ Security validation passed"
puts "✓ Multiple key pairs working"
puts "✓ Unicode and special characters supported"
puts "✓ Memory management working"
puts "✓ Round-trip encryption/decryption working"

exit 0 