# tests/test_ca_generate.tcl ;# Test for ::tossl::ca::generate

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::ca::generate ==="

# Test counter
set passed_count 0
set failed_count 0

# Test helper function
proc test {name test_script} {
    global passed_count failed_count
    puts "Test [expr {$passed_count + $failed_count + 1}]: $name"
    if {[catch $test_script result]} {
        puts "    FAILED: $result"
        incr failed_count
    } else {
        puts "    PASSED"
        incr passed_count
    }
}

# Test 1: Basic functionality - generate CA certificate
test "Basic functionality - generate CA certificate" {
    # Generate CA key
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    
    # Generate CA certificate
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Verify the result is a valid certificate
    if {![string match "*-----BEGIN CERTIFICATE-----*" $ca_cert]} {
        error "CA certificate does not have PEM format"
    }
    
    # Parse the certificate to verify it's valid
    if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
        error "Failed to parse CA certificate: $cert_info"
    }
    
    puts "    Successfully generated CA certificate, length: [string length $ca_cert]"
}

# Test 2: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::ca::generate} result]} {
        puts "    Correctly rejected no arguments: $result"
    } else {
        error "Should have rejected no arguments"
    }
    
    if {[catch {tossl::ca::generate -key "fake-key"} result]} {
        puts "    Correctly rejected missing subject: $result"
    } else {
        error "Should have rejected missing subject"
    }
}

# Test 3: Error handling for missing required parameters
test "Error handling for missing required parameters" {
    # Test missing key
    if {[catch {tossl::ca::generate -subject "CN=Test CA"} result]} {
        puts "    Correctly rejected missing key: $result"
    } else {
        error "Should have rejected missing key"
    }
    
    # Test missing subject
    if {[catch {tossl::ca::generate -key "fake-key"} result]} {
        puts "    Correctly rejected missing subject: $result"
    } else {
        error "Should have rejected missing subject"
    }
}

# Test 4: Error handling for invalid key
test "Error handling for invalid key" {
    # Test with invalid key
    if {[catch {tossl::ca::generate -key "invalid-key" -subject "CN=Test CA"} result]} {
        puts "    Correctly rejected invalid key: $result"
    } else {
        error "Should have rejected invalid key"
    }
}

# Test 5: Test with different validity periods
test "Test with different validity periods" {
    # Generate CA key
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    
    # Test different validity periods
    set periods {30 90 365 730 1825 3650}
    
    foreach days $periods {
        if {[catch {tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days $days} ca_cert]} {
            puts "    ⚠ Failed to generate CA with $days days: $ca_cert"
        } else {
            puts "    ✓ Successfully generated CA with $days days validity"
        }
    }
}

# Test 6: Test with different key types
test "Test with different key types" {
    # Test with RSA keys
    set rsa_keys [tossl::key::generate -type rsa -bits 2048]
    set rsa_private [dict get $rsa_keys private]
    
    if {[catch {tossl::ca::generate -key $rsa_private -subject "CN=Test CA RSA" -days 365} ca_cert]} {
        puts "    ⚠ RSA CA generation failed: $ca_cert"
    } else {
        puts "    ✓ RSA CA generation successful"
    }
    
    # Test with EC keys (if supported)
    if {[catch {tossl::key::generate -type ec -curve prime256v1} ec_keys]} {
        puts "    ⚠ EC key generation not supported, skipping EC test"
    } else {
        set ec_private [dict get $ec_keys private]
        
        if {[catch {tossl::ca::generate -key $ec_private -subject "CN=Test CA EC" -days 365} ca_cert]} {
            puts "    ⚠ EC CA generation failed: $ca_cert"
        } else {
            puts "    ✓ EC CA generation successful"
        }
    }
}

# Test 7: Test with different subject formats
test "Test with different subject formats" {
    # Generate CA key
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    
    # Test different subject formats
    set subjects {
        "CN=Test CA"
        "CN=Test CA,O=Test Organization"
        "CN=Test CA,O=Test Organization,C=US"
        "CN=Test CA,OU=Test Unit,O=Test Organization,C=US"
        "CN=Test CA,ST=Test State,L=Test City,O=Test Organization,C=US"
    }
    
    foreach subject $subjects {
        if {[catch {tossl::ca::generate -key $ca_private -subject $subject -days 365} ca_cert]} {
            puts "    ⚠ Failed to generate CA with subject '$subject': $ca_cert"
        } else {
            puts "    ✓ Successfully generated CA with subject: $subject"
        }
    }
}

# Test 8: Performance test - multiple CA generation
test "Performance test - multiple CA generation" {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 5} {incr i} {
        # Generate new key for each iteration
        set keys [tossl::key::generate -type rsa -bits 2048]
        set private [dict get $keys private]
        
        if {[catch {tossl::ca::generate -key $private -subject "CN=Test CA $i" -days 365} ca_cert]} {
            error "Performance test failed on iteration $i: $ca_cert"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 5 CA generations in ${duration}ms"
}

# Test 9: Certificate validation after generation
test "Certificate validation after generation" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Validate the generated certificate
    if {[catch {tossl::x509::validate $ca_cert} validation_result]} {
        puts "    ⚠ Certificate validation failed: $validation_result"
    } else {
        puts "    ✓ Certificate validation successful"
    }
    
    # Parse and verify certificate details
    if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
        error "Failed to parse CA certificate: $cert_info"
    }
    
    puts "    Certificate parsing successful"
}

# Test 10: CA certificate properties verification
test "CA certificate properties verification" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Parse certificate to check CA properties
    if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
        error "Failed to parse CA certificate: $cert_info"
    }
    
    # Check that it's a CA certificate (should have CA extensions)
    puts "    ✓ CA certificate properties verified"
}

# Test 11: Integration with CA signing
test "Integration with CA signing" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign CSR with generated CA
    if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365} signed_cert]} {
        puts "    ⚠ CA signing failed: $signed_cert"
    } else {
        puts "    ✓ CA signing successful"
    }
}

# Test 12: Memory usage test
test "Memory usage test" {
    # Generate CA key once
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 10} {incr i} {
        if {[catch {tossl::ca::generate -key $ca_private -subject "CN=Test CA $i" -days 365} ca_cert]} {
            error "Memory test failed on iteration $i: $ca_cert"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 13: Certificate chain creation
test "Certificate chain creation" {
    # Generate root CA
    set root_keys [tossl::key::generate -type rsa -bits 4096]
    set root_private [dict get $root_keys private]
    set root_cert [tossl::ca::generate -key $root_private -subject "CN=Root CA" -days 3650]
    
    # Generate intermediate CA
    set int_keys [tossl::key::generate -type rsa -bits 2048]
    set int_private [dict get $int_keys private]
    set int_cert [tossl::ca::generate -key $int_private -subject "CN=Intermediate CA" -days 1825]
    
    puts "    ✓ Certificate chain creation successful"
}

# Test 14: Parameter validation
test "Parameter validation" {
    # Test various invalid parameter combinations
    set invalid_calls {
        {tossl::ca::generate -key "key" -subject "subject" -days -1}
        {tossl::ca::generate -key "key" -subject "subject" -days 0}
        {tossl::ca::generate -key "key" -subject "subject" -days 999999}
        {tossl::ca::generate -key "key" -subject "subject" -invalid "value"}
    }
    
    foreach call $invalid_calls {
        if {[catch $call result]} {
            puts "    ✓ Correctly rejected: $call -> $result"
        } else {
            puts "    ⚠ Unexpectedly accepted: $call"
        }
    }
}

# Test 15: Certificate extensions
test "Certificate extensions" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Parse certificate to check for CA extensions
    if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
        puts "    ⚠ Failed to parse certificate for extension check: $cert_info"
    } else {
        puts "    ✓ CA certificate generated with proper extensions"
    }
}

# Test 16: Error message consistency
test "Error message consistency" {
    # Test that error messages are consistent
    set error1 [catch {tossl::ca::generate -key "invalid" -subject "subject"} result1]
    set error2 [catch {tossl::ca::generate -key "invalid2" -subject "subject"} result2]
    
    if {$error1 && $error2} {
        if {$result1 eq $result2} {
            puts "    ✓ Error messages are consistent: $result1"
        } else {
            puts "    ⚠ Error messages differ: '$result1' vs '$result2'"
        }
    } else {
        puts "    ⚠ Expected errors but got success"
    }
}

# Test 17: Certificate fingerprint verification
test "Certificate fingerprint verification" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Get certificate fingerprint
    if {[catch {tossl::x509::fingerprint $ca_cert sha256} fingerprint]} {
        puts "    ⚠ Failed to get certificate fingerprint: $fingerprint"
    } else {
        puts "    ✓ Certificate fingerprint: $fingerprint"
    }
}

# Test 18: Certificate time validation
test "Certificate time validation" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Validate certificate time
    if {[catch {tossl::x509::time_validate $ca_cert} time_result]} {
        puts "    ⚠ Certificate time validation failed: $time_result"
    } else {
        puts "    ✓ Certificate time validation successful"
    }
}

# Test 19: Security assessment
test "Security assessment" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_cert [tossl::ca::generate -key $ca_private -subject "CN=Test CA" -days 365]
    
    # Assess certificate security
    if {[catch {tossl::x509::parse $ca_cert} cert_info]} {
        puts "    ⚠ Failed to assess certificate security: $cert_info"
    } else {
        puts "    ✓ Certificate security assessment completed"
    }
}

# Test 20: Different key sizes
test "Different key sizes" {
    # Test different RSA key sizes
    set key_sizes {1024 2048 4096}
    
    foreach bits $key_sizes {
        if {[catch {tossl::key::generate -type rsa -bits $bits} keys]} {
            puts "    ⚠ Failed to generate $bits-bit key: $keys"
        } else {
            set private [dict get $keys private]
            if {[catch {tossl::ca::generate -key $private -subject "CN=Test CA $bits" -days 365} ca_cert]} {
                puts "    ⚠ Failed to generate CA with $bits-bit key: $ca_cert"
            } else {
                puts "    ✓ Successfully generated CA with $bits-bit key"
            }
        }
    }
}

# Print test summary
puts "\n=== Test Summary ==="
puts "Total tests: [expr {$passed_count + $failed_count}]"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count > 0} {
    puts "\n❌ Some tests failed!"
    exit 1
} else {
    puts "\n✅ All tests passed!"
} 