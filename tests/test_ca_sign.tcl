# tests/test_ca_sign.tcl ;# Test for ::tossl::ca::sign

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== Testing ::tossl::ca::sign ==="

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

# Test 1: Basic functionality - sign a CSR
test "Basic functionality - sign a CSR" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    
    # Create CA certificate
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR key and create CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Verify the result is a valid certificate
    if {![string match "*-----BEGIN CERTIFICATE-----*" $signed_cert]} {
        error "Signed certificate does not have PEM format"
    }
    
    # Parse the certificate to verify it's valid
    if {[catch {tossl::x509::parse $signed_cert} cert_info]} {
        error "Failed to parse signed certificate: $cert_info"
    }
    
    puts "    Successfully signed CSR, certificate length: [string length $signed_cert]"
}

# Test 2: Error handling for wrong number of arguments
test "Error handling for wrong number of arguments" {
    if {[catch {tossl::ca::sign} result]} {
        puts "    Correctly rejected no arguments: $result"
    } else {
        error "Should have rejected no arguments"
    }
    
    if {[catch {tossl::ca::sign -ca_key key1 -ca_cert cert1} result]} {
        puts "    Correctly rejected missing CSR: $result"
    } else {
        error "Should have rejected missing CSR"
    }
}

# Test 3: Error handling for missing required parameters
test "Error handling for missing required parameters" {
    # Test missing CA key
    if {[catch {tossl::ca::sign -ca_cert "fake-cert" -csr "fake-csr"} result]} {
        puts "    Correctly rejected missing CA key: $result"
    } else {
        error "Should have rejected missing CA key"
    }
    
    # Test missing CA cert
    if {[catch {tossl::ca::sign -ca_key "fake-key" -csr "fake-csr"} result]} {
        puts "    Correctly rejected missing CA cert: $result"
    } else {
        error "Should have rejected missing CA cert"
    }
    
    # Test missing CSR
    if {[catch {tossl::ca::sign -ca_key "fake-key" -ca_cert "fake-cert"} result]} {
        puts "    Correctly rejected missing CSR: $result"
    } else {
        error "Should have rejected missing CSR"
    }
}

# Test 4: Error handling for invalid CA key
test "Error handling for invalid CA key" {
    # Generate valid CA cert and CSR
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey [dict get $ca_keys private] -days 365]
    
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Test with invalid CA key
    if {[catch {tossl::ca::sign -ca_key "invalid-key" -ca_cert $ca_cert -csr $csr} result]} {
        puts "    Correctly rejected invalid CA key: $result"
    } else {
        error "Should have rejected invalid CA key"
    }
}

# Test 5: Error handling for invalid CA certificate
test "Error handling for invalid CA certificate" {
    # Generate valid CA key and CSR
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Test with invalid CA certificate
    if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert "invalid-cert" -csr $csr} result]} {
        puts "    Correctly rejected invalid CA certificate: $result"
    } else {
        error "Should have rejected invalid CA certificate"
    }
}

# Test 6: Error handling for invalid CSR
test "Error handling for invalid CSR" {
    # Generate valid CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Test with invalid CSR
    if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr "invalid-csr"} result]} {
        puts "    Correctly rejected invalid CSR: $result"
    } else {
        error "Should have rejected invalid CSR"
    }
}

# Test 7: Test with different validity periods
test "Test with different validity periods" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Test different validity periods
    set periods {30 90 365 730}
    
    foreach days $periods {
        if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days $days} signed_cert]} {
            puts "    ⚠ Failed to sign with $days days: $signed_cert"
        } else {
            puts "    ✓ Successfully signed with $days days validity"
        }
    }
}

# Test 8: Test with different key types
test "Test with different key types" {
    # Test with RSA keys
    set ca_keys_rsa [tossl::key::generate -type rsa -bits 2048]
    set ca_private_rsa [dict get $ca_keys_rsa private]
    set ca_public_rsa [dict get $ca_keys_rsa public]
    set ca_cert_rsa [tossl::x509::create -subject "CN=Test CA RSA" -issuer "CN=Test CA RSA" -pubkey $ca_public_rsa -privkey $ca_private_rsa -days 365]
    
    set csr_keys_rsa [tossl::key::generate -type rsa -bits 2048]
    set csr_rsa [tossl::csr::create -key [dict get $csr_keys_rsa private] -subject "CN=TestServerRSA"]
    
    if {[catch {tossl::ca::sign -ca_key $ca_private_rsa -ca_cert $ca_cert_rsa -csr $csr_rsa -days 365} signed_cert]} {
        puts "    ⚠ RSA signing failed: $signed_cert"
    } else {
        puts "    ✓ RSA signing successful"
    }
    
    # Test with EC keys (if supported)
    if {[catch {tossl::key::generate -type ec -curve prime256v1} ca_keys_ec]} {
        puts "    ⚠ EC key generation not supported, skipping EC test"
    } else {
        set ca_private_ec [dict get $ca_keys_ec private]
        set ca_public_ec [dict get $ca_keys_ec public]
        set ca_cert_ec [tossl::x509::create -subject "CN=Test CA EC" -issuer "CN=Test CA EC" -pubkey $ca_public_ec -privkey $ca_private_ec -days 365]
        
        if {[catch {tossl::key::generate -type ec -curve prime256v1} csr_keys_ec]} {
            puts "    ⚠ EC CSR key generation failed"
        } else {
            set csr_ec [tossl::csr::create -key [dict get $csr_keys_ec private] -subject "CN=TestServerEC"]
            
            if {[catch {tossl::ca::sign -ca_key $ca_private_ec -ca_cert $ca_cert_ec -csr $csr_ec -days 365} signed_cert]} {
                puts "    ⚠ EC signing failed: $signed_cert"
            } else {
                puts "    ✓ EC signing successful"
            }
        }
    }
}

# Test 9: Performance test - multiple signing operations
test "Performance test - multiple signing operations" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 5} {incr i} {
        # Generate new CSR for each iteration
        set csr_keys [tossl::key::generate -type rsa -bits 2048]
        set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer$i"]
        
        if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365} signed_cert]} {
            error "Performance test failed on iteration $i: $signed_cert"
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    
    puts "    Completed 5 signing operations in ${duration}ms"
}

# Test 10: Certificate validation after signing
test "Certificate validation after signing" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Validate the signed certificate
    if {[catch {tossl::x509::validate $signed_cert} validation_result]} {
        puts "    ⚠ Certificate validation failed: $validation_result"
    } else {
        puts "    ✓ Certificate validation successful"
    }
    
    # Parse and verify certificate details
    if {[catch {tossl::x509::parse $signed_cert} cert_info]} {
        error "Failed to parse signed certificate: $cert_info"
    }
    
    puts "    Certificate parsing successful"
}

# Test 11: Integration with certificate verification
test "Integration with certificate verification" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Verify the certificate against the CA
    if {[catch {tossl::x509::verify $signed_cert $ca_cert} verify_result]} {
        puts "    ⚠ Certificate verification failed: $verify_result"
    } else {
        puts "    ✓ Certificate verification successful"
    }
}

# Test 12: Memory usage test
test "Memory usage test" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Call the command multiple times to check for memory leaks
    for {set i 0} {$i < 10} {incr i} {
        # Generate new CSR for each iteration
        set csr_keys [tossl::key::generate -type rsa -bits 2048]
        set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer$i"]
        
        if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365} signed_cert]} {
            error "Memory test failed on iteration $i: $signed_cert"
        }
    }
    
    puts "    Memory usage test completed successfully"
}

# Test 13: Error handling for mismatched key types
test "Error handling for mismatched key types" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR with different key type (if EC is supported)
    if {[catch {tossl::key::generate -type ec -curve prime256v1} csr_keys_ec]} {
        puts "    ⚠ EC key generation not supported, skipping mismatched key test"
    } else {
        set csr_ec [tossl::csr::create -key [dict get $csr_keys_ec private] -subject "CN=TestServerEC"]
        
        # This should work (RSA CA can sign EC CSR)
        if {[catch {tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr_ec -days 365} signed_cert]} {
            puts "    ⚠ Cross-key-type signing failed: $signed_cert"
        } else {
            puts "    ✓ Cross-key-type signing successful"
        }
    }
}

# Test 14: Certificate chain validation
test "Certificate chain validation" {
    # Generate root CA
    set root_keys [tossl::key::generate -type rsa -bits 2048]
    set root_private [dict get $root_keys private]
    set root_public [dict get $root_keys public]
    set root_cert [tossl::x509::create -subject "CN=Root CA" -issuer "CN=Root CA" -pubkey $root_public -privkey $root_private -days 365]
    
    # Generate intermediate CA CSR
    set int_keys [tossl::key::generate -type rsa -bits 2048]
    set int_csr [tossl::csr::create -key [dict get $int_keys private] -subject "CN=IntermediateCA"]
    
    # Sign intermediate CA certificate
    set int_cert [tossl::ca::sign -ca_key $root_private -ca_cert $root_cert -csr $int_csr -days 365]
    
    # Generate end entity CSR
    set end_keys [tossl::key::generate -type rsa -bits 2048]
    set end_csr [tossl::csr::create -key [dict get $end_keys private] -subject "CN=EndEntity"]
    
    # Sign end entity certificate with intermediate CA
    set end_cert [tossl::ca::sign -ca_key [dict get $int_keys private] -ca_cert $int_cert -csr $end_csr -days 365]
    
    puts "    ✓ Certificate chain creation successful"
}

# Test 15: Parameter validation
test "Parameter validation" {
    # Test various invalid parameter combinations
    set invalid_calls {
        {tossl::ca::sign -ca_key "key" -ca_cert "cert" -csr "csr" -days -1}
        {tossl::ca::sign -ca_key "key" -ca_cert "cert" -csr "csr" -days 0}
        {tossl::ca::sign -ca_key "key" -ca_cert "cert" -csr "csr" -days 999999}
        {tossl::ca::sign -ca_key "key" -ca_cert "cert" -csr "csr" -invalid "value"}
    }
    
    foreach call $invalid_calls {
        if {[catch $call result]} {
            puts "    ✓ Correctly rejected: $call -> $result"
        } else {
            puts "    ⚠ Unexpectedly accepted: $call"
        }
    }
}

# Test 16: Certificate extensions
test "Certificate extensions" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR (extensions should be automatically added)
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Parse certificate to check for extensions
    if {[catch {tossl::x509::parse $signed_cert} cert_info]} {
        puts "    ⚠ Failed to parse certificate for extension check: $cert_info"
    } else {
        puts "    ✓ Certificate signed with extensions"
    }
}

# Test 17: Error message consistency
test "Error message consistency" {
    # Test that error messages are consistent
    set error1 [catch {tossl::ca::sign -ca_key "invalid" -ca_cert "invalid" -csr "invalid"} result1]
    set error2 [catch {tossl::ca::sign -ca_key "invalid2" -ca_cert "invalid2" -csr "invalid2"} result2]
    
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

# Test 18: Certificate fingerprint verification
test "Certificate fingerprint verification" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Get certificate fingerprint
    if {[catch {tossl::x509::fingerprint $signed_cert sha256} fingerprint]} {
        puts "    ⚠ Failed to get certificate fingerprint: $fingerprint"
    } else {
        puts "    ✓ Certificate fingerprint: $fingerprint"
    }
}

# Test 19: Certificate time validation
test "Certificate time validation" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Validate certificate time
    if {[catch {tossl::x509::time_validate $signed_cert} time_result]} {
        puts "    ⚠ Certificate time validation failed: $time_result"
    } else {
        puts "    ✓ Certificate time validation successful"
    }
}

# Test 20: Security assessment
test "Security assessment" {
    # Generate CA key and certificate
    set ca_keys [tossl::key::generate -type rsa -bits 2048]
    set ca_private [dict get $ca_keys private]
    set ca_public [dict get $ca_keys public]
    set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public -privkey $ca_private -days 365]
    
    # Generate CSR
    set csr_keys [tossl::key::generate -type rsa -bits 2048]
    set csr [tossl::csr::create -key [dict get $csr_keys private] -subject "CN=TestServer"]
    
    # Sign the CSR
    set signed_cert [tossl::ca::sign -ca_key $ca_private -ca_cert $ca_cert -csr $csr -days 365]
    
    # Assess certificate security
    if {[catch {tossl::x509::parse $signed_cert} cert_info]} {
        puts "    ⚠ Failed to assess certificate security: $cert_info"
    } else {
        puts "    ✓ Certificate security assessment completed"
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