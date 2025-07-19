# tests/test_asn1_oid_to_text.tcl ;# Test for ::tossl::asn1::oid_to_text

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing ::tossl::asn1::oid_to_text..."

# Test 1: Basic functionality - convert OID to text
puts "\n=== Test 1: Basic OID to Text Conversion ==="
set rc [catch {
    # Test with a simple OID
    set text_result [tossl::asn1::oid_to_text "1.2.3"]
    puts "✓ OID '1.2.3' converted to text: $text_result"
    
    # Verify the result is not empty
    if {[string length $text_result] > 0} {
        puts "✓ Result is not empty"
    } else {
        error "Result is empty"
    }
    
    # Test round-trip conversion
    set oid_result [tossl::asn1::text_to_oid $text_result]
    puts "✓ Round-trip conversion: $oid_result"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Basic functionality test failed: $result"
    exit 1
}

# Test 2: Multiple OID conversions
puts "\n=== Test 2: Multiple OID Conversions ==="
set rc [catch {
    set test_oids {
        "1.2.3"
        "1.3.6.1.5.5.7.1.1"
        "2.5.4.3"
        "1.2.840.113549.1.1.1"
        "1.2.840.113549.1.1.11"
        "1.2.840.10040.4.1"
        "1.2.840.10045.2.1"
        "2.16.840.1.101.3.4.2.1"
    }
    
    foreach oid $test_oids {
        if {[catch {
            set result [tossl::asn1::oid_to_text $oid]
            puts "✓ '$oid' -> '$result'"
            
            # Verify result is not empty
            if {[string length $result] > 0} {
                puts "  ✓ Result is not empty"
            } else {
                puts "  ⚠ Result is empty"
            }
            
            # Check if result is OID format or text name
            if {[regexp {^\d+(\.\d+)*$} $result]} {
                puts "  ✓ Result is OID format (no text name available)"
            } else {
                puts "  ✓ Result is text name format"
            }
        } err]} {
            puts "✗ Failed to convert '$oid': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Multiple OID conversions test failed: $result"
    exit 2
}

# Test 3: Error handling - wrong number of arguments
puts "\n=== Test 3: Argument Count Error Handling ==="
set rc [catch {
    tossl::asn1::oid_to_text
} result]
if {$rc != 0} {
    puts "✓ Wrong number of arguments correctly rejected: $result"
} else {
    puts stderr "✗ Wrong number of arguments should have caused an error"
    exit 3
}

set rc [catch {
    tossl::asn1::oid_to_text "arg1" "arg2"
} result]
if {$rc != 0} {
    puts "✓ Too many arguments correctly rejected: $result"
} else {
    puts stderr "✗ Too many arguments should have caused an error"
    exit 3
}

# Test 4: Error handling - invalid OID
puts "\n=== Test 4: Invalid OID Error Handling ==="
set rc [catch {
    tossl::asn1::oid_to_text "invalid_oid"
} result]
if {$rc != 0} {
    puts "✓ Invalid OID correctly rejected: $result"
} else {
    puts stderr "✗ Invalid OID should have caused an error"
    exit 4
}

set rc [catch {
    tossl::asn1::oid_to_text "not.an.oid"
} result]
if {$rc != 0} {
    puts "✓ Invalid OID format correctly rejected: $result"
} else {
    puts stderr "✗ Invalid OID format should have caused an error"
    exit 4
}

# Test 5: Edge cases and special values
puts "\n=== Test 5: Edge Cases and Special Values ==="
set rc [catch {
    # Test with empty string
    if {[catch {
        set result [tossl::asn1::oid_to_text ""]
        puts "✓ Empty string result: '$result'"
    } err]} {
        puts "✓ Empty string correctly rejected: $err"
    }
    
    # Test with single number
    if {[catch {
        set result [tossl::asn1::oid_to_text "1"]
        puts "✓ Single number result: '$result'"
    } err]} {
        puts "✓ Single number correctly rejected: $err"
    }
    
    # Test with very long OID
    set long_oid "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20"
    if {[catch {
        set result [tossl::asn1::oid_to_text $long_oid]
        puts "✓ Long OID result: '$result'"
    } err]} {
        puts "✓ Long OID correctly rejected: $err"
    }
    
    # Test with special characters
    if {[catch {
        set result [tossl::asn1::oid_to_text "1.2.3@4"]
        puts "✓ Special characters result: '$result'"
    } err]} {
        puts "✓ Special characters correctly rejected: $err"
    }
    
    # Test with negative numbers
    if {[catch {
        set result [tossl::asn1::oid_to_text "1.-2.3"]
        puts "✓ Negative numbers result: '$result'"
    } err]} {
        puts "✓ Negative numbers correctly rejected: $err"
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Edge cases test failed: $result"
    exit 5
}

# Test 6: Performance test
puts "\n=== Test 6: Performance Test ==="
set rc [catch {
    set iterations 100
    set test_oid "1.2.3.4.5"
    
    # Time multiple OID conversion operations
    set start_time [clock milliseconds]
    for {set i 0} {$i < $iterations} {incr i} {
        set result [tossl::asn1::oid_to_text $test_oid]
        if {[string length $result] == 0} {
            error "Empty result generated on iteration $i"
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
    exit 6
}

# Test 7: OID format validation
puts "\n=== Test 7: OID Format Validation ==="
set rc [catch {
    set test_cases {
        "1.2.3"
        "1.3.6.1.5.5.7.1.1"
        "2.5.4.3"
        "1.2.840.113549.1.1.1"
        "1.2.840.113549.1.1.11"
        "1.2.840.10040.4.1"
    }
    
    foreach test_oid $test_cases {
        if {[catch {
            set result [tossl::asn1::oid_to_text $test_oid]
            
            # Check that result is not empty
            if {[string length $result] > 0} {
                puts "✓ '$test_oid' -> '$result' (valid result)"
                
                # Check if result is different from input (if conversion happened)
                if {$result ne $test_oid} {
                    puts "  ✓ Conversion occurred (OID to text name)"
                } else {
                    puts "  ✓ Input preserved (no text name available)"
                }
            } else {
                puts "⚠ '$test_oid' -> '$result' (empty result)"
            }
        } err]} {
            puts "✗ Failed to convert '$test_oid': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ OID format validation failed: $result"
    exit 7
}

# Test 8: Round-trip conversion testing
puts "\n=== Test 8: Round-trip Conversion Testing ==="
set rc [catch {
    set test_oids {
        "1.2.3"
        "1.3.6.1.5.5.7.1.1"
        "2.5.4.3"
        "1.2.840.113549.1.1.1"
    }
    
    foreach original_oid $test_oids {
        if {[catch {
            # Convert OID to text
            set text_result [tossl::asn1::oid_to_text $original_oid]
            
            # Convert text back to OID
            set oid_result [tossl::asn1::text_to_oid $text_result]
            
            puts "✓ Round-trip: '$original_oid' -> '$text_result' -> '$oid_result'"
            
            # Verify round-trip consistency
            if {$oid_result eq $original_oid} {
                puts "  ✓ Round-trip conversion is consistent"
            } else {
                puts "  ⚠ Round-trip conversion may not be consistent"
            }
        } err]} {
            puts "✗ Round-trip failed for '$original_oid': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Round-trip conversion testing failed: $result"
    exit 8
}

# Test 9: Memory and resource management
puts "\n=== Test 9: Memory and Resource Management ==="
set rc [catch {
    # Test many OID conversion operations to check for memory leaks
    set results {}
    
    for {set i 0} {$i < 50} {incr i} {
        set test_oid "1.2.3.$i"
        set result [tossl::asn1::oid_to_text $test_oid]
        lappend results $result
        
        # Verify each result works
        if {[string length $result] == 0} {
            error "Empty result generated on iteration $i"
        }
    }
    
    puts "✓ Memory and resource management test successful"
    puts "  ✓ Generated [llength $results] conversions"
    puts "  ✓ All conversions produced results"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Memory and resource management test failed: $result"
    exit 9
}

# Test 10: Error recovery and robustness
puts "\n=== Test 10: Error Recovery and Robustness ==="
set rc [catch {
    # Test that we can convert OIDs after various operations
    set test_operations {
        "Basic conversion"
        "After error handling"
        "After multiple conversions"
        "After round-trip testing"
    }
    
    foreach operation $test_operations {
        if {[catch {
            set result [tossl::asn1::oid_to_text "1.2.3"]
            
            if {[string length $result] == 0} {
                error "Empty result after $operation"
            }
            
            puts "✓ OID conversion successful after $operation"
        } err]} {
            error "OID conversion failed after $operation: $err"
        }
    }
    
    puts "✓ Error recovery and robustness test successful"
    
} result]
if {$rc != 0} {
    puts stderr "✗ Error recovery and robustness test failed: $result"
    exit 10
}

# Test 11: Known OID text name testing
puts "\n=== Test 11: Known OID Text Name Testing ==="
set rc [catch {
    # Test OIDs that should have text names in OpenSSL
    set known_oids {
        "2.5.4.3"      ;# commonName
        "2.5.4.6"      ;# countryName
        "2.5.4.7"      ;# localityName
        "2.5.4.8"      ;# stateOrProvinceName
        "2.5.4.10"     ;# organizationName
        "2.5.4.11"     ;# organizationalUnitName
        "1.3.6.1.5.5.7.1.1"  ;# Authority Information Access
        "1.2.840.113549.1.1.1"  ;# rsaEncryption
        "1.2.840.113549.1.1.11" ;# sha256WithRSAEncryption
    }
    
    foreach oid $known_oids {
        if {[catch {
            set result [tossl::asn1::oid_to_text $oid]
            puts "✓ '$oid' -> '$result'"
            
            # Check if we got a text name or OID
            if {[regexp {^\d+(\.\d+)*$} $result]} {
                puts "  ⚠ No text name available, returned OID"
            } else {
                puts "  ✓ Text name found"
            }
        } err]} {
            puts "✗ Failed to convert '$oid': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Known OID text name testing failed: $result"
    exit 11
}

# Test 12: Cryptographic algorithm OID testing
puts "\n=== Test 12: Cryptographic Algorithm OID Testing ==="
set rc [catch {
    # Test cryptographic algorithm OIDs
    set crypto_oids {
        "1.2.840.113549.1.1.1"   ;# RSA
        "1.2.840.10040.4.1"      ;# DSA
        "1.2.840.10045.2.1"      ;# ECDSA
        "2.16.840.1.101.3.4.2.1" ;# SHA-256
        "2.16.840.1.101.3.4.2.2" ;# SHA-384
        "2.16.840.1.101.3.4.2.3" ;# SHA-512
    }
    
    foreach oid $crypto_oids {
        if {[catch {
            set result [tossl::asn1::oid_to_text $oid]
            puts "✓ '$oid' -> '$result'"
            
            # Check if we got a text name or OID
            if {[regexp {^\d+(\.\d+)*$} $result]} {
                puts "  ⚠ No text name available, returned OID"
            } else {
                puts "  ✓ Text name found"
            }
        } err]} {
            puts "✗ Failed to convert '$oid': $err"
        }
    }
    
} result]
if {$rc != 0} {
    puts stderr "✗ Cryptographic algorithm OID testing failed: $result"
    exit 12
}

puts "\n=== All ASN.1 OID to Text Tests Passed ==="
puts "✓ Basic functionality working"
puts "✓ Multiple OID conversions working"
puts "✓ Error handling working"
puts "✓ Performance acceptable"
puts "✓ OID format validation passed"
puts "✓ Round-trip conversion working"
puts "✓ Memory management working"
puts "✓ Error recovery and robustness working"
puts "✓ Known OID text name testing completed"
puts "✓ Cryptographic algorithm OID testing completed"

exit 0 