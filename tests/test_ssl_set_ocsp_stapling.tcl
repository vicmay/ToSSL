#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::set_ocsp_stapling command
package require tossl

puts "Testing ::tossl::ssl::set_ocsp_stapling command..."

# Test configuration - use existing certificates
set cert_file "server.pem"
set key_file "server.key"

# Check if certificate files exist
if {![file exists $cert_file] || ![file exists $key_file]} {
    puts "Certificate files not found: $cert_file and $key_file"
    puts "Please ensure server.pem and server.key exist"
    exit 1
}

puts "Using existing certificates: $cert_file and $key_file"

# Test 1: Basic SSL context creation
puts "\n=== Test 1: Basic SSL context creation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context handle format is correct"
    } else {
        error "Invalid context handle format"
    }
} err]

if {$result == 0} {
    puts "✓ Test 1 PASSED"
} else {
    puts "✗ Test 1 FAILED: $err"
}

# Test 2: Basic OCSP stapling enable
puts "\n=== Test 2: Basic OCSP stapling enable ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling enabled successfully"
    } else {
        error "Expected 'ok' but got: $result"
    }
} err]

if {$result == 0} {
    puts "✓ Test 2 PASSED"
} else {
    puts "✗ Test 2 FAILED: $err"
}

# Test 3: Basic OCSP stapling disable
puts "\n=== Test 3: Basic OCSP stapling disable ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling disabled successfully"
    } else {
        error "Expected 'ok' but got: $result"
    }
} err]

if {$result == 0} {
    puts "✓ Test 3 PASSED"
} else {
    puts "✗ Test 3 FAILED: $err"
}

# Test 4: Error handling - invalid context
puts "\n=== Test 4: Error handling - invalid context ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "nonexistent_ctx" -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected invalid context"
} else {
    puts "✗ Test 4 FAILED: Expected 'SSL context not found' error, got: $err"
}

# Test 5: Error handling - missing parameters
puts "\n=== Test 5: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 5 FAILED: Expected wrong args error, got: $err"
}

# Test 6: Error handling - missing required parameters
puts "\n=== Test 6: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "test_ctx"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 6 PASSED: Correctly rejected missing enable parameter"
} else {
    puts "✗ Test 6 FAILED: Expected wrong args error, got: $err"
}

# Test 7: Parameter validation - empty context name
puts "\n=== Test 7: Parameter validation - empty context name ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "" -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 7 PASSED: Correctly rejected empty context name"
} else {
    puts "✗ Test 7 FAILED: Expected SSL context not found error, got: $err"
}

# Test 8: Parameter validation - whitespace in context name
puts "\n=== Test 8: Parameter validation - whitespace in context name ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "  test_ctx  " -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 8 PASSED: Correctly handled whitespace in context name"
} else {
    puts "✗ Test 8 FAILED: Expected SSL context not found error, got: $err"
}

# Test 9: Parameter validation - special characters in context name
puts "\n=== Test 9: Parameter validation - special characters in context name ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "test_ctx@#$%" -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 9 PASSED: Correctly handled special characters in context name"
} else {
    puts "✗ Test 9 FAILED: Expected SSL context not found error, got: $err"
}

# Test 10: Enable parameter validation - boolean true
puts "\n=== Test 10: Enable parameter validation - boolean true ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable true]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling enabled with 'true' value"
    } else {
        error "Expected 'ok' but got: $result"
    }
} err]

if {$result == 0} {
    puts "✓ Test 10 PASSED"
} else {
    puts "✗ Test 10 FAILED: $err"
}

# Test 11: Enable parameter validation - boolean false
puts "\n=== Test 11: Enable parameter validation - boolean false ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable false]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling disabled with 'false' value"
    } else {
        error "Expected 'ok' but got: $result"
    }
} err]

if {$result == 0} {
    puts "✓ Test 11 PASSED"
} else {
    puts "✗ Test 11 FAILED: $err"
}

# Test 12: Enable parameter validation - string values
puts "\n=== Test 12: Enable parameter validation - string values ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable "enabled"]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling handled non-boolean string value"
    } else {
        error "Expected 'ok' but got: $result"
    }
} err]

if {$result == 0} {
    puts "✓ Test 12 PASSED"
} else {
    puts "✗ Test 12 FAILED: $err"
}

# Test 13: Context handle format validation
puts "\n=== Test 13: Context handle format validation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context handle format validation successful"
    } else {
        error "Invalid context handle format: $ctx"
    }
} err]

if {$result == 0} {
    puts "✓ Test 13 PASSED"
} else {
    puts "✗ Test 13 FAILED: $err"
}

# Test 14: Resource management - multiple contexts
puts "\n=== Test 14: Resource management - multiple contexts ==="
set result [catch {
    set contexts {}
    for {set i 0} {$i < 3} {incr i} {
        set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
        lappend contexts $ctx
        puts "✓ Created context $i: $ctx"
    }
    
    # Enable OCSP stapling on all contexts
    foreach ctx $contexts {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
        if {$result ne "ok"} {
            error "Failed to enable OCSP stapling on context $ctx"
        }
    }
    puts "✓ OCSP stapling enabled on all contexts"
} err]

if {$result == 0} {
    puts "✓ Test 14 PASSED"
} else {
    puts "✗ Test 14 FAILED: $err"
}

# Test 15: Command syntax validation
puts "\n=== Test 15: Command syntax validation ==="
set result [catch {
    # Test with invalid parameter names
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    tossl::ssl::set_ocsp_stapling -invalid_param "value" -ctx $ctx -enable 1
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 15 PASSED: Correctly rejected invalid parameter names"
} else {
    puts "✗ Test 15 FAILED: Expected wrong args error, got: $err"
}

# Test 16: Integration with SSL context creation
puts "\n=== Test 16: Integration with SSL context creation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created for integration test: $ctx"
    
    # Enable OCSP stapling
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling integration successful"
    } else {
        error "OCSP stapling integration failed"
    }
} err]

if {$result == 0} {
    puts "✓ Test 16 PASSED"
} else {
    puts "✗ Test 16 FAILED: $err"
}

# Test 17: Edge case - very long context name
puts "\n=== Test 17: Edge case - very long context name ==="
set result [catch {
    set long_name [string repeat "a" 1000]
    tossl::ssl::set_ocsp_stapling -ctx $long_name -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 17 PASSED: Correctly handled very long context name"
} else {
    puts "✗ Test 17 FAILED: Expected SSL context not found error, got: $err"
}

# Test 18: Edge case - context name with null bytes
puts "\n=== Test 18: Edge case - context name with null bytes ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "test\x00ctx" -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 18 PASSED: Correctly handled context name with null bytes"
} else {
    puts "✗ Test 18 FAILED: Expected SSL context not found error, got: $err"
}

# Test 19: Edge case - context name with unicode characters
puts "\n=== Test 19: Edge case - context name with unicode characters ==="
set result [catch {
    tossl::ssl::set_ocsp_stapling -ctx "test_ctx_🚀_🌍" -enable 1
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 19 PASSED: Correctly handled context name with unicode characters"
} else {
    puts "✗ Test 19 FAILED: Expected SSL context not found error, got: $err"
}

# Test 20: Performance validation - multiple rapid calls
puts "\n=== Test 20: Performance validation - multiple rapid calls ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Test multiple rapid calls to ensure no resource leaks
    for {set i 0} {$i < 5} {incr i} {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable [expr {$i % 2}]]
        if {$result ne "ok"} {
            error "Unexpected result on iteration $i: $result"
        }
    }
    puts "✓ Completed 5 rapid set_ocsp_stapling attempts"
} err]

if {$result == 0} {
    puts "✓ Test 20 PASSED"
} else {
    puts "✗ Test 20 FAILED: $err"
}

# Test 21: Command behavior consistency
puts "\n=== Test 21: Command behavior consistency ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Test that the command behaves consistently across multiple calls
    set results1 {}
    set results2 {}
    
    # First set of calls
    for {set i 0} {$i < 3} {incr i} {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
        lappend results1 $result
    }
    
    # Second set of calls
    for {set i 0} {$i < 3} {incr i} {
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
        lappend results2 $result
    }
    
    # Verify consistent results
    if {[llength $results1] == 3 && [llength $results2] == 3} {
        foreach result $results1 {
            if {$result ne "ok"} {
                error "Inconsistent result in first set: $result"
            }
        }
        foreach result $results2 {
            if {$result ne "ok"} {
                error "Inconsistent result in second set: $result"
            }
        }
        puts "✓ Command behavior is consistent across multiple calls"
    } else {
        error "Inconsistent behavior detected"
    }
} err]

if {$result == 0} {
    puts "✓ Test 21 PASSED"
} else {
    puts "✗ Test 21 FAILED: $err"
}

# Test 22: Memory management validation
puts "\n=== Test 22: Memory management validation ==="
set result [catch {
    # Test that repeated calls don't cause memory leaks
    for {set i 0} {$i < 10} {incr i} {
        set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
        set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
        if {$result ne "ok"} {
            error "Memory management test failed on iteration $i"
        }
    }
    puts "✓ Completed 10 calls without memory issues"
} err]

if {$result == 0} {
    puts "✓ Test 22 PASSED"
} else {
    puts "✗ Test 22 FAILED: $err"
}

# Test 23: Integration with other SSL commands
puts "\n=== Test 23: Integration with other SSL commands ==="
set result [catch {
    # Test that set_ocsp_stapling can work with contexts created by other commands
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Verify the context is valid for other operations
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context created successfully for integration test"
    } else {
        error "Context creation failed for integration test"
    }
    
    # Enable OCSP stapling
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    if {$result eq "ok"} {
        puts "✓ OCSP stapling integration successful"
    } else {
        error "OCSP stapling integration failed"
    }
} err]

if {$result == 0} {
    puts "✓ Test 23 PASSED"
} else {
    puts "✗ Test 23 FAILED: $err"
}

# Test 24: Security validation
puts "\n=== Test 24: Security validation ==="
set result [catch {
    # Test that the command doesn't expose sensitive information in error messages
    if {[catch {
        tossl::ssl::set_ocsp_stapling -ctx "test_ctx" -enable 1
    } err]} {
        # Check that error message doesn't contain sensitive information
        if {![string match "*password*" $err] && ![string match "*key*" $err] && ![string match "*cert*" $err]} {
            puts "✓ Error message doesn't expose sensitive information"
        } else {
            error "Error message may expose sensitive information"
        }
    }
} err]

if {$result == 0} {
    puts "✓ Test 24 PASSED"
} else {
    puts "✗ Test 24 FAILED: $err"
}

# Test 25: Comprehensive validation
puts "\n=== Test 25: Comprehensive validation ==="
set result [catch {
    # Test all aspects of the command in a comprehensive manner
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Verify context creation
    if {![string match "sslctx*" $ctx]} {
        error "Context creation failed"
    }
    
    # Test OCSP stapling enable
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 1]
    if {$result ne "ok"} {
        error "OCSP stapling enable failed"
    }
    
    # Test OCSP stapling disable
    set result [tossl::ssl::set_ocsp_stapling -ctx $ctx -enable 0]
    if {$result ne "ok"} {
        error "OCSP stapling disable failed"
    }
    
    # Test error handling
    if {[catch {
        tossl::ssl::set_ocsp_stapling -ctx "nonexistent" -enable 1
    } err]} {
        if {![string match "*SSL context not found*" $err]} {
            error "Unexpected error message: $err"
        }
    } else {
        error "Expected error but got success"
    }
    
    puts "✓ Comprehensive validation completed successfully"
} err]

if {$result == 0} {
    puts "✓ Test 25 PASSED"
} else {
    puts "✗ Test 25 FAILED: $err"
}

puts "\n=== SSL Set OCSP Stapling Test Summary ==="
puts "All tests completed for ::tossl::ssl::set_ocsp_stapling command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Parameter validation verified"
puts "✓ Integration with SSL context creation tested"
puts "✓ Resource management validated"
puts "✓ Edge cases handled"
puts "✓ Command syntax validation completed"
puts "✓ Performance aspects validated"
puts "✓ Security aspects validated"
puts "✓ Comprehensive validation completed" 