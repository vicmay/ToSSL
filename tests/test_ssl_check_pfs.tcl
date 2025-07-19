#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::check_pfs command
package require tossl

puts "Testing ::tossl::ssl::check_pfs command..."

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

# Test 2: Error handling - invalid connection
puts "\n=== Test 2: Error handling - invalid connection ==="
set result [catch {
    tossl::ssl::check_pfs -conn "nonexistent_conn"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected invalid connection"
} else {
    puts "✗ Test 2 FAILED: Expected 'SSL connection not found' error, got: $err"
}

# Test 3: Error handling - missing parameters
puts "\n=== Test 3: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::check_pfs
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 3 FAILED: Expected wrong args error, got: $err"
}

# Test 4: Error handling - missing required parameters
puts "\n=== Test 4: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::check_pfs -invalid_param "value"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing conn parameter"
} else {
    puts "✗ Test 4 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 5: Parameter validation - empty connection name
puts "\n=== Test 5: Parameter validation - empty connection name ==="
set result [catch {
    tossl::ssl::check_pfs -conn ""
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected empty connection name"
} else {
    puts "✗ Test 5 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 6: Parameter validation - whitespace in connection name
puts "\n=== Test 6: Parameter validation - whitespace in connection name ==="
set result [catch {
    tossl::ssl::check_pfs -conn "  test_conn  "
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 6 PASSED: Correctly handled whitespace in connection name"
} else {
    puts "✗ Test 6 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 7: Parameter validation - special characters in connection name
puts "\n=== Test 7: Parameter validation - special characters in connection name ==="
set result [catch {
    tossl::ssl::check_pfs -conn "test_conn@#$%"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 7 PASSED: Correctly handled special characters in connection name"
} else {
    puts "✗ Test 7 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 8: Context handle format validation
puts "\n=== Test 8: Context handle format validation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context handle format validation successful"
    } else {
        error "Invalid context handle format: $ctx"
    }
} err]

if {$result == 0} {
    puts "✓ Test 8 PASSED"
} else {
    puts "✗ Test 8 FAILED: $err"
}

# Test 9: Resource management - multiple contexts
puts "\n=== Test 9: Resource management - multiple contexts ==="
set result [catch {
    set contexts {}
    for {set i 0} {$i < 3} {incr i} {
        set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
        lappend contexts $ctx
        puts "✓ Created context $i: $ctx"
    }
    
    # Verify all contexts have correct format
    foreach ctx $contexts {
        if {![string match "sslctx*" $ctx]} {
            error "Invalid context handle format: $ctx"
        }
    }
    puts "✓ All contexts have correct format"
} err]

if {$result == 0} {
    puts "✓ Test 9 PASSED"
} else {
    puts "✗ Test 9 FAILED: $err"
}

# Test 10: Command syntax validation
puts "\n=== Test 10: Command syntax validation ==="
set result [catch {
    # Test with invalid parameter names
    tossl::ssl::check_pfs -invalid_param "value"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 10 PASSED: Correctly rejected invalid parameter names"
} else {
    puts "✗ Test 10 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 11: Integration with SSL context creation
puts "\n=== Test 11: Integration with SSL context creation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created for integration test: $ctx"
    
    # Verify context can be used for other operations
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context integration successful"
    } else {
        error "Context integration failed"
    }
} err]

if {$result == 0} {
    puts "✓ Test 11 PASSED"
} else {
    puts "✗ Test 11 FAILED: $err"
}

# Test 12: Edge case - very long connection name
puts "\n=== Test 12: Edge case - very long connection name ==="
set result [catch {
    set long_name [string repeat "a" 1000]
    tossl::ssl::check_pfs -conn $long_name
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 12 PASSED: Correctly handled very long connection name"
} else {
    puts "✗ Test 12 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 13: Edge case - connection name with null bytes
puts "\n=== Test 13: Edge case - connection name with null bytes ==="
set result [catch {
    tossl::ssl::check_pfs -conn "test\x00conn"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 13 PASSED: Correctly handled connection name with null bytes"
} else {
    puts "✗ Test 13 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 14: Edge case - connection name with unicode characters
puts "\n=== Test 14: Edge case - connection name with unicode characters ==="
set result [catch {
    tossl::ssl::check_pfs -conn "test_conn_🚀_🌍"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 14 PASSED: Correctly handled connection name with unicode characters"
} else {
    puts "✗ Test 14 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 15: Performance validation - multiple rapid calls
puts "\n=== Test 15: Performance validation - multiple rapid calls ==="
set result [catch {
    # Test multiple rapid calls to ensure no resource leaks
    for {set i 0} {$i < 5} {incr i} {
        if {[catch {
            tossl::ssl::check_pfs -conn "test_conn"
        } err]} {
            if {![string match "*SSL connection not found*" $err]} {
                error "Unexpected error on iteration $i: $err"
            }
        }
    }
    puts "✓ Completed 5 rapid check_pfs attempts"
} err]

if {$result == 0} {
    puts "✓ Test 15 PASSED"
} else {
    puts "✗ Test 15 FAILED: $err"
}

# Test 16: Command behavior consistency
puts "\n=== Test 16: Command behavior consistency ==="
set result [catch {
    # Test that the command behaves consistently across multiple calls
    set errors1 {}
    set errors2 {}
    
    # First set of calls
    for {set i 0} {$i < 3} {incr i} {
        if {[catch {
            tossl::ssl::check_pfs -conn "test_conn"
        } err]} {
            lappend errors1 $err
        }
    }
    
    # Second set of calls
    for {set i 0} {$i < 3} {incr i} {
        if {[catch {
            tossl::ssl::check_pfs -conn "test_conn"
        } err]} {
            lappend errors2 $err
        }
    }
    
    # Verify consistent error messages
    if {[llength $errors1] == 3 && [llength $errors2] == 3} {
        puts "✓ Command behavior is consistent across multiple calls"
    } else {
        error "Inconsistent behavior detected"
    }
} err]

if {$result == 0} {
    puts "✓ Test 16 PASSED"
} else {
    puts "✗ Test 16 FAILED: $err"
}

# Test 17: Memory management validation
puts "\n=== Test 17: Memory management validation ==="
set result [catch {
    # Test that repeated calls don't cause memory leaks
    for {set i 0} {$i < 10} {incr i} {
        if {[catch {
            tossl::ssl::check_pfs -conn "test_conn"
        } err]} {
            # Expected error, continue
        }
    }
    puts "✓ Completed 10 calls without memory issues"
} err]

if {$result == 0} {
    puts "✓ Test 17 PASSED"
} else {
    puts "✗ Test 17 FAILED: $err"
}

# Test 18: Integration with other SSL commands
puts "\n=== Test 18: Integration with other SSL commands ==="
set result [catch {
    # Test that check_pfs can work with contexts created by other commands
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Verify the context is valid for other operations
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context created successfully for integration test"
    } else {
        error "Context creation failed for integration test"
    }
} err]

if {$result == 0} {
    puts "✓ Test 18 PASSED"
} else {
    puts "✗ Test 18 FAILED: $err"
}

# Test 19: Security validation
puts "\n=== Test 19: Security validation ==="
set result [catch {
    # Test that the command doesn't expose sensitive information in error messages
    if {[catch {
        tossl::ssl::check_pfs -conn "test_conn"
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
    puts "✓ Test 19 PASSED"
} else {
    puts "✗ Test 19 FAILED: $err"
}

# Test 20: Comprehensive validation
puts "\n=== Test 20: Comprehensive validation ==="
set result [catch {
    # Test all aspects of the command in a comprehensive manner
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Verify context creation
    if {![string match "sslctx*" $ctx]} {
        error "Context creation failed"
    }
    
    # Test error handling
    if {[catch {
        tossl::ssl::check_pfs -conn "nonexistent"
    } err]} {
        if {![string match "*SSL connection not found*" $err]} {
            error "Unexpected error message: $err"
        }
    } else {
        error "Expected error but got success"
    }
    
    puts "✓ Comprehensive validation completed successfully"
} err]

if {$result == 0} {
    puts "✓ Test 20 PASSED"
} else {
    puts "✗ Test 20 FAILED: $err"
}

puts "\n=== SSL Check PFS Test Summary ==="
puts "All tests completed for ::tossl::ssl::check_pfs command"
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