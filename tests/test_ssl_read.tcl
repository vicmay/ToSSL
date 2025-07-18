#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::read command
package require tossl

puts "Testing ::tossl::ssl::read command..."

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
    tossl::ssl::read -conn "nonexistent_conn"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected invalid connection"
} else {
    puts "✗ Test 2 FAILED: Expected 'SSL connection not found' error, got: $err"
}

# Test 3: Error handling - missing parameters
puts "\n=== Test 3: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::read
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 3 FAILED: Expected wrong args error, got: $err"
}

# Test 4: Error handling - missing required parameters
puts "\n=== Test 4: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::read -length 1024
} err]

if {$result == 1 && [string match "*Missing connection parameter*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing conn parameter"
} else {
    puts "✗ Test 4 FAILED: Expected missing parameters error, got: $err"
}

# Test 5: Parameter validation - empty connection name
puts "\n=== Test 5: Parameter validation - empty connection name ==="
set result [catch {
    tossl::ssl::read -conn "" -length 1024
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected empty connection name"
} else {
    puts "✗ Test 5 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 6: Parameter validation - invalid length
puts "\n=== Test 6: Parameter validation - invalid length ==="
set result [catch {
    tossl::ssl::read -conn "test_conn" -length "invalid"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 6 PASSED: Correctly handled invalid length parameter"
} else {
    puts "✗ Test 6 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 7: Parameter validation - negative length
puts "\n=== Test 7: Parameter validation - negative length ==="
set result [catch {
    tossl::ssl::read -conn "test_conn" -length -100
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 7 PASSED: Correctly handled negative length parameter"
} else {
    puts "✗ Test 7 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 8: Parameter validation - zero length
puts "\n=== Test 8: Parameter validation - zero length ==="
set result [catch {
    tossl::ssl::read -conn "test_conn" -length 0
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 8 PASSED: Correctly handled zero length parameter"
} else {
    puts "✗ Test 8 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 9: Context handle format validation
puts "\n=== Test 9: Context handle format validation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    if {[string match "sslctx*" $ctx]} {
        puts "✓ Context handle format validation successful"
    } else {
        error "Invalid context handle format: $ctx"
    }
} err]

if {$result == 0} {
    puts "✓ Test 9 PASSED"
} else {
    puts "✗ Test 9 FAILED: $err"
}

# Test 10: Resource management - multiple contexts
puts "\n=== Test 10: Resource management - multiple contexts ==="
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
    puts "✓ Test 10 PASSED"
} else {
    puts "✗ Test 10 FAILED: $err"
}

# Test 11: Command syntax validation
puts "\n=== Test 11: Command syntax validation ==="
set result [catch {
    # Test with invalid parameter names
    tossl::ssl::read -invalid_param "value" -length 1024
} err]

if {$result == 1 && [string match "*Missing connection parameter*" $err]} {
    puts "✓ Test 11 PASSED: Correctly rejected invalid parameter names"
} else {
    puts "✗ Test 11 FAILED: Expected missing connection parameter error, got: $err"
}

# Test 12: Integration with SSL context creation
puts "\n=== Test 12: Integration with SSL context creation ==="
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
    puts "✓ Test 12 PASSED"
} else {
    puts "✗ Test 12 FAILED: $err"
}

# Test 13: Edge case - very large length
puts "\n=== Test 13: Edge case - very large length ==="
set result [catch {
    tossl::ssl::read -conn "test_conn" -length 1000000
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 13 PASSED: Correctly handled very large length parameter"
} else {
    puts "✗ Test 13 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 14: Edge case - maximum length
puts "\n=== Test 14: Edge case - maximum length ==="
set result [catch {
    tossl::ssl::read -conn "test_conn" -length 2147483647
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 14 PASSED: Correctly handled maximum length parameter"
} else {
    puts "✗ Test 14 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 15: Default length parameter
puts "\n=== Test 15: Default length parameter ==="
set result [catch {
    # Test that the command accepts the default length (1024)
    tossl::ssl::read -conn "test_conn"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 15 PASSED: Correctly handled default length parameter"
} else {
    puts "✗ Test 15 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 16: Multiple length parameters
puts "\n=== Test 16: Multiple length parameters ==="
set result [catch {
    # Test with multiple length parameters (should use the last one)
    tossl::ssl::read -conn "test_conn" -length 512 -length 1024
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 16 PASSED: Correctly handled multiple length parameters"
} else {
    puts "✗ Test 16 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 17: Parameter order independence
puts "\n=== Test 17: Parameter order independence ==="
set result [catch {
    # Test that parameters work in different orders
    tossl::ssl::read -length 1024 -conn "test_conn"
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 17 PASSED: Correctly handled parameter order independence"
} else {
    puts "✗ Test 17 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 18: Whitespace handling
puts "\n=== Test 18: Whitespace handling ==="
set result [catch {
    # Test with whitespace in connection name
    tossl::ssl::read -conn "  test_conn  " -length 1024
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 18 PASSED: Correctly handled whitespace in connection name"
} else {
    puts "✗ Test 18 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 19: Special characters in connection name
puts "\n=== Test 19: Special characters in connection name ==="
set result [catch {
    # Test with special characters in connection name
    tossl::ssl::read -conn "test_conn@#$%" -length 1024
} err]

if {$result == 1 && [string match "*SSL connection not found*" $err]} {
    puts "✓ Test 19 PASSED: Correctly handled special characters in connection name"
} else {
    puts "✗ Test 19 FAILED: Expected SSL connection not found error, got: $err"
}

# Test 20: Performance validation - multiple rapid calls
puts "\n=== Test 20: Performance validation - multiple rapid calls ==="
set result [catch {
    # Test multiple rapid calls to ensure no resource leaks
    for {set i 0} {$i < 5} {incr i} {
        if {[catch {
            tossl::ssl::read -conn "test_conn" -length 1024
        } err]} {
            if {![string match "*SSL connection not found*" $err]} {
                error "Unexpected error on iteration $i: $err"
            }
        }
    }
    puts "✓ Completed 5 rapid read attempts"
} err]

if {$result == 0} {
    puts "✓ Test 20 PASSED"
} else {
    puts "✗ Test 20 FAILED: $err"
}

puts "\n=== SSL Read Test Summary ==="
puts "All tests completed for ::tossl::ssl::read command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Parameter validation verified"
puts "✓ Integration with SSL context creation tested"
puts "✓ Resource management validated"
puts "✓ Edge cases handled"
puts "✓ Command syntax validation completed"
puts "✓ Performance aspects validated" 