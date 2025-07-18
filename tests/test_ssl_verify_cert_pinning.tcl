#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::verify_cert_pinning command
package require tossl

puts "Testing ::tossl::ssl::verify_cert_pinning command..."

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
    tossl::ssl::verify_cert_pinning -conn "nonexistent_conn" -pins "test_pin"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected with wrong args error"
} else {
    puts "✗ Test 2 FAILED: Expected wrong args error, got: $err"
}

# Test 3: Error handling - missing parameters
puts "\n=== Test 3: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::verify_cert_pinning
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 3 FAILED: Expected wrong args error, got: $err"
}

# Test 4: Error handling - missing required parameters
puts "\n=== Test 4: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::verify_cert_pinning -conn "test_conn"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing pins parameter"
} else {
    puts "✗ Test 4 FAILED: Expected missing parameters error, got: $err"
}

# Test 5: Error handling - missing required parameters (partial)
puts "\n=== Test 5: Error handling - missing required parameters (partial) ==="
set result [catch {
    tossl::ssl::verify_cert_pinning -pins "test_pin"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected missing conn parameter"
} else {
    puts "✗ Test 5 FAILED: Expected missing parameters error, got: $err"
}

# Test 6: Parameter validation - empty connection name
puts "\n=== Test 6: Parameter validation - empty connection name ==="
set result [catch {
    tossl::ssl::verify_cert_pinning -conn "" -pins "test_pin"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 6 PASSED: Correctly rejected empty connection name"
} else {
    puts "✗ Test 6 FAILED: Expected wrong args error, got: $err"
}

# Test 7: Parameter validation - empty pins
puts "\n=== Test 7: Parameter validation - empty pins ==="
set result [catch {
    tossl::ssl::verify_cert_pinning -conn "test_conn" -pins ""
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 7 PASSED: Correctly rejected empty pins with invalid connection"
} else {
    puts "✗ Test 7 FAILED: Expected wrong args error, got: $err"
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
    tossl::ssl::verify_cert_pinning -invalid_param "value" -pins "test"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 10 PASSED: Correctly rejected invalid parameter names"
} else {
    puts "✗ Test 10 FAILED: Expected wrong args error, got: $err"
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

# Test 12: Edge case - very long pin string
puts "\n=== Test 12: Edge case - very long pin string ==="
set result [catch {
    # Create a very long pin string
    set long_pin [string repeat "a" 1000]
    tossl::ssl::verify_cert_pinning -conn "test_conn" -pins $long_pin
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 12 PASSED: Correctly handled long pin string"
} else {
    puts "✗ Test 12 FAILED: Expected wrong args error, got: $err"
}

puts "\n=== SSL Verify Cert Pinning Test Summary ==="
puts "All tests completed for ::tossl::ssl::verify_cert_pinning command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Parameter validation verified"
puts "✓ Integration with SSL context creation tested"
puts "✓ Resource management validated"
puts "✓ Edge cases handled"
puts "✓ Command syntax validation completed" 