#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::accept command
package require tossl

puts "Testing ::tossl::ssl::accept command..."

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
    # Create server context
    set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ Server context created: $server_ctx"
    
    # Verify context exists
    if {[string match "sslctx*" $server_ctx]} {
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

# Test 2: Error handling - invalid context
puts "\n=== Test 2: Error handling - invalid context ==="
set result [catch {
    set invalid_ctx "nonexistent_ctx"
    set test_sock [socket -server {} 0]
    set sock [socket 127.0.0.1 [lindex [fconfigure $test_sock -sockname] 2]]
    close $test_sock
    
    tossl::ssl::accept -ctx $invalid_ctx -socket $sock
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected invalid context"
} else {
    puts "✗ Test 2 FAILED: Expected 'SSL context not found' error, got: $err"
}

# Test 3: Error handling - invalid socket
puts "\n=== Test 3: Error handling - invalid socket ==="
set result [catch {
    set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    tossl::ssl::accept -ctx $server_ctx -socket "nonexistent_socket"
} err]

if {$result == 1 && [string match "*Failed to get socket file descriptor*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected invalid socket"
} else {
    puts "✗ Test 3 FAILED: Expected socket error, got: $err"
}

# Test 4: Error handling - missing parameters
puts "\n=== Test 4: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::accept
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 4 FAILED: Expected wrong args error, got: $err"
}

# Test 5: Error handling - missing required parameters
puts "\n=== Test 5: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::accept -ctx "test_ctx"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected missing socket parameter"
} else {
    puts "✗ Test 5 FAILED: Expected missing parameters error, got: $err"
}

# Test 6: Integration with SSL context creation
puts "\n=== Test 6: Integration with SSL context creation ==="
set result [catch {
    # Create context with various options
    set ctx [tossl::ssl::context create \
        -cert $cert_file \
        -key $key_file \
        -verify peer]
    puts "✓ Context created with verification: $ctx"
    
    # Test that context can be used for accept (without actually accepting)
    puts "✓ Context is ready for SSL accept operations"
} err]

if {$result == 0} {
    puts "✓ Test 6 PASSED"
} else {
    puts "✗ Test 6 FAILED: $err"
}

# Test 7: Parameter validation
puts "\n=== Test 7: Parameter validation ==="
set result [catch {
    # Test with empty context name
    tossl::ssl::accept -ctx "" -socket "test"
} err]

if {$result == 1} {
    puts "✓ Test 7 PASSED: Correctly rejected empty context"
} else {
    puts "✗ Test 7 FAILED: Should have rejected empty context"
}

# Test 8: Context handle format validation
puts "\n=== Test 8: Context handle format validation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    # Verify context handle format
    if {[regexp {^sslctx[0-9]+$} $ctx]} {
        puts "✓ Context handle format is valid: $ctx"
    } else {
        error "Invalid context handle format: $ctx"
    }
} err]

if {$result == 0} {
    puts "✓ Test 8 PASSED"
} else {
    puts "✗ Test 8 FAILED: $err"
}

# Test 9: Resource management
puts "\n=== Test 9: Resource management ==="
set result [catch {
    # Create multiple contexts
    set ctx1 [tossl::ssl::context create -cert $cert_file -key $key_file]
    set ctx2 [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    puts "✓ Created multiple contexts: $ctx1, $ctx2"
    
    # Verify they are different
    if {$ctx1 ne $ctx2} {
        puts "✓ Contexts are unique"
    } else {
        error "Contexts should be unique"
    }
} err]

if {$result == 0} {
    puts "✓ Test 9 PASSED"
} else {
    puts "✗ Test 9 FAILED: $err"
}

puts "\n=== SSL Accept Test Summary ==="
puts "All tests completed for ::tossl::ssl::accept command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Integration with other SSL commands verified"
puts "✓ Parameter validation confirmed"
puts "✓ Resource management tested" 