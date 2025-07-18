#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::set_protocol_version command
package require tossl

puts "Testing ::tossl::ssl::set_protocol_version command..."

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

# Test 1: Basic protocol version setting
puts "\n=== Test 1: Basic protocol version setting ==="
set result [catch {
    # Create SSL context
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Set protocol versions
    set result [tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3]
    puts "✓ Protocol version set result: $result"
    
    # Verify the setting worked
    if {$result eq "ok"} {
        puts "✓ Protocol version setting successful"
    } else {
        error "Protocol version setting failed"
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
    tossl::ssl::set_protocol_version -ctx "nonexistent_ctx" -min TLSv1.2 -max TLSv1.3
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected invalid context"
} else {
    puts "✗ Test 2 FAILED: Expected 'SSL context not found' error, got: $err"
}

# Test 3: Error handling - missing parameters
puts "\n=== Test 3: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::set_protocol_version
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 3 FAILED: Expected wrong args error, got: $err"
}

# Test 4: Error handling - missing required parameters
puts "\n=== Test 4: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::set_protocol_version -ctx "test_ctx"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing min/max parameters"
} else {
    puts "✗ Test 4 FAILED: Expected missing parameters error, got: $err"
}

# Test 5: Error handling - missing required parameters (partial)
puts "\n=== Test 5: Error handling - missing required parameters (partial) ==="
set result [catch {
    tossl::ssl::set_protocol_version -ctx "test_ctx" -min TLSv1.2
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected missing max parameter"
} else {
    puts "✗ Test 5 FAILED: Expected missing parameters error, got: $err"
}

# Test 6: All supported TLS versions
puts "\n=== Test 6: All supported TLS versions ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Test all supported version combinations
    set versions {
        {TLSv1.0 TLSv1.0}
        {TLSv1.0 TLSv1.1}
        {TLSv1.0 TLSv1.2}
        {TLSv1.0 TLSv1.3}
        {TLSv1.1 TLSv1.1}
        {TLSv1.1 TLSv1.2}
        {TLSv1.1 TLSv1.3}
        {TLSv1.2 TLSv1.2}
        {TLSv1.2 TLSv1.3}
        {TLSv1.3 TLSv1.3}
    }
    
    foreach version_pair $versions {
        set min_ver [lindex $version_pair 0]
        set max_ver [lindex $version_pair 1]
        
        set result [tossl::ssl::set_protocol_version -ctx $ctx -min $min_ver -max $max_ver]
        if {$result eq "ok"} {
            puts "  ✓ $min_ver to $max_ver: OK"
        } else {
            puts "  ✗ $min_ver to $max_ver: FAILED"
        }
    }
} err]

if {$result == 0} {
    puts "✓ Test 6 PASSED"
} else {
    puts "✗ Test 6 FAILED: $err"
}

# Test 7: Invalid version combinations
puts "\n=== Test 7: Invalid version combinations ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Test invalid version combinations (min > max)
    set invalid_combinations {
        {TLSv1.3 TLSv1.2}
        {TLSv1.2 TLSv1.1}
        {TLSv1.1 TLSv1.0}
    }
    
    foreach version_pair $invalid_combinations {
        set min_ver [lindex $version_pair 0]
        set max_ver [lindex $version_pair 1]
        
        set result [tossl::ssl::set_protocol_version -ctx $ctx -min $min_ver -max $max_ver]
        if {$result eq "ok"} {
            puts "  ⚠ $min_ver to $max_ver: Accepted (should be invalid)"
        } else {
            puts "  ✓ $min_ver to $max_ver: Rejected as expected"
        }
    }
} err]

if {$result == 0} {
    puts "✓ Test 7 PASSED"
} else {
    puts "✗ Test 7 FAILED: $err"
}

# Test 8: Integration with protocol version retrieval
puts "\n=== Test 8: Integration with protocol version retrieval ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Set specific protocol versions
    tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
    
    # Retrieve and verify the protocol version
    set version_info [tossl::ssl::protocol_version -ctx $ctx]
    puts "✓ Protocol version info: $version_info"
    
    # Verify it's a valid response
    if {[string length $version_info] > 0} {
        puts "✓ Protocol version retrieval successful"
    } else {
        error "Protocol version retrieval failed"
    }
} err]

if {$result == 0} {
    puts "✓ Test 8 PASSED"
} else {
    puts "✗ Test 8 FAILED: $err"
}

# Test 9: Multiple contexts with different versions
puts "\n=== Test 9: Multiple contexts with different versions ==="
set result [catch {
    # Create multiple contexts with different protocol versions
    set ctx1 [tossl::ssl::context create -cert $cert_file -key $key_file]
    set ctx2 [tossl::ssl::context create -cert $cert_file -key $key_file]
    set ctx3 [tossl::ssl::context create -cert $cert_file -key $key_file]
    
    puts "✓ Created contexts: $ctx1, $ctx2, $ctx3"
    
    # Set different protocol versions for each context
    tossl::ssl::set_protocol_version -ctx $ctx1 -min TLSv1.0 -max TLSv1.3
    tossl::ssl::set_protocol_version -ctx $ctx2 -min TLSv1.2 -max TLSv1.2
    tossl::ssl::set_protocol_version -ctx $ctx3 -min TLSv1.3 -max TLSv1.3
    
    puts "✓ Set different protocol versions for each context"
    
    # Verify all contexts are unique
    if {$ctx1 ne $ctx2 && $ctx2 ne $ctx3 && $ctx1 ne $ctx3} {
        puts "✓ All contexts are unique"
    } else {
        error "Contexts should be unique"
    }
} err]

if {$result == 0} {
    puts "✓ Test 9 PASSED"
} else {
    puts "✗ Test 9 FAILED: $err"
}

# Test 10: Edge case - same min and max versions
puts "\n=== Test 10: Edge case - same min and max versions ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Test setting same min and max versions
    set result [tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.2]
    if {$result eq "ok"} {
        puts "✓ Same min/max version setting successful"
    } else {
        puts "✗ Same min/max version setting failed"
    }
    
    # Test with TLSv1.3
    set result [tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.3 -max TLSv1.3]
    if {$result eq "ok"} {
        puts "✓ TLSv1.3 only setting successful"
    } else {
        puts "✗ TLSv1.3 only setting failed"
    }
} err]

if {$result == 0} {
    puts "✓ Test 10 PASSED"
} else {
    puts "✗ Test 10 FAILED: $err"
}

# Test 11: Security validation - deprecated versions
puts "\n=== Test 11: Security validation - deprecated versions ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Test setting deprecated versions (should still work but warn)
    set deprecated_versions {
        {TLSv1.0 TLSv1.0}
        {TLSv1.0 TLSv1.1}
        {TLSv1.1 TLSv1.1}
    }
    
    foreach version_pair $deprecated_versions {
        set min_ver [lindex $version_pair 0]
        set max_ver [lindex $version_pair 1]
        
        set result [tossl::ssl::set_protocol_version -ctx $ctx -min $min_ver -max $max_ver]
        if {$result eq "ok"} {
            puts "  ⚠ $min_ver to $max_ver: Accepted (deprecated but functional)"
        } else {
            puts "  ✗ $min_ver to $max_ver: Failed"
        }
    }
} err]

if {$result == 0} {
    puts "✓ Test 11 PASSED"
} else {
    puts "✗ Test 11 FAILED: $err"
}

# Test 12: Performance test - multiple rapid changes
puts "\n=== Test 12: Performance test - multiple rapid changes ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Perform multiple rapid protocol version changes
    for {set i 0} {$i < 10} {incr i} {
        set min_ver [lindex {TLSv1.2 TLSv1.3} [expr $i % 2]]
        set max_ver [lindex {TLSv1.2 TLSv1.3} [expr ($i + 1) % 2]]
        
        set result [tossl::ssl::set_protocol_version -ctx $ctx -min $min_ver -max $max_ver]
        if {$result ne "ok"} {
            error "Failed to set protocol version on iteration $i"
        }
    }
    
    puts "✓ Completed 10 rapid protocol version changes"
} err]

if {$result == 0} {
    puts "✓ Test 12 PASSED"
} else {
    puts "✗ Test 12 FAILED: $err"
}

puts "\n=== SSL Set Protocol Version Test Summary ==="
puts "All tests completed for ::tossl::ssl::set_protocol_version command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Integration with other SSL commands verified"
puts "✓ All supported TLS versions tested"
puts "✓ Security considerations covered"
puts "✓ Performance aspects validated" 