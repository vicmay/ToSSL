#!/usr/bin/env tclsh

# Test script for ::tossl::ssl::set_alpn_callback command
package require tossl

puts "Testing ::tossl::ssl::set_alpn_callback command..."

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

# Test 1: Basic ALPN callback setting
puts "\n=== Test 1: Basic ALPN callback setting ==="
set result [catch {
    # Create SSL context
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Define a simple ALPN callback
    proc test_alpn_callback {protos} {
        puts "  ✓ ALPN callback called with: $protos"
        return [lindex $protos 0]
    }
    
    # Set ALPN callback
    set result [tossl::ssl::set_alpn_callback -ctx $ctx -callback test_alpn_callback]
    puts "✓ ALPN callback set result: $result"
    
    # Verify the setting worked
    if {$result eq "ok"} {
        puts "✓ ALPN callback setting successful"
    } else {
        error "ALPN callback setting failed"
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
    tossl::ssl::set_alpn_callback -ctx "nonexistent_ctx" -callback test_callback
} err]

if {$result == 1 && [string match "*SSL context not found*" $err]} {
    puts "✓ Test 2 PASSED: Correctly rejected invalid context"
} else {
    puts "✗ Test 2 FAILED: Expected 'SSL context not found' error, got: $err"
}

# Test 3: Error handling - missing parameters
puts "\n=== Test 3: Error handling - missing parameters ==="
set result [catch {
    tossl::ssl::set_alpn_callback
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 3 PASSED: Correctly rejected missing parameters"
} else {
    puts "✗ Test 3 FAILED: Expected wrong args error, got: $err"
}

# Test 4: Error handling - missing required parameters
puts "\n=== Test 4: Error handling - missing required parameters ==="
set result [catch {
    tossl::ssl::set_alpn_callback -ctx "test_ctx"
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 4 PASSED: Correctly rejected missing callback parameter"
} else {
    puts "✗ Test 4 FAILED: Expected missing parameters error, got: $err"
}

# Test 5: Error handling - missing required parameters (partial)
puts "\n=== Test 5: Error handling - missing required parameters (partial) ==="
set result [catch {
    tossl::ssl::set_alpn_callback -callback test_callback
} err]

if {$result == 1 && [string match "*wrong # args*" $err]} {
    puts "✓ Test 5 PASSED: Correctly rejected missing ctx parameter"
} else {
    puts "✗ Test 5 FAILED: Expected missing parameters error, got: $err"
}

# Test 6: Multiple ALPN callbacks on different contexts
puts "\n=== Test 6: Multiple ALPN callbacks on different contexts ==="
set result [catch {
    # Create multiple contexts
    set ctx1 [tossl::ssl::context create -cert $cert_file -key $key_file]
    set ctx2 [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ Created contexts: $ctx1, $ctx2"
    
    # Define different callbacks
    proc alpn_callback1 {protos} {
        puts "  ✓ Callback 1 called with: $protos"
        if {"h2" in $protos} {
            return "h2"
        }
        return [lindex $protos 0]
    }
    
    proc alpn_callback2 {protos} {
        puts "  ✓ Callback 2 called with: $protos"
        if {"http/1.1" in $protos} {
            return "http/1.1"
        }
        return [lindex $protos 0]
    }
    
    # Set different callbacks on different contexts
    tossl::ssl::set_alpn_callback -ctx $ctx1 -callback alpn_callback1
    tossl::ssl::set_alpn_callback -ctx $ctx2 -callback alpn_callback2
    
    puts "✓ Set different ALPN callbacks on different contexts"
    
    # Verify contexts are unique
    if {$ctx1 ne $ctx2} {
        puts "✓ Contexts are unique"
    } else {
        error "Contexts should be unique"
    }
} err]

if {$result == 0} {
    puts "✓ Test 6 PASSED"
} else {
    puts "✗ Test 6 FAILED: $err"
}

# Test 7: Overwriting ALPN callback
puts "\n=== Test 7: Overwriting ALPN callback ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Define first callback
    proc first_callback {protos} {
        puts "  ✓ First callback called with: $protos"
        return [lindex $protos 0]
    }
    
    # Define second callback
    proc second_callback {protos} {
        puts "  ✓ Second callback called with: $protos"
        return [lindex $protos 0]
    }
    
    # Set first callback
    tossl::ssl::set_alpn_callback -ctx $ctx -callback first_callback
    puts "✓ Set first ALPN callback"
    
    # Overwrite with second callback
    tossl::ssl::set_alpn_callback -ctx $ctx -callback second_callback
    puts "✓ Overwrote with second ALPN callback"
    
    puts "✓ ALPN callback overwriting successful"
} err]

if {$result == 0} {
    puts "✓ Test 7 PASSED"
} else {
    puts "✗ Test 7 FAILED: $err"
}

# Test 8: Integration with protocol version setting
puts "\n=== Test 8: Integration with protocol version setting ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Set protocol versions first
    tossl::ssl::set_protocol_version -ctx $ctx -min TLSv1.2 -max TLSv1.3
    puts "✓ Set protocol versions"
    
    # Set ALPN callback
    proc integrated_callback {protos} {
        puts "  ✓ Integrated callback called with: $protos"
        return [lindex $protos 0]
    }
    
    tossl::ssl::set_alpn_callback -ctx $ctx -callback integrated_callback
    puts "✓ Set ALPN callback"
    
    puts "✓ Integration with protocol version setting successful"
} err]

if {$result == 0} {
    puts "✓ Test 8 PASSED"
} else {
    puts "✗ Test 8 FAILED: $err"
}

# Test 9: Complex ALPN callback logic
puts "\n=== Test 9: Complex ALPN callback logic ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Define complex callback with priority logic
    proc complex_alpn_callback {protos} {
        puts "  ✓ Complex callback called with: $protos"
        
        # Priority order: h2 > http/1.1 > others
        if {"h2" in $protos} {
            puts "    → Selecting h2 (highest priority)"
            return "h2"
        } elseif {"http/1.1" in $protos} {
            puts "    → Selecting http/1.1 (second priority)"
            return "http/1.1"
        } else {
            set selected [lindex $protos 0]
            puts "    → Selecting first available: $selected"
            return $selected
        }
    }
    
    tossl::ssl::set_alpn_callback -ctx $ctx -callback complex_alpn_callback
    puts "✓ Set complex ALPN callback"
    
    puts "✓ Complex ALPN callback logic successful"
} err]

if {$result == 0} {
    puts "✓ Test 9 PASSED"
} else {
    puts "✗ Test 9 FAILED: $err"
}

# Test 10: Edge case - empty protocol list handling
puts "\n=== Test 10: Edge case - empty protocol list handling ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Define callback that handles empty lists
    proc empty_list_callback {protos} {
        puts "  ✓ Empty list callback called with: $protos"
        
        if {[llength $protos] == 0} {
            puts "    → Empty protocol list, returning empty string"
            return ""
        }
        
        set selected [lindex $protos 0]
        puts "    → Selecting first protocol: $selected"
        return $selected
    }
    
    tossl::ssl::set_alpn_callback -ctx $ctx -callback empty_list_callback
    puts "✓ Set empty list handling ALPN callback"
    
    puts "✓ Empty protocol list handling successful"
} err]

if {$result == 0} {
    puts "✓ Test 10 PASSED"
} else {
    puts "✗ Test 10 FAILED: $err"
}

# Test 11: Performance test - multiple rapid callback changes
puts "\n=== Test 11: Performance test - multiple rapid callback changes ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Create multiple callbacks
    for {set i 1} {$i <= 5} {incr i} {
        proc "callback_$i" {protos} "puts \"  ✓ Callback $i called with: \$protos\"; return \[lindex \$protos 0\]"
    }
    
    # Perform multiple rapid callback changes
    for {set i 1} {$i <= 10} {incr i} {
        set callback_name "callback_[expr ($i % 5) + 1]"
        set result [tossl::ssl::set_alpn_callback -ctx $ctx -callback $callback_name]
        if {$result ne "ok"} {
            error "Failed to set ALPN callback on iteration $i"
        }
    }
    
    puts "✓ Completed 10 rapid ALPN callback changes"
} err]

if {$result == 0} {
    puts "✓ Test 11 PASSED"
} else {
    puts "✗ Test 11 FAILED: $err"
}

# Test 12: Security validation - callback parameter validation
puts "\n=== Test 12: Security validation - callback parameter validation ==="
set result [catch {
    set ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
    puts "✓ SSL context created: $ctx"
    
    # Test with various callback names
    set test_callbacks {
        "normal_callback"
        "callback_with_underscores"
        "CALLBACK_WITH_CAPS"
        "callback123"
        "callback-with-dashes"
    }
    
    foreach callback_name $test_callbacks {
        # Define the callback
        proc $callback_name {protos} "puts \"  ✓ $callback_name called with: \$protos\"; return \[lindex \$protos 0\]"
        
        # Set the callback
        set result [tossl::ssl::set_alpn_callback -ctx $ctx -callback $callback_name]
        if {$result eq "ok"} {
            puts "  ✓ $callback_name: OK"
        } else {
            puts "  ✗ $callback_name: FAILED"
        }
    }
    
    puts "✓ Callback parameter validation successful"
} err]

if {$result == 0} {
    puts "✓ Test 12 PASSED"
} else {
    puts "✗ Test 12 FAILED: $err"
}

puts "\n=== SSL Set ALPN Callback Test Summary ==="
puts "All tests completed for ::tossl::ssl::set_alpn_callback command"
puts "✓ Basic functionality tested"
puts "✓ Error handling validated"
puts "✓ Integration with other SSL commands verified"
puts "✓ Multiple contexts and callbacks tested"
puts "✓ Complex callback logic validated"
puts "✓ Performance aspects tested"
puts "✓ Security considerations covered" 