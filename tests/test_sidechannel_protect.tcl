# Test for ::tossl::sidechannel::protect
load ./libtossl.so

puts "Testing ::tossl::sidechannel::protect..."

;# Test 1: Basic side-channel protection check
puts "\n--- Test 1: Basic Side-Channel Protection Check ---"
try {
    set protection_info [tossl::sidechannel::protect]
    puts "Side-channel protection info: $protection_info"
    
    ;# Verify expected fields are present
    if {[dict exists $protection_info constant_time_ops] && 
        [dict exists $protection_info memory_protection] && 
        [dict exists $protection_info timing_protection] && 
        [dict exists $protection_info cache_protection] && 
        [dict exists $protection_info side_channel_protection]} {
        puts "✓ All expected protection fields present"
    } else {
        puts "✗ Missing expected protection fields"
        exit 1
    }
    
    ;# Verify all protection features are enabled (OpenSSL 3.x should have these)
    if {[dict get $protection_info constant_time_ops] == 1} {
        puts "✓ Constant-time operations supported"
    } else {
        puts "✗ Constant-time operations not supported"
        exit 1
    }
    
    if {[dict get $protection_info memory_protection] == 1} {
        puts "✓ Memory protection supported"
    } else {
        puts "✗ Memory protection not supported"
        exit 1
    }
    
    if {[dict get $protection_info timing_protection] == 1} {
        puts "✓ Timing protection supported"
    } else {
        puts "✗ Timing protection not supported"
        exit 1
    }
    
    if {[dict get $protection_info cache_protection] == 1} {
        puts "✓ Cache attack protection supported"
    } else {
        puts "✗ Cache attack protection not supported"
        exit 1
    }
    
    ;# Verify overall protection status
    if {[dict get $protection_info side_channel_protection] == 1} {
        puts "✓ Overall side-channel protection enabled"
    } else {
        puts "✗ Overall side-channel protection not enabled"
        exit 1
    }
    
} on error {err} {
    puts "✗ Basic side-channel protection check failed: $err"
    exit 1
}

;# Test 2: Error handling - extra arguments
puts "\n--- Test 2: Error Handling - Extra Arguments ---"
if {[catch {tossl::sidechannel::protect extra} err]} {
    puts "✓ Error on extra arguments: $err"
} else {
    puts "✗ Extra arguments should have errored"
    exit 1
}

;# Test 3: Error handling - invalid arguments
puts "\n--- Test 3: Error Handling - Invalid Arguments ---"
if {[catch {tossl::sidechannel::protect -invalid} err]} {
    puts "✓ Error on invalid arguments: $err"
} else {
    puts "✗ Invalid arguments should have errored"
    exit 1
}

;# Test 4: Performance test - multiple calls
puts "\n--- Test 4: Performance Test - Multiple Calls ---"
try {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set protection_info [tossl::sidechannel::protect]
        
        ;# Verify the result is consistent
        if {[dict get $protection_info side_channel_protection] != 1} {
            puts "✗ Inconsistent protection status on call $i"
            exit 1
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "✓ Processed 100 protection checks in ${duration}ms"
    
} on error {err} {
    puts "✗ Performance test failed: $err"
    exit 1
}

;# Test 5: Integration test - with cryptographic operations
puts "\n--- Test 5: Integration Test - With Cryptographic Operations ---"
try {
    ;# Get protection status
    set protection_info [tossl::sidechannel::protect]
    
    ;# Perform cryptographic operations that should benefit from side-channel protection
    if {[dict get $protection_info side_channel_protection]} {
        puts "Side-channel protection available - testing secure operations..."
        
        ;# Generate a key (should use constant-time operations)
        set keys [tossl::key::generate -type rsa -bits 2048]
        puts "✓ RSA key generation completed with side-channel protection"
        
        ;# Perform signing (should use constant-time operations)
        set test_data [tossl::randbytes 32]
        set private_key [dict get $keys private]
        set signature [tossl::rsa::sign -key $private_key -data $test_data -alg sha256]
        puts "✓ RSA signing completed with side-channel protection"
        
        ;# Perform verification (should use constant-time operations)
        set public_key [dict get $keys public]
        set verify_result [tossl::rsa::verify -key $public_key -data $test_data -sig $signature -alg sha256]
        puts "✓ RSA verification completed with side-channel protection"
        
        if {$verify_result} {
            puts "✓ Verification successful"
        } else {
            puts "✗ Verification failed"
            exit 1
        }
        
    } else {
        puts "Side-channel protection not available - skipping integration test"
    }
    
} on error {err} {
    puts "✗ Integration test failed: $err"
    exit 1
}

;# Test 6: Edge case - rapid successive calls
puts "\n--- Test 6: Edge Case - Rapid Successive Calls ---"
try {
    ;# Make rapid successive calls to ensure no race conditions
    for {set i 0} {$i < 10} {incr i} {
        set protection_info [tossl::sidechannel::protect]
        
        ;# Verify all fields are present and consistent
        foreach field {constant_time_ops memory_protection timing_protection cache_protection side_channel_protection} {
            if {![dict exists $protection_info $field]} {
                puts "✗ Missing field '$field' on call $i"
                exit 1
            }
            
            set value [dict get $protection_info $field]
            if {$value != 0 && $value != 1} {
                puts "✗ Invalid value for field '$field': $value on call $i"
                exit 1
            }
        }
    }
    
    puts "✓ All rapid successive calls successful"
    
} on error {err} {
    puts "✗ Rapid successive calls test failed: $err"
    exit 1
}

;# Test 7: Security validation - protection consistency
puts "\n--- Test 7: Security Validation - Protection Consistency ---"
try {
    set protection_info [tossl::sidechannel::protect]
    
    ;# Verify that if all individual protections are enabled, overall protection is enabled
    set individual_protections [list \
        [dict get $protection_info constant_time_ops] \
        [dict get $protection_info memory_protection] \
        [dict get $protection_info timing_protection] \
        [dict get $protection_info cache_protection]]
    
    set all_enabled 1
    foreach protection $individual_protections {
        if {$protection != 1} {
            set all_enabled 0
            break
        }
    }
    
    set overall_protection [dict get $protection_info side_channel_protection]
    
    if {$all_enabled && $overall_protection == 1} {
        puts "✓ Protection consistency validated"
    } elseif {!$all_enabled && $overall_protection == 0} {
        puts "✓ Protection consistency validated (some protections disabled)"
    } else {
        puts "✗ Protection consistency check failed"
        puts "  Individual protections: $individual_protections"
        puts "  Overall protection: $overall_protection"
        exit 1
    }
    
} on error {err} {
    puts "✗ Security validation failed: $err"
    exit 1
}

puts "\nAll ::tossl::sidechannel::protect tests passed" 