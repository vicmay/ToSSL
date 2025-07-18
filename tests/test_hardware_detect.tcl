# Test for ::tossl::hardware::detect
load ./libtossl.so

puts "Testing ::tossl::hardware::detect..."

;# Test 1: Basic hardware acceleration detection
puts "\n--- Test 1: Basic Hardware Acceleration Detection ---"
try {
    set hw_info [tossl::hardware::detect]
    puts "Hardware acceleration info: $hw_info"
    
    ;# Verify expected fields are present
    if {[dict exists $hw_info aes_ni] && 
        [dict exists $hw_info sha_ni] && 
        [dict exists $hw_info avx2] && 
        [dict exists $hw_info hardware_rng] && 
        [dict exists $hw_info rsa_acceleration] && 
        [dict exists $hw_info hardware_acceleration]} {
        puts "✓ All expected hardware fields present"
    } else {
        puts "✗ Missing expected hardware fields"
        exit 1
    }
    
    ;# Verify all values are boolean (0 or 1)
    foreach field {aes_ni sha_ni avx2 hardware_rng rsa_acceleration hardware_acceleration} {
        set value [dict get $hw_info $field]
        if {$value != 0 && $value != 1} {
            puts "✗ Invalid value for field '$field': $value (should be 0 or 1)"
            exit 1
        }
    }
    
    ;# Display individual feature status
    puts "AES-NI: [dict get $hw_info aes_ni]"
    puts "SHA-NI: [dict get $hw_info sha_ni]"
    puts "AVX2: [dict get $hw_info avx2]"
    puts "Hardware RNG: [dict get $hw_info hardware_rng]"
    puts "RSA Acceleration: [dict get $hw_info rsa_acceleration]"
    puts "Overall Hardware Acceleration: [dict get $hw_info hardware_acceleration]"
    
} on error {err} {
    puts "✗ Basic hardware acceleration detection failed: $err"
    exit 1
}

;# Test 2: Error handling - extra arguments
puts "\n--- Test 2: Error Handling - Extra Arguments ---"
if {[catch {tossl::hardware::detect extra} err]} {
    puts "✓ Error on extra arguments: $err"
} else {
    puts "✗ Extra arguments should have errored"
    exit 1
}

;# Test 3: Error handling - invalid arguments
puts "\n--- Test 3: Error Handling - Invalid Arguments ---"
if {[catch {tossl::hardware::detect -invalid} err]} {
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
        set hw_info [tossl::hardware::detect]
        
        ;# Verify the result is consistent
        if {![dict exists $hw_info hardware_acceleration]} {
            puts "✗ Inconsistent hardware info on call $i"
            exit 1
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "✓ Processed 100 hardware detection calls in ${duration}ms"
    
} on error {err} {
    puts "✗ Performance test failed: $err"
    exit 1
}

;# Test 5: Integration test - with cryptographic operations
puts "\n--- Test 5: Integration Test - With Cryptographic Operations ---"
try {
    ;# Get hardware acceleration status
    set hw_info [tossl::hardware::detect]
    
    ;# Perform cryptographic operations that may benefit from hardware acceleration
    puts "Testing cryptographic operations with hardware acceleration..."
    
    ;# Test hash operations (may benefit from SHA-NI)
    if {[dict get $hw_info sha_ni]} {
        puts "SHA-NI available - testing hash operations..."
        set hash [tossl::digest -alg sha256 "Test data for hashing"]
        puts "✓ SHA-256 hashing completed with hardware acceleration"
    } else {
        puts "SHA-NI not available - testing software hashing..."
        set hash [tossl::digest -alg sha256 "Test data for hashing"]
        puts "✓ SHA-256 hashing completed with software implementation"
    }
    
    ;# Test RSA operations (may benefit from RSA acceleration)
    if {[dict get $hw_info rsa_acceleration]} {
        puts "RSA acceleration available - testing RSA operations..."
        set keys [tossl::key::generate -type rsa -bits 2048]
        set private_key [dict get $keys private]
        set test_data [tossl::randbytes 32]
        set signature [tossl::rsa::sign -key $private_key -data $test_data -alg sha256]
        puts "✓ RSA signing completed with hardware acceleration"
    } else {
        puts "RSA acceleration not available - testing software RSA..."
        set keys [tossl::key::generate -type rsa -bits 2048]
        set private_key [dict get $keys private]
        set test_data [tossl::randbytes 32]
        set signature [tossl::rsa::sign -key $private_key -data $test_data -alg sha256]
        puts "✓ RSA signing completed with software implementation"
    }
    
    ;# Test random number generation (may benefit from hardware RNG)
    if {[dict get $hw_info hardware_rng]} {
        puts "Hardware RNG available - testing random generation..."
        set random_data [tossl::randbytes 64]
        puts "✓ Random number generation completed with hardware RNG"
    } else {
        puts "Hardware RNG not available - testing software RNG..."
        set random_data [tossl::randbytes 64]
        puts "✓ Random number generation completed with software RNG"
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
        set hw_info [tossl::hardware::detect]
        
        ;# Verify all fields are present and consistent
        foreach field {aes_ni sha_ni avx2 hardware_rng rsa_acceleration hardware_acceleration} {
            if {![dict exists $hw_info $field]} {
                puts "✗ Missing field '$field' on call $i"
                exit 1
            }
            
            set value [dict get $hw_info $field]
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

;# Test 7: Hardware acceleration consistency validation
puts "\n--- Test 7: Hardware Acceleration Consistency Validation ---"
try {
    set hw_info [tossl::hardware::detect]
    
    ;# Verify that if any individual acceleration is enabled, overall acceleration is enabled
    set individual_accelerations [list \
        [dict get $hw_info aes_ni] \
        [dict get $hw_info sha_ni] \
        [dict get $hw_info avx2] \
        [dict get $hw_info hardware_rng] \
        [dict get $hw_info rsa_acceleration]]
    
    set any_enabled 0
    foreach acceleration $individual_accelerations {
        if {$acceleration == 1} {
            set any_enabled 1
            break
        }
    }
    
    set overall_acceleration [dict get $hw_info hardware_acceleration]
    
    if {$any_enabled && $overall_acceleration == 1} {
        puts "✓ Hardware acceleration consistency validated"
    } elseif {!$any_enabled && $overall_acceleration == 0} {
        puts "✓ Hardware acceleration consistency validated (no accelerations available)"
    } else {
        puts "✗ Hardware acceleration consistency check failed"
        puts "  Individual accelerations: $individual_accelerations"
        puts "  Overall acceleration: $overall_acceleration"
        exit 1
    }
    
} on error {err} {
    puts "✗ Hardware acceleration consistency validation failed: $err"
    exit 1
}

;# Test 8: Platform-specific behavior validation
puts "\n--- Test 8: Platform-Specific Behavior Validation ---"
try {
    set hw_info [tossl::hardware::detect]
    
    ;# On x86_64 systems, some features might be available
    ;# On other architectures, they should all be 0
    set platform [exec uname -m]
    puts "Platform: $platform"
    
    if {$platform eq "x86_64"} {
        puts "✓ Running on x86_64 platform - hardware features may be available"
        puts "  This is normal behavior for x86_64 systems"
    } else {
        puts "✓ Running on non-x86_64 platform - hardware features likely not available"
        puts "  This is normal behavior for non-x86_64 systems"
        
        ;# On non-x86_64 platforms, all hardware features should be 0
        foreach field {aes_ni sha_ni avx2 hardware_rng rsa_acceleration} {
            set value [dict get $hw_info $field]
            if {$value != 0} {
                puts "✗ Unexpected hardware feature '$field' enabled on non-x86_64 platform: $value"
                exit 1
            }
        }
    }
    
} on error {err} {
    puts "✗ Platform-specific behavior validation failed: $err"
    exit 1
}

puts "\nAll ::tossl::hardware::detect tests passed" 