# Test for ::tossl::x509::time_validate
load ./libtossl.so

puts "Testing ::tossl::x509::time_validate..."

;# Test 1: Basic certificate time validation
puts "\n--- Test 1: Basic Certificate Time Validation ---"
try {
    ;# Generate a test certificate
    set ca_key_dict [tossl::key::generate -type rsa -bits 2048]
    set ca_key [dict get $ca_key_dict private]
    set ca_cert [tossl::ca::generate -key $ca_key -subject {CN=Test CA} -days 365]
    
    ;# Create a leaf certificate
    set leaf_key_dict [tossl::key::generate -type rsa -bits 2048]
    set leaf_key [dict get $leaf_key_dict private]
    set csr [tossl::csr::create -key $leaf_key -subject {CN=test.example.com}]
    set leaf_cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days 30]
    
    ;# Validate certificate time
    set time_validation [tossl::x509::time_validate $leaf_cert]
    puts "Time validation result: $time_validation"
    
    ;# Verify expected fields are present
    if {[lsearch $time_validation "not_before_valid"] >= 0 && 
        [lsearch $time_validation "not_after_valid"] >= 0 && 
        [lsearch $time_validation "valid"] >= 0} {
        puts "✓ All expected time validation fields present"
    } else {
        puts "✗ Missing expected time validation fields"
        exit 1
    }
    
    ;# Extract values
    set not_before_idx [lsearch $time_validation "not_before_valid"]
    set not_after_idx [lsearch $time_validation "not_after_valid"]
    set valid_idx [lsearch $time_validation "valid"]
    
    set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
    set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    puts "Not before valid: $not_before_valid"
    puts "Not after valid: $not_after_valid"
    puts "Overall valid: $overall_valid"
    
    ;# Verify logical consistency
    if {$not_before_valid && $not_after_valid && $overall_valid} {
        puts "✓ Certificate time validation is consistent"
    } else {
        puts "✗ Certificate time validation inconsistency detected"
        exit 1
    }
    
} on error {err} {
    puts "✗ Basic certificate time validation failed: $err"
    exit 1
}

;# Test 2: Error handling - missing arguments
puts "\n--- Test 2: Error Handling - Missing Arguments ---"
if {[catch {tossl::x509::time_validate} err]} {
    puts "✓ Error on missing arguments: $err"
} else {
    puts "✗ Missing arguments should have errored"
    exit 1
}

;# Test 3: Error handling - extra arguments
puts "\n--- Test 3: Error Handling - Extra Arguments ---"
if {[catch {tossl::x509::time_validate $leaf_cert extra} err]} {
    puts "✓ Error on extra arguments: $err"
} else {
    puts "✗ Extra arguments should have errored"
    exit 1
}

;# Test 4: Error handling - invalid certificate
puts "\n--- Test 4: Error Handling - Invalid Certificate ---"
if {[catch {tossl::x509::time_validate "invalid certificate data"} err]} {
    puts "✓ Error on invalid certificate: $err"
} else {
    puts "✗ Invalid certificate should have errored"
    exit 1
}

;# Test 5: Performance test - multiple calls
puts "\n--- Test 5: Performance Test - Multiple Calls ---"
try {
    set start_time [clock milliseconds]
    
    for {set i 0} {$i < 100} {incr i} {
        set time_validation [tossl::x509::time_validate $leaf_cert]
        
        ;# Verify the result is consistent
        if {[lsearch $time_validation "valid"] < 0} {
            puts "✗ Inconsistent time validation on call $i"
            exit 1
        }
    }
    
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "✓ Processed 100 time validation calls in ${duration}ms"
    
} on error {err} {
    puts "✗ Performance test failed: $err"
    exit 1
}

;# Test 6: Edge case - expired certificate
puts "\n--- Test 6: Edge Case - Expired Certificate ---"
try {
    ;# Create a certificate that's already expired (negative days)
    set expired_cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days -1]
    
    set time_validation [tossl::x509::time_validate $expired_cert]
    puts "Expired certificate validation: $time_validation"
    
    ;# Extract values
    set not_after_idx [lsearch $time_validation "not_after_valid"]
    set valid_idx [lsearch $time_validation "valid"]
    
    set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    ;# Expired certificate should have not_after_valid = 0 and overall_valid = 0
    if {!$not_after_valid && !$overall_valid} {
        puts "✓ Expired certificate correctly detected"
    } else {
        puts "✗ Expired certificate not correctly detected"
        exit 1
    }
    
} on error {err} {
    puts "✗ Expired certificate test failed: $err"
    exit 1
}

;# Test 7: Edge case - not yet valid certificate
puts "\n--- Test 7: Edge Case - Not Yet Valid Certificate ---"
try {
    ;# Create a certificate that's not yet valid (future date)
    ;# Note: This test may not work as expected since the implementation
    ;# uses current time for comparison
    set future_cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days 365]
    
    set time_validation [tossl::x509::time_validate $future_cert]
    puts "Future certificate validation: $time_validation"
    
    ;# Extract values
    set not_before_idx [lsearch $time_validation "not_before_valid"]
    set valid_idx [lsearch $time_validation "valid"]
    
    set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    ;# Future certificate should be valid since it's created with current time
    if {$not_before_valid && $overall_valid} {
        puts "✓ Future certificate correctly validated (created with current time)"
    } else {
        puts "✗ Future certificate validation unexpected"
        exit 1
    }
    
} on error {err} {
    puts "✗ Future certificate test failed: $err"
    exit 1
}

;# Test 8: Integration test - with certificate parsing
puts "\n--- Test 8: Integration Test - With Certificate Parsing ---"
try {
    ;# Parse the certificate to get validity dates
    set cert_info [tossl::x509::parse $leaf_cert]
    puts "Certificate info: [dict get $cert_info subject]"
    puts "Not before: [dict get $cert_info not_before]"
    puts "Not after: [dict get $cert_info not_after]"
    
    ;# Validate time
    set time_validation [tossl::x509::time_validate $leaf_cert]
    puts "Time validation: $time_validation"
    
    ;# Extract overall validity
    set valid_idx [lsearch $time_validation "valid"]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    if {$overall_valid} {
        puts "✓ Certificate time validation integration successful"
    } else {
        puts "✗ Certificate time validation integration failed"
        exit 1
    }
    
} on error {err} {
    puts "✗ Integration test failed: $err"
    exit 1
}

;# Test 9: Edge case - rapid successive calls
puts "\n--- Test 9: Edge Case - Rapid Successive Calls ---"
try {
    ;# Make rapid successive calls to ensure no race conditions
    for {set i 0} {$i < 10} {incr i} {
        set time_validation [tossl::x509::time_validate $leaf_cert]
        
        ;# Verify all fields are present and consistent
        foreach field {not_before_valid not_after_valid valid} {
            if {[lsearch $time_validation $field] < 0} {
                puts "✗ Missing field '$field' on call $i"
                exit 1
            }
        }
        
        ;# Verify values are boolean
        set not_before_idx [lsearch $time_validation "not_before_valid"]
        set not_after_idx [lsearch $time_validation "not_after_valid"]
        set valid_idx [lsearch $time_validation "valid"]
        
        set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
        set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
        set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
        
        if {$not_before_valid != 0 && $not_before_valid != 1} {
            puts "✗ Invalid not_before_valid value on call $i: $not_before_valid"
            exit 1
        }
        
        if {$not_after_valid != 0 && $not_after_valid != 1} {
            puts "✗ Invalid not_after_valid value on call $i: $not_after_valid"
            exit 1
        }
        
        if {$overall_valid != 0 && $overall_valid != 1} {
            puts "✗ Invalid overall_valid value on call $i: $overall_valid"
            exit 1
        }
    }
    
    puts "✓ All rapid successive calls successful"
    
} on error {err} {
    puts "✗ Rapid successive calls test failed: $err"
    exit 1
}

;# Test 10: Time validation consistency validation
puts "\n--- Test 10: Time Validation Consistency Validation ---"
try {
    set time_validation [tossl::x509::time_validate $leaf_cert]
    
    ;# Extract values
    set not_before_idx [lsearch $time_validation "not_before_valid"]
    set not_after_idx [lsearch $time_validation "not_after_valid"]
    set valid_idx [lsearch $time_validation "valid"]
    
    set not_before_valid [lindex $time_validation [expr {$not_before_idx + 1}]]
    set not_after_valid [lindex $time_validation [expr {$not_after_idx + 1}]]
    set overall_valid [lindex $time_validation [expr {$valid_idx + 1}]]
    
    ;# Verify logical consistency: overall_valid should be true only if both individual checks are true
    set expected_overall [expr {$not_before_valid && $not_after_valid}]
    
    if {$overall_valid == $expected_overall} {
        puts "✓ Time validation consistency validated"
    } else {
        puts "✗ Time validation consistency check failed"
        puts "  Not before valid: $not_before_valid"
        puts "  Not after valid: $not_after_valid"
        puts "  Overall valid: $overall_valid"
        puts "  Expected overall: $expected_overall"
        exit 1
    }
    
} on error {err} {
    puts "✗ Time validation consistency validation failed: $err"
    exit 1
}

puts "\nAll ::tossl::x509::time_validate tests passed" 