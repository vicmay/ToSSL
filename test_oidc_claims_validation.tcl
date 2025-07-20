#!/usr/bin/env tclsh

# OIDC Claims Validation Test
# Tests the new claims validation functions

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "❌ Failed to load libtossl.so"
    exit 1
}

puts "🔍 OIDC Claims Validation Test"
puts "=============================="
puts ""

set passed 0
set total 0

proc test {name script} {
    global passed total
    incr total
    puts "Test $total: $name"
    
    if {[catch {eval $script} result]} {
        puts "  ❌ FAILED: $result"
    } else {
        if {[string first "PASS" $result] == 0} {
            puts "  ✅ PASSED: $result"
            incr passed
        } else {
            puts "  ❌ FAILED: $result"
        }
    }
}

# Test 1: Validate claims with valid data
test "Validate claims with valid data" {
    set claims {
        {
            "sub": "1234567890",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "email_verified": true,
            "phone_number": "+1-555-123-4567",
            "picture": "https://example.com/john.jpg",
            "updated_at": 1640995200
        }
    }
    
    set result [tossl::oidc::validate_claims \
        -claims $claims \
        -required_claims {sub name email email_verified phone_number picture updated_at}]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: missing=[dict get $result missing_claims], invalid=[dict get $result invalid_claims]"
    }
}

# Test 2: Validate claims with missing required claims
test "Validate claims with missing required claims" {
    set claims {
        {
            "sub": "1234567890",
            "name": "John Doe",
            "email": "john.doe@example.com"
        }
    }
    
    set result [tossl::oidc::validate_claims \
        -claims $claims \
        -required_claims {sub name email phone_number picture}]
    
    if {![dict get $result valid]} {
        set missing [dict get $result missing_claims]
        if {[lsearch $missing "phone_number"] >= 0 && [lsearch $missing "picture"] >= 0} {
            return "PASS"
        } else {
            return "FAIL: Wrong missing claims: $missing"
        }
    } else {
        return "Should have failed validation"
    }
}

# Test 3: Validate claims with invalid email format
test "Validate claims with invalid email format" {
    set claims {
        {
            "sub": "1234567890",
            "name": "John Doe",
            "email": "invalid-email-format",
            "email_verified": true
        }
    }
    
    set result [tossl::oidc::validate_claims \
        -claims $claims \
        -required_claims {sub name email email_verified}]
    
    if {![dict get $result valid]} {
        set invalid [dict get $result invalid_claims]
        if {[lsearch $invalid "email"] >= 0} {
            return "PASS"
        } else {
            return "FAIL: Wrong invalid claims: $invalid"
        }
    } else {
        return "Should have failed validation"
    }
}

# Test 4: Check specific claim value
test "Check specific claim value" {
    set claims {
        {
            "sub": "1234567890",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "email_verified": true
        }
    }
    
    set result [tossl::oidc::check_claim \
        -claims $claims \
        -claim "email" \
        -value "john.doe@example.com"]
    
    if {[dict get $result matches]} {
        return "PASS"
    } else {
        return "FAIL: Failed to match email value"
    }
}

# Test 5: Check claim value that doesn't match
test "Check claim value that doesn't match" {
    set claims {
        {
            "sub": "1234567890",
            "name": "John Doe",
            "email": "john.doe@example.com"
        }
    }
    
    set result [tossl::oidc::check_claim \
        -claims $claims \
        -claim "email" \
        -value "wrong.email@example.com"]
    
    if {![dict get $result matches]} {
        return "PASS"
    } else {
        return "FAIL: Incorrectly matched wrong value"
    }
}

# Test 6: Validate email format
test "Validate email format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "email" \
        -value "valid.email@example.com"]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Failed to validate valid email: [dict get $result error]"
    }
}

# Test 7: Validate invalid email format
test "Validate invalid email format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "email" \
        -value "invalid-email-format"]
    
    if {![dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Incorrectly accepted invalid email"
    }
}

# Test 8: Validate phone number format
test "Validate phone number format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "phone_number" \
        -value "+1-555-123-4567"]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Failed to validate valid phone number: [dict get $result error]"
    }
}

# Test 9: Validate invalid phone number format
test "Validate invalid phone number format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "phone_number" \
        -value "invalid-phone"]
    
    if {![dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Incorrectly accepted invalid phone number"
    }
}

# Test 10: Validate URL format
test "Validate URL format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "picture" \
        -value "https://example.com/photo.jpg"]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Failed to validate valid URL: [dict get $result error]"
    }
}

# Test 11: Validate invalid URL format
test "Validate invalid URL format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "picture" \
        -value "not-a-url"]
    
    if {![dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Incorrectly accepted invalid URL"
    }
}

# Test 12: Validate boolean format
test "Validate boolean format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "email_verified" \
        -value "true"]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Failed to validate valid boolean: [dict get $result error]"
    }
}

# Test 13: Validate timestamp format
test "Validate timestamp format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "updated_at" \
        -value "1640995200"]
    
    if {[dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Failed to validate valid timestamp: [dict get $result error]"
    }
}

# Test 14: Validate invalid timestamp format
test "Validate invalid timestamp format" {
    set result [tossl::oidc::validate_claim_format \
        -claim "updated_at" \
        -value "not-a-timestamp"]
    
    if {![dict get $result valid]} {
        return "PASS"
    } else {
        return "FAIL: Incorrectly accepted invalid timestamp"
    }
}

# Test 15: Check boolean claim value
test "Check boolean claim value" {
    set claims {
        {
            "email_verified": true,
            "phone_number_verified": false
        }
    }
    
    set result1 [tossl::oidc::check_claim \
        -claims $claims \
        -claim "email_verified" \
        -value "true"]
    
    set result2 [tossl::oidc::check_claim \
        -claims $claims \
        -claim "phone_number_verified" \
        -value "false"]
    
    if {[dict get $result1 matches] && [dict get $result2 matches]} {
        return "PASS"
    } else {
        return "FAIL: Failed to match boolean values"
    }
}

puts ""
puts "Test Results: $passed/$total tests passed"
puts ""

if {$passed == $total} {
    puts "🎉 ALL OIDC CLAIMS VALIDATION TESTS PASSED!"
    puts "✅ Claims validation functions are working correctly"
    puts "✅ Format validation is working correctly"
    puts "✅ Value checking is working correctly"
} else {
    puts "❌ Some tests failed!"
    exit 1
}

puts ""
puts "Implemented OIDC Claims Validation Functions:"
puts "✅ tossl::oidc::validate_claims - Validate required claims and formats"
puts "✅ tossl::oidc::check_claim - Check specific claim values"
puts "✅ tossl::oidc::validate_claim_format - Validate claim format"
puts ""
puts "Supported Claim Formats:"
puts "✅ Email validation (contains @, valid domain)"
puts "✅ Phone number validation (digits, spaces, dashes, parentheses, +)"
puts "✅ URL validation (http:// or https:// with domain)"
puts "✅ Boolean validation (true/false, 1/0, yes/no)"
puts "✅ Timestamp validation (valid integer, reasonable range)"
puts ""
puts "OIDC Claims Validation Implementation: COMPLETE! 🎉" 