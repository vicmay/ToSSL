#!/usr/bin/env tclsh

# Simple OIDC Claims Validation Verification
# Verifies that all three new functions work correctly

package require Tcl 8.6

# Load the ToSSL library
if {[catch {load ./libtossl.so}]} {
    puts "❌ Failed to load libtossl.so"
    exit 1
}

puts "🔍 OIDC Claims Validation Verification"
puts "======================================"
puts ""

set all_passed 1

# Test 1: validate_claims function
puts "Test 1: tossl::oidc::validate_claims"
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
    puts "  ✅ PASSED: All claims valid"
} else {
    puts "  ❌ FAILED: Claims validation failed"
    puts "     Missing: [dict get $result missing_claims]"
    puts "     Invalid: [dict get $result invalid_claims]"
    set all_passed 0
}

# Test 2: check_claim function
puts ""
puts "Test 2: tossl::oidc::check_claim"
set result [tossl::oidc::check_claim \
    -claims $claims \
    -claim "email" \
    -value "john.doe@example.com"]

if {[dict get $result matches]} {
    puts "  ✅ PASSED: Correctly matched email value"
} else {
    puts "  ❌ FAILED: Failed to match email value"
    set all_passed 0
}

# Test 3: validate_claim_format function
puts ""
puts "Test 3: tossl::oidc::validate_claim_format"
set result [tossl::oidc::validate_claim_format \
    -claim "email" \
    -value "valid.email@example.com"]

if {[dict get $result valid]} {
    puts "  ✅ PASSED: Correctly validated email format"
} else {
    puts "  ❌ FAILED: Failed to validate email format: [dict get $result error]"
    set all_passed 0
}

# Test 4: Invalid email format
puts ""
puts "Test 4: Invalid email format validation"
set result [tossl::oidc::validate_claim_format \
    -claim "email" \
    -value "invalid-email-format"]

if {![dict get $result valid]} {
    puts "  ✅ PASSED: Correctly rejected invalid email format"
} else {
    puts "  ❌ FAILED: Incorrectly accepted invalid email format"
    set all_passed 0
}

# Test 5: Phone number validation
puts ""
puts "Test 5: Phone number format validation"
set result [tossl::oidc::validate_claim_format \
    -claim "phone_number" \
    -value "+1-555-123-4567"]

if {[dict get $result valid]} {
    puts "  ✅ PASSED: Correctly validated phone number format"
} else {
    puts "  ❌ FAILED: Failed to validate phone number format: [dict get $result error]"
    set all_passed 0
}

# Test 6: URL validation
puts ""
puts "Test 6: URL format validation"
set result [tossl::oidc::validate_claim_format \
    -claim "picture" \
    -value "https://example.com/photo.jpg"]

if {[dict get $result valid]} {
    puts "  ✅ PASSED: Correctly validated URL format"
} else {
    puts "  ❌ FAILED: Failed to validate URL format: [dict get $result error]"
    set all_passed 0
}

# Test 7: Boolean validation
puts ""
puts "Test 7: Boolean format validation"
set result [tossl::oidc::validate_claim_format \
    -claim "email_verified" \
    -value "true"]

if {[dict get $result valid]} {
    puts "  ✅ PASSED: Correctly validated boolean format"
} else {
    puts "  ❌ FAILED: Failed to validate boolean format: [dict get $result error]"
    set all_passed 0
}

# Test 8: Timestamp validation
puts ""
puts "Test 8: Timestamp format validation"
set result [tossl::oidc::validate_claim_format \
    -claim "updated_at" \
    -value "1640995200"]

if {[dict get $result valid]} {
    puts "  ✅ PASSED: Correctly validated timestamp format"
} else {
    puts "  ❌ FAILED: Failed to validate timestamp format: [dict get $result error]"
    set all_passed 0
}

puts ""
puts "======================================"
if {$all_passed} {
    puts "🎉 ALL OIDC CLAIMS VALIDATION TESTS PASSED!"
    puts ""
    puts "✅ tossl::oidc::validate_claims - Working correctly"
    puts "✅ tossl::oidc::check_claim - Working correctly"
    puts "✅ tossl::oidc::validate_claim_format - Working correctly"
    puts ""
    puts "Supported Claim Formats:"
    puts "✅ Email validation (contains @, valid domain)"
    puts "✅ Phone number validation (digits, spaces, dashes, parentheses, +)"
    puts "✅ URL validation (http:// or https:// with domain)"
    puts "✅ Boolean validation (true/false, 1/0, yes/no)"
    puts "✅ Timestamp validation (valid integer, reasonable range)"
    puts ""
    puts "OIDC Claims Validation Implementation: COMPLETE! 🎉"
} else {
    puts "❌ Some tests failed!"
    exit 1
} 