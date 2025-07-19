#!/usr/bin/env tclsh
# UserInfo Endpoint Test for TOSSL OIDC

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== UserInfo Endpoint Test ==="

# Test 1: UserInfo validation
puts "\nTest 1: UserInfo validation"
set userinfo_data {
{
  "sub": "1234567890",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "picture": "https://example.com/john.jpg"
}
}

if {[catch {
    set result [tossl::oidc::validate_userinfo \
        -userinfo $userinfo_data \
        -expected_subject "1234567890"]
    puts "Validation result: $result"
} result]} {
    puts "Error: $result"
}

# Test 2: UserInfo validation with wrong subject
puts "\nTest 2: UserInfo validation with wrong subject"
if {[catch {
    set result [tossl::oidc::validate_userinfo \
        -userinfo $userinfo_data \
        -expected_subject "wrong_subject"]
    puts "Validation result: $result"
} result]} {
    puts "Expected error: $result"
}

# Test 3: Extract specific user claims
puts "\nTest 3: Extract specific user claims"
if {[catch {
    set result [tossl::oidc::extract_user_claims \
        -userinfo $userinfo_data \
        -claims {name email picture}]
    puts "Extracted claims: $result"
} result]} {
    puts "Error: $result"
}

# Test 4: Extract all available claims
puts "\nTest 4: Extract all available claims"
if {[catch {
    set result [tossl::oidc::extract_user_claims \
        -userinfo $userinfo_data \
        -claims {sub name given_name family_name email email_verified picture}]
    puts "All claims: $result"
} result]} {
    puts "Error: $result"
}

# Test 5: Invalid UserInfo data
puts "\nTest 5: Invalid UserInfo data"
if {[catch {
    set result [tossl::oidc::validate_userinfo \
        -userinfo "invalid json" \
        -expected_subject "1234567890"]
    puts "Validation result: $result"
} result]} {
    puts "Expected error: $result"
}

# Test 6: Missing subject in UserInfo
puts "\nTest 6: Missing subject in UserInfo"
set userinfo_no_sub {
{
  "name": "John Doe",
  "email": "john.doe@example.com"
}
}

if {[catch {
    set result [tossl::oidc::validate_userinfo \
        -userinfo $userinfo_no_sub \
        -expected_subject "1234567890"]
    puts "Validation result: $result"
} result]} {
    puts "Expected error: $result"
}

puts "\n=== UserInfo Endpoint Test Complete ===" 