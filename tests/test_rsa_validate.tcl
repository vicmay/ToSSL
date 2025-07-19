# Test for ::tossl::rsa::validate
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::validate..."

# 1. Basic RSA key validation (private key)
puts "\n1. Testing RSA private key validation..."
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set result [tossl::rsa::validate -key $priv]
if {$result == 1} {
    puts "PASS: RSA private key validation"
} else {
    puts stderr "FAIL: RSA private key validation"
    incr ::errors
}

# 2. Basic RSA key validation (public key)
puts "\n2. Testing RSA public key validation..."
set pub [dict get $keys public]
set result [tossl::rsa::validate -key $pub]
if {$result == 1} {
    puts "PASS: RSA public key validation"
} else {
    puts stderr "FAIL: RSA public key validation"
    incr ::errors
}

# 3. Test with different key sizes
puts "\n3. Testing different key sizes..."
set key_sizes {1024 2048 3072}
foreach size $key_sizes {
    set keys [tossl::key::generate -type rsa -bits $size]
    set priv [dict get $keys private]
    set pub [dict get $keys public]
    
    set priv_valid [tossl::rsa::validate -key $priv]
    set pub_valid [tossl::rsa::validate -key $pub]
    
    if {$priv_valid == 1 && $pub_valid == 1} {
        puts "PASS: RSA $size-bit key validation (both private and public)"
    } else {
        puts stderr "FAIL: RSA $size-bit key validation"
        incr ::errors
    }
}

# 4. Test with corrupted key (should fail)
puts "\n4. Testing corrupted key..."
set corrupted_key [string replace $priv 100 110 "INVALID"]
if {[catch {tossl::rsa::validate -key $corrupted_key} err]} {
    puts "PASS: Corrupted key (error as expected: $err)"
} else {
    puts stderr "FAIL: Corrupted key should have errored"
    incr ::errors
}

# 5. Test with non-RSA key (should fail)
puts "\n5. Testing non-RSA key..."
set ec_keys [tossl::key::generate -type ec -curve prime256v1]
set ec_priv [dict get $ec_keys private]
if {[catch {tossl::rsa::validate -key $ec_priv} err]} {
    puts "PASS: Non-RSA key (error as expected: $err)"
} else {
    puts stderr "FAIL: Non-RSA key should have errored"
    incr ::errors
}

# 6. Test with invalid PEM format
puts "\n6. Testing invalid PEM format..."
if {[catch {tossl::rsa::validate -key "invalid-pem-data"} err]} {
    puts "PASS: Invalid PEM format (error as expected: $err)"
} else {
    puts stderr "FAIL: Invalid PEM format should have errored"
    incr ::errors
}

# 7. Test with empty key
puts "\n7. Testing empty key..."
if {[catch {tossl::rsa::validate -key ""} err]} {
    puts "PASS: Empty key (error as expected: $err)"
} else {
    puts stderr "FAIL: Empty key should have errored"
    incr ::errors
}

# 8. Test error handling - missing arguments
puts "\n8. Testing missing arguments..."
if {[catch {tossl::rsa::validate} err]} {
    puts "PASS: Missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: Missing arguments should have errored"
    incr ::errors
}

# 9. Test error handling - wrong option
puts "\n9. Testing wrong option..."
if {[catch {tossl::rsa::validate -wrong $priv} err]} {
    puts "PASS: Wrong option (error as expected: $err)"
} else {
    puts stderr "FAIL: Wrong option should have errored"
    incr ::errors
}

puts "\nTotal errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::validate tests passed"
} 