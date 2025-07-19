# Test for ::tossl::rsa::components
load ./libtossl.so

set errors 0

puts "Testing ::tossl::rsa::components..."

# 1. Basic RSA components extraction
puts "\n1. Testing basic RSA components extraction..."
set keys [tossl::key::generate -type rsa -bits 2048]
set priv [dict get $keys private]
set components [tossl::rsa::components -key $priv]

# Check that all required components are present
set required_components {n e d p q dmp1 dmq1 iqmp}
foreach comp $required_components {
    if {[dict exists $components $comp]} {
        puts "PASS: Component '$comp' present"
    } else {
        puts stderr "FAIL: Component '$comp' missing"
        incr ::errors
    }
}

# 2. Validate component properties
puts "\n2. Testing component properties..."
if {[dict exists $components n]} {
    set n [dict get $components n]
    if {[string length $n] > 0} {
        puts "PASS: Modulus 'n' is not empty"
    } else {
        puts stderr "FAIL: Modulus 'n' is empty"
        incr ::errors
    }
}

if {[dict exists $components e]} {
    set e [dict get $components e]
    if {[string length $e] > 0} {
        puts "PASS: Public exponent 'e' is not empty"
    } else {
        puts stderr "FAIL: Public exponent 'e' is empty"
        incr ::errors
    }
}

if {[dict exists $components d]} {
    set d [dict get $components d]
    if {[string length $d] > 0} {
        puts "PASS: Private exponent 'd' is not empty"
    } else {
        puts stderr "FAIL: Private exponent 'd' is empty"
        incr ::errors
    }
}

# 3. Test with different key sizes
puts "\n3. Testing with different key sizes..."
set key_sizes {1024 2048 3072}
foreach size $key_sizes {
    set keys [tossl::key::generate -type rsa -bits $size]
    set priv [dict get $keys private]
    set components [tossl::rsa::components -key $priv]
    
    if {[dict exists $components n] && [dict exists $components e] && [dict exists $components d]} {
        puts "PASS: RSA $size-bit key components extracted"
    } else {
        puts stderr "FAIL: RSA $size-bit key components missing"
        incr ::errors
    }
}

# 4. Error handling tests
puts "\n4. Testing error handling..."
if {[catch {tossl::rsa::components} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}

if {[catch {tossl::rsa::components -key "invalid"} err]} {
    puts "PASS: invalid key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid key should have errored"
    incr ::errors
}

# Test with public key (should fail)
set pub [dict get $keys public]
if {[catch {tossl::rsa::components -key $pub} err]} {
    puts "PASS: public key (error as expected: $err)"
} else {
    puts stderr "FAIL: public key should have errored"
    incr ::errors
}

puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::rsa::components tests passed"
} 