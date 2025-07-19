# Test for ::tossl::x25519::derive
load ./libtossl.so

set errors 0

puts "Testing ::tossl::x25519::generate and ::tossl::x25519::derive..."

# 1. Key generation
puts "\n1. Testing key generation..."
set priv1 [tossl::x25519::generate]
set priv2 [tossl::x25519::generate]
if {[string match *BEGIN* $priv1] && [string match *BEGIN* $priv2]} {
    puts "PASS: X25519 key generation"
} else {
    puts stderr "FAIL: X25519 key generation output"
    incr ::errors
}

# 2. Key agreement (shared secret)
puts "\n2. Testing key agreement..."
set pub1 [tossl::key::getpub -key $priv1]
set pub2 [tossl::key::getpub -key $priv2]
set secret1 [tossl::x25519::derive $priv1 $pub2]
set secret2 [tossl::x25519::derive $priv2 $pub1]
if {$secret1 eq $secret2} {
    puts "PASS: X25519 key agreement (shared secret matches)"
} else {
    puts stderr "FAIL: X25519 key agreement mismatch"
    incr ::errors
}

# 3. Error handling
puts "\n3. Testing error handling..."
if {[catch {tossl::x25519::derive} err]} {
    puts "PASS: missing arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: missing arguments should have errored"
    incr ::errors
}
if {[catch {tossl::x25519::derive "notakey" $pub2} err]} {
    puts "PASS: invalid private key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid private key should have errored"
    incr ::errors
}
if {[catch {tossl::x25519::derive $priv1 "notapub"} err]} {
    puts "PASS: invalid public key (error as expected: $err)"
} else {
    puts stderr "FAIL: invalid public key should have errored"
    incr ::errors
}
if {[catch {tossl::x25519::derive $priv1} err]} {
    puts "PASS: too few arguments (error as expected: $err)"
} else {
    puts stderr "FAIL: too few arguments should have errored"
    incr ::errors
}

# 4. Edge case: derive with self
puts "\n4. Testing derive with self..."
set secret_self [tossl::x25519::derive $priv1 $pub1]
if {[string length $secret_self] == [string length $secret1]} {
    puts "PASS: derive with self (length matches)"
} else {
    puts stderr "FAIL: derive with self (length mismatch)"
    incr ::errors
}

puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::x25519::derive tests passed"
} 