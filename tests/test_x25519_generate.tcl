# Test for ::tossl::x25519::generate
load ./libtossl.so

set errors 0

puts "Testing ::tossl::x25519::generate..."

# 1. Key generation
puts "\n1. Testing key generation..."
set priv1 [tossl::x25519::generate]
set priv2 [tossl::x25519::generate]
if {[string match *BEGIN* $priv1] && [string match *BEGIN* $priv2]} {
    puts "PASS: X25519 key generation (PEM format)"
} else {
    puts stderr "FAIL: X25519 key generation output"
    incr ::errors
}

# 2. Key uniqueness
puts "\n2. Testing key uniqueness..."
if {$priv1 ne $priv2} {
    puts "PASS: X25519 keys are unique"
} else {
    puts stderr "FAIL: X25519 keys are not unique"
    incr ::errors
}

# 3. Public key extraction
puts "\n3. Testing public key extraction..."
set pub1 [tossl::key::getpub -key $priv1]
set pub2 [tossl::key::getpub -key $priv2]
if {[string match *BEGIN* $pub1] && [string match *BEGIN* $pub2]} {
    puts "PASS: X25519 public key extraction (PEM format)"
} else {
    puts stderr "FAIL: X25519 public key extraction output"
    incr ::errors
}

# 4. Error handling
puts "\n4. Testing error handling..."
if {[catch {tossl::x25519::generate foo} err]} {
    puts "PASS: extra argument (error as expected: $err)"
} else {
    puts stderr "FAIL: extra argument should have errored"
    incr ::errors
}

puts "Total errors: $errors"
if {$errors > 0} {
    exit 1
} else {
    puts "All ::tossl::x25519::generate tests passed"
} 