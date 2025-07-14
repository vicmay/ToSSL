#!/usr/bin/env tclsh

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing new TOSSL features..."
puts "=============================="

# Test new hash algorithms
puts "\n1. Testing new hash algorithms:"
set test_data "Hello, World!"
puts "Test data: $test_data"

foreach alg {sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 ripemd160 whirlpool} {
    if {[catch {
        set hash [tossl::digest -alg $alg $test_data]
        puts "  $alg: $hash"
    } err]} {
        puts "  $alg: ERROR - $err"
    }
}

# Test RSA with different padding
puts "\n2. Testing RSA with different padding schemes:"
if {[catch {
    set keys [tossl::key::generate -type rsa -bits 2048]
    set privkey [dict get $keys private]
    set pubkey [dict get $keys public]
    
    set test_msg "Test message for RSA signing"
    
    # Test PKCS1 padding
    set sig1 [tossl::rsa::sign -privkey $privkey -alg sha256 -padding pkcs1 $test_msg]
    puts "  PKCS1 signature length: [string length $sig1] bytes"
    
    # Test PSS padding  
    set sig2 [tossl::rsa::sign -privkey $privkey -alg sha256 -padding pss $test_msg]
    puts "  PSS signature length: [string length $sig2] bytes"
    
    puts "  RSA padding tests: PASSED"
} err]} {
    puts "  RSA padding tests: ERROR - $err"
}

# Test RSA key validation
puts "\n3. Testing RSA key validation:"
if {[catch {
    set valid [tossl::rsa::validate -key $privkey]
    puts "  Key validation: [expr {$valid ? "VALID" : "INVALID"}]"
} err]} {
    puts "  Key validation: ERROR - $err"
}

# Test RSA components extraction
puts "\n4. Testing RSA components extraction:"
if {[catch {
    set components [tossl::rsa::components -key $privkey]
    puts "  Components extracted: [dict keys $components]"
    puts "  n length: [string length [dict get $components n]] chars"
    puts "  e length: [string length [dict get $components e]] chars"
} err]} {
    puts "  Components extraction: ERROR - $err"
}

puts "\nTest completed!" 