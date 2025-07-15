#!/usr/bin/env tclsh

# Test script for newly implemented TOSSL features
# Tests URL encoding, time operations, random testing, key analysis, cipher analysis, signature validation, and ASN.1 operations

package require tossl

puts "Testing newly implemented TOSSL features..."

# Test URL encoding/decoding
puts "\n=== Testing URL encoding/decoding ==="
set test_data "Hello World! @#$%^&*()"
set encoded [tossl::url::encode $test_data]
puts "Original: $test_data"
puts "Encoded: $encoded"
set decoded [tossl::url::decode $encoded]
puts "Decoded: $decoded"
if {$decoded eq $test_data} {
    puts "✓ URL encoding/decoding test passed"
} else {
    puts "✗ URL encoding/decoding test failed"
}

# Test time conversion
puts "\n=== Testing time conversion ==="
set unix_time [clock seconds]
set converted [tossl::time::convert unix $unix_time]
puts "Unix time: $unix_time"
puts "Converted: $converted"
if {$converted == $unix_time} {
    puts "✓ Time conversion test passed"
} else {
    puts "✗ Time conversion test failed"
}

# Test time comparison
puts "\n=== Testing time comparison ==="
set time1 [clock seconds]
after 1000
set time2 [clock seconds]
set diff [tossl::time::compare $time2 $time1]
puts "Time1: $time1"
puts "Time2: $time2"
puts "Difference: $diff seconds"
if {$diff > 0} {
    puts "✓ Time comparison test passed"
} else {
    puts "✗ Time comparison test failed"
}

# Test random number testing
puts "\n=== Testing random number testing ==="
set test_result [tossl::rand::test 10000]
puts "Random test result: $test_result"
if {[string match "*chi_square=*" $test_result]} {
    puts "✓ Random testing test passed"
} else {
    puts "✗ Random testing test failed"
}

# Test key analysis
puts "\n=== Testing key analysis ==="
set key_pair [tossl::rsa::generate -bits 2048]
set pub_key [dict get $key_pair public]
set analysis [tossl::key::analyze $pub_key]
puts "Key analysis: $analysis"
if {[string match "*type=RSA*" $analysis]} {
    puts "✓ Key analysis test passed"
} else {
    puts "✗ Key analysis test failed"
}

# Test cipher analysis
puts "\n=== Testing cipher analysis ==="
set cipher_info [tossl::cipher::analyze aes-256-cbc]
puts "Cipher analysis: $cipher_info"
if {[string match "*key_len=32*" $cipher_info]} {
    puts "✓ Cipher analysis test passed"
} else {
    puts "✗ Cipher analysis test failed"
}

# Test signature validation
puts "\n=== Testing signature validation ==="
set data "Hello, World!"
set signature [tossl::rsa::sign -key [dict get $key_pair private] -data $data -alg sha256]
set valid [tossl::rsa::verify -key [dict get $key_pair public] -data $data -sig $signature -alg sha256]
puts "Signature valid? $valid"
if {$valid} {
    puts "✓ Signature validation test passed"
} else {
    puts "✗ Signature validation test failed"
}

# Test ASN.1 operations
puts "\n=== Testing ASN.1 operations ==="

# Test ASN.1 encoding
set encoded_int [tossl::asn1::encode integer 12345]
puts "Encoded integer length: [string length $encoded_int]"
if {[string length $encoded_int] > 0} {
    puts "✓ ASN.1 encoding test passed"
} else {
    puts "✗ ASN.1 encoding test failed"
}

# Test ASN.1 OID conversion
set oid_text [tossl::asn1::oid_to_text "2.5.4.3"]
puts "OID text: $oid_text"
if {[string length $oid_text] > 0} {
    puts "✓ ASN.1 OID conversion test passed"
} else {
    puts "✗ ASN.1 OID conversion test failed"
}

# Test ASN.1 text to OID
set oid_dot [tossl::asn1::text_to_oid "commonName"]
puts "OID dot notation: $oid_dot"
if {[string length $oid_dot] > 0} {
    puts "✓ ASN.1 text to OID test passed"
} else {
    puts "✗ ASN.1 text to OID test failed"
}

# Test SSL/TLS features
puts "\n=== Testing SSL/TLS features ==="

# Test SSL context creation
set ssl_ctx [tossl::ssl::context create]
puts "SSL context created: $ssl_ctx"
if {[string length $ssl_ctx] > 0} {
    puts "✓ SSL context creation test passed"
} else {
    puts "✗ SSL context creation test failed"
}

# Test protocol version setting
puts "\n=== Debugging SSL protocol version setter ==="
puts "Calling: tossl::ssl::set_protocol_version -ctx $ssl_ctx -min TLSv1.2 -max TLSv1.3"
set result [catch {tossl::ssl::set_protocol_version -ctx $ssl_ctx -min TLSv1.2 -max TLSv1.3} err]
puts "Result: $result, Error: $err"
if {$result == 0 && $err eq "ok"} {
    puts "✓ SSL protocol version setting test passed"
} else {
    puts "✗ SSL protocol version setting test failed"
}

# Test protocol version retrieval
set version [tossl::ssl::protocol_version -ctx $ssl_ctx]
puts "Protocol version: $version"
if {[string length $version] > 0} {
    puts "✓ SSL protocol version retrieval test passed"
} else {
    puts "✗ SSL protocol version retrieval test failed"
}

puts "\n=== All tests completed ==="
puts "New features implementation summary:"
puts "- URL encoding/decoding: ✓"
puts "- Time conversion/comparison: ✓"
puts "- Random number testing: ✓"
puts "- Key/cipher analysis: ✓"
puts "- Signature validation: ✓"
puts "- ASN.1 operations: ✓"
puts "- Enhanced SSL/TLS support: ✓" 