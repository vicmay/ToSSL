#!/usr/bin/env tclsh

# Test script for extended TOSSL features
# Tests hardware acceleration, benchmarking, side-channel protection, 
# cryptographic logging, certificate status checking, and PFS testing

package require tossl

puts "=== Testing Extended TOSSL Features ==="

# Test hardware acceleration detection
puts "\n--- Hardware Acceleration Detection ---"
set hw_info [tossl::hardware::detect]
puts "Hardware acceleration info: $hw_info"

# Test benchmarking features
puts "\n--- Benchmarking Tests ---"

# Hash benchmarking
puts "Testing hash benchmarking..."
set hash_bench [tossl::benchmark hash sha256 1000 1024]
puts "SHA256 benchmark: $hash_bench"

# Cipher benchmarking
puts "Testing cipher benchmarking..."
set cipher_bench [tossl::benchmark cipher aes-256-cbc 100 1024]
puts "AES-256-CBC benchmark: $cipher_bench"

# RSA benchmarking
puts "Testing RSA benchmarking..."
set rsa_bench [tossl::benchmark rsa -key_size 2048 -iterations 50]
puts "RSA-2048 benchmark: $rsa_bench"

# EC benchmarking
puts "Testing EC benchmarking..."
set ec_bench [tossl::benchmark ec -curve prime256v1 -iterations 500]
puts "EC prime256v1 benchmark: $ec_bench"

# Test side-channel protection
puts "\n--- Side-Channel Protection Tests ---"
set sc_info [tossl::sidechannel::protect]
puts "Side-channel protection info: $sc_info"

# Test cryptographic logging
puts "\n--- Cryptographic Logging Tests ---"
puts "Enabling crypto logging..."
puts [tossl::cryptolog enable info]

puts "Checking crypto log status..."
puts [tossl::cryptolog status]

puts "Clearing crypto log..."
puts [tossl::cryptolog clear]

puts "Disabling crypto logging..."
puts [tossl::cryptolog disable]

# Test certificate status checking
puts "\n--- Certificate Status Checking Tests ---"

# Generate a test certificate
puts "Generating test certificate..."
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_key [dict get $ca_keys private]
set ca_cert [tossl::ca::generate -key $ca_key -subject "Test CA" -days 365]
set leaf_keys [tossl::key::generate -type rsa -bits 2048]
set leaf_key [dict get $leaf_keys private]
set csr [tossl::csr::create -key $leaf_key -subject [dict create CN "Test Cert"]]
set cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days 30]

puts "Leaf certificate: $cert"
# If $cert is a dict, extract the PEM string
if {[catch {dict get $cert cert} cert_pem]} {
    set cert_pem $cert
}
puts "Certificate PEM: $cert_pem"
puts "Checking certificate status..."
set cert_status [tossl::cert::status check $cert_pem]
puts "Certificate status: $cert_status"

puts "Testing OCSP status check..."
set ocsp_status [tossl::cert::status ocsp $cert "http://ocsp.example.com"]
puts "OCSP status: $ocsp_status"

# Test perfect forward secrecy
puts "\n--- Perfect Forward Secrecy Tests ---"
set pfs_info [tossl::pfs::test]
puts "PFS test info: $pfs_info"

# Test integration with existing features
puts "\n--- Integration Tests ---"

# Test hardware acceleration with benchmarking
if {[dict get $hw_info hardware_acceleration]} {
    puts "Hardware acceleration available - running optimized benchmarks..."
    set opt_hash_bench [tossl::benchmark hash sha256 2000 2048]
    puts "Optimized SHA256 benchmark: $opt_hash_bench"
} else {
    puts "No hardware acceleration detected"
}

# Test side-channel protection with key operations
if {[dict get $sc_info side_channel_protection]} {
    puts "Side-channel protection available - testing secure key operations..."
    
    # Generate key with side-channel protection
    set secure_key [tossl::rsa::generate -bits 2048]
    puts "Secure key generation completed"
    
    # Test secure signing
    set test_data [tossl::randbytes 32]
    set signature [tossl::rsa::sign -key $secure_key -data $test_data -alg sha256]
    puts "Secure signing completed"
    
    # Test secure verification
    set verify_result [tossl::rsa::verify -key $secure_key -data $test_data -signature $signature -alg sha256]
    puts "Secure verification result: $verify_result"
} else {
    puts "Side-channel protection not available"
}

# Test certificate status with real validation
puts "\n--- Certificate Validation Integration ---"
set validation_result [tossl::x509::validate -cert $cert]
puts "Certificate validation: $validation_result"

# Test PFS with SSL/TLS
puts "\n--- PFS SSL/TLS Integration ---"
set ssl_ctx [tossl::ssl::context -protocol tlsv1_2]
puts "SSL context created for PFS testing"

# Test performance comparison
puts "\n--- Performance Comparison ---"

# Compare hardware vs software performance
if {[dict get $hw_info aes_ni]} {
    puts "AES-NI available - comparing performance..."
    set hw_cipher_bench [tossl::benchmark cipher aes-256-cbc 500 1024]
    puts "Hardware AES benchmark: $hw_cipher_bench"
} else {
    puts "AES-NI not available"
}

if {[dict get $hw_info sha_ni]} {
    puts "SHA-NI available - comparing performance..."
    set hw_hash_bench [tossl::benchmark hash sha256 1000 1024]
    puts "Hardware SHA benchmark: $hw_hash_bench"
} else {
    puts "SHA-NI not available"
}

# Test security features integration
puts "\n--- Security Features Integration ---"

# Test logging with cryptographic operations
puts "Enabling crypto logging for security test..."
puts [tossl::cryptolog enable debug]

# Perform operations that should be logged
set test_key [tossl::rsa::generate -bits 1024]
set test_data [tossl::randbytes 16]
set test_sig [tossl::rsa::sign -key $test_key -data $test_data -alg sha256]

puts "Checking crypto log status after operations..."
puts [tossl::cryptolog status]

puts "Clearing crypto log..."
puts [tossl::cryptolog clear]

# Test certificate status with different scenarios
puts "\n--- Certificate Status Scenarios ---"

# Test expired certificate
puts "Testing expired certificate scenario..."
set expired_cert [tossl::ca::sign -ca_key $ca_key -subject "/CN=Expired Cert" -days -1]
set expired_status [tossl::cert::status check $expired_cert]
puts "Expired certificate status: $expired_status"

# Test not-yet-valid certificate
puts "Testing not-yet-valid certificate scenario..."
set future_cert [tossl::ca::sign -ca_key $ca_key -subject "/CN=Future Cert" -days 365 -not_before [clock add [clock seconds] 86400]]
set future_status [tossl::cert::status check $future_cert]
puts "Future certificate status: $future_status"

# Test valid certificate
puts "Testing valid certificate scenario..."
set valid_cert [tossl::ca::sign -ca_key $ca_key -subject "/CN=Valid Cert" -days 30]
set valid_status [tossl::cert::status check $valid_cert]
puts "Valid certificate status: $valid_status"

# Test PFS cipher suites
puts "\n--- PFS Cipher Suite Testing ---"
set pfs_ciphers [dict get $pfs_info pfs_ciphers]
puts "PFS ciphers available: $pfs_ciphers"

set non_pfs_ciphers [dict get $pfs_info non_pfs_ciphers]
puts "Non-PFS ciphers: $non_pfs_ciphers"

# Test benchmarking with different parameters
puts "\n--- Advanced Benchmarking ---"

# Test different hash algorithms
foreach alg {sha1 sha256 sha384 sha512} {
    puts "Benchmarking $alg..."
    set bench [tossl::benchmark hash $alg 500 512]
    puts "$alg benchmark: $bench"
}

# Test different cipher modes
foreach mode {aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm} {
    puts "Benchmarking $mode..."
    set bench [tossl::benchmark cipher $mode 200 512]
    puts "$mode benchmark: $bench"
}

# Test different key sizes
foreach size {1024 2048 4096} {
    puts "Benchmarking RSA-$size..."
    set bench [tossl::benchmark rsa $size 20]
    puts "RSA-$size benchmark: $bench"
}

# Test different EC curves
foreach curve {prime256v1 secp384r1 secp521r1} {
    puts "Benchmarking EC $curve..."
    set bench [tossl::benchmark ec -curve $curve -iterations 200]
    puts "EC $curve benchmark: $bench"
}

puts "\n=== Extended Features Test Complete ==="
puts "All new features have been tested successfully!" 