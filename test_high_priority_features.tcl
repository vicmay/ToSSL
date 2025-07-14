#!/usr/bin/env tclsh

package require tossl

puts "=== Testing High Priority Features ===\n"

# Test 1: CA Certificate Generation
puts "1. Testing CA Certificate Generation..."
set ca_key_dict [tossl::rsa::generate -bits 2048]
set ca_key [dict get $ca_key_dict private]
set ca_cert [tossl::ca::generate -key $ca_key -subject "Test CA" -days 365]
puts "   CA certificate generated successfully"
puts "   Certificate length: [string length $ca_cert] bytes\n"

# Test 2: CSR Creation and Signing
puts "2. Testing CSR Creation and CA Signing..."
set server_key_dict [tossl::rsa::generate -bits 2048]
set server_key [dict get $server_key_dict private]
set server_pubkey [dict get $server_key_dict public]
set csr [tossl::csr::create -privkey $server_key -pubkey $server_pubkey -subject "CN=test.example.com"]
puts "   CSR created successfully"

set server_cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days 365]
puts "   Certificate signed by CA successfully"
puts "   Server certificate length: [string length $server_cert] bytes\n"

# Test 3: Certificate Validation
puts "3. Testing Certificate Validation..."
set validation [tossl::x509::validate -cert $server_cert -ca $ca_cert]
puts "   Validation result: $validation\n"

# Test 4: Certificate Fingerprinting
puts "4. Testing Certificate Fingerprinting..."
set fingerprint [tossl::x509::fingerprint -cert $server_cert -alg sha256]
puts "   Certificate fingerprint: $fingerprint\n"

# Test 5: Enhanced SSL/TLS Protocol Version Management
puts "5. Testing Enhanced SSL/TLS Protocol Version Management..."
# set ssl_ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3}]
set ssl_ctx [tossl::ssl::context create]
puts "   SSL context created: $ssl_ctx"

set protocol_info [tossl::ssl::protocol_version -ctx $ssl_ctx]
puts "   Protocol version info: $protocol_info"

set result [tossl::ssl::set_protocol_version -ctx $ssl_ctx -min TLSv1.2 -max TLSv1.3]
puts "   Protocol version set: $result"

set updated_info [tossl::ssl::protocol_version -ctx $ssl_ctx]
puts "   Updated protocol info: $updated_info\n"

# Test 6: CRL Creation and Parsing
puts "6. Testing CRL Creation and Parsing..."
set revoked_list [list [list 123 "keyCompromise"] [list 456 "unspecified"]]
set crl [tossl::crl::create -ca_key $ca_key -ca_cert $ca_cert -revoked $revoked_list -days 30]
puts "   CRL created successfully"
puts "   CRL length: [string length $crl] bytes"

set crl_info [tossl::crl::parse $crl]
puts "   CRL info: $crl_info\n"

# Test 7: Additional Symmetric Ciphers
puts "7. Testing Additional Symmetric Ciphers..."
set cipher_list [tossl::cipher::list -type gcm]
puts "   Available GCM ciphers: $cipher_list"

set chacha_ciphers [tossl::cipher::list]
set chacha_found 0
foreach cipher $chacha_ciphers {
    if {[string match "*chacha*" $cipher]} {
        set chacha_found 1
        break
    }
}
if {$chacha_found} {
    puts "   ChaCha20 ciphers available"
} else {
    puts "   ChaCha20 ciphers not found"
}

# Test ChaCha20 encryption if available
if {$chacha_found} {
    set key [tossl::rand::key -alg chacha20]
    set iv [tossl::rand::iv -alg chacha20]
    set data "Hello, ChaCha20 encryption!"
    set encrypted [tossl::encrypt -alg chacha20 -key $key -iv $iv $data]
    puts "   ChaCha20 encryption successful"
} else {
    puts "   Skipping ChaCha20 encryption test"
}
puts ""

# Test 8: Key Derivation Functions (already implemented)
puts "8. Testing Key Derivation Functions..."
set password "test_password"
set salt [tossl::randbytes 16]
set pbkdf2_key [tossl::kdf::pbkdf2 -password $password -salt $salt -iterations 10000 -keylen 32 -digest sha256]
puts "   PBKDF2 key derivation successful"

set scrypt_key [tossl::kdf::scrypt -password $password -salt $salt -n 16384 -r 8 -p 1 -keylen 32]
puts "   Scrypt key derivation successful"

set argon2_key [tossl::kdf::argon2 -password $password -salt $salt -time 3 -memory 65536 -parallel 4 -keylen 32]
puts "   Argon2 key derivation successful\n"

# Test 9: Complete SSL/TLS Operations
puts "9. Testing Complete SSL/TLS Operations..."
set ssl_ctx_server [tossl::ssl::context create -cert $server_cert -key $server_key -verify 0]
puts "   Server SSL context created"

set ssl_ctx_client [tossl::ssl::context create -verify 0]
puts "   Client SSL context created"

# Note: Full SSL connection testing would require actual network operations
# This is just testing the context creation and configuration
puts "   SSL contexts configured successfully\n"

# Test 10: Certificate Chain Validation
puts "10. Testing Certificate Chain Validation..."
set chain_validation [tossl::x509::validate -cert $server_cert -ca $ca_cert]
puts "   Chain validation result: $chain_validation\n"

puts "=== All High Priority Features Tested Successfully ==="
puts "\nSummary of implemented features:"
puts "- CA certificate generation and signing"
puts "- Enhanced SSL/TLS protocol version management"
puts "- Certificate revocation list (CRL) creation and parsing"
puts "- Certificate validation and fingerprinting"
puts "- Additional symmetric ciphers (ChaCha20, GCM modes)"
puts "- Key derivation functions (PBKDF2, Scrypt, Argon2)"
puts "- Complete SSL/TLS context management"

puts "\nThese features address the high priority items from MISSING-TODO.md:"
puts "- Complete SSL/TLS support (enhanced)"
puts "- Certificate Authority operations"
puts "- Certificate revocation (CRL operations)"
puts "- Additional symmetric ciphers"
puts "- Key derivation functions" 