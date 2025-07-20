# Test for ::tossl::ocsp::create_request
load ./libtossl.so

puts "Testing ocsp::create_request: missing required args..."
set rc [catch {tossl::ocsp::create_request} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::ocsp::create_request "cert"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing issuer did not error"
    exit 1
}
puts "All ::tossl::ocsp::create_request argument tests passed"

puts "Testing ocsp::create_request: invalid certificate data..."
set rc [catch {tossl::ocsp::create_request "invalid_cert" "invalid_issuer"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid certificates did not error"
    exit 1
}
puts "ocsp::create_request invalid certificates: OK"

puts "Testing ocsp::create_request: basic functionality..."
# Generate test CA and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private_key [dict get $ca_keypair private]
set ca_public_key [dict get $ca_keypair public]

# Create CA certificate
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public_key -privkey $ca_private_key -days 3650]

# Generate server key pair
set server_keypair [tossl::key::generate -type rsa -bits 2048]
set server_private_key [dict get $server_keypair private]
set server_public_key [dict get $server_keypair public]

# Create server certificate signed by CA
set server_cert [tossl::x509::create -subject "CN=test.example.com" -issuer "CN=Test CA" -pubkey $server_public_key -privkey $ca_private_key -days 365]

# Create OCSP request
set ocsp_request [tossl::ocsp::create_request $server_cert $ca_cert]
if {[string length $ocsp_request] == 0} {
    puts "FAIL: OCSP request should not be empty"
    exit 1
}
puts "OCSP request created successfully: [string length $ocsp_request] bytes"

# Test that the request is valid binary data (check for non-printable characters)
set has_binary 0
for {set i 0} {$i < [string length $ocsp_request]} {incr i} {
    set char [string index $ocsp_request $i]
    if {[string is print $char] == 0} {
        set has_binary 1
        break
    }
}
if {$has_binary} {
    puts "OCSP request is valid binary data: OK"
} else {
    puts "FAIL: OCSP request should be binary data"
    exit 1
}

puts "Testing ocsp::create_request: mismatched certificate and issuer..."
# Create a different CA certificate
set ca2_keypair [tossl::key::generate -type rsa -bits 2048]
set ca2_private_key [dict get $ca2_keypair private]
set ca2_public_key [dict get $ca2_keypair public]
set ca2_cert [tossl::x509::create -subject "CN=Different CA" -issuer "CN=Different CA" -pubkey $ca2_public_key -privkey $ca2_private_key -days 3650]

# This should still work as OCSP requests can be created for any certificate/issuer pair
set ocsp_request2 [tossl::ocsp::create_request $server_cert $ca2_cert]
if {[string length $ocsp_request2] == 0} {
    puts "FAIL: OCSP request with different issuer should not be empty"
    exit 1
}
puts "OCSP request with different issuer created successfully: OK"

puts "Testing ocsp::create_request: self-signed certificate..."
# Create a self-signed certificate
set self_signed_cert [tossl::x509::create -subject "CN=self.example.com" -issuer "CN=self.example.com" -pubkey $server_public_key -privkey $server_private_key -days 365]

# Create OCSP request for self-signed certificate (issuer is the same as certificate)
set ocsp_request3 [tossl::ocsp::create_request $self_signed_cert $self_signed_cert]
if {[string length $ocsp_request3] == 0} {
    puts "FAIL: OCSP request for self-signed cert should not be empty"
    exit 1
}
puts "OCSP request for self-signed certificate created successfully: OK"

puts "All ::tossl::ocsp::create_request tests passed" 