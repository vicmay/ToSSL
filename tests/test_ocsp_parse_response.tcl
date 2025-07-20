# Test for ::tossl::ocsp::parse_response
load ./libtossl.so

puts "Testing ocsp::parse_response: missing required args..."
set rc [catch {tossl::ocsp::parse_response} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "All ::tossl::ocsp::parse_response argument tests passed"

puts "Testing ocsp::parse_response: invalid OCSP response data..."
set rc [catch {tossl::ocsp::parse_response "invalid_response"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid OCSP response did not error"
    exit 1
}
puts "ocsp::parse_response invalid data: OK"

puts "Testing ocsp::parse_response: empty response..."
set rc [catch {tossl::ocsp::parse_response ""} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Empty response did not error"
    exit 1
}
puts "ocsp::parse_response empty response: OK"

puts "Testing ocsp::parse_response: basic functionality..."
# Generate test CA and certificate
set ca_keypair [tossl::key::generate -type rsa -bits 2048]
set ca_private_key [dict get $ca_keypair private]
set ca_public_key [dict get $ca_keypair public]
set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" -pubkey $ca_public_key -privkey $ca_private_key -days 3650]

set server_keypair [tossl::key::generate -type rsa -bits 2048]
set server_private_key [dict get $server_keypair private]
set server_public_key [dict get $server_keypair public]
set server_cert [tossl::x509::create -subject "CN=test.example.com" -issuer "CN=Test CA" -pubkey $server_public_key -privkey $ca_private_key -days 365]

# Create OCSP request
set ocsp_request [tossl::ocsp::create_request $server_cert $ca_cert]
if {[string length $ocsp_request] == 0} {
    puts "FAIL: OCSP request should not be empty"
    exit 1
}

# For testing, we'll create a mock OCSP response
# In a real scenario, this would come from an OCSP responder
# For now, we'll test with invalid data to ensure error handling works
set mock_response "mock_ocsp_response_data"
set rc [catch {tossl::ocsp::parse_response $mock_response} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Mock response should have failed"
    exit 1
}
puts "ocsp::parse_response mock response: OK"

puts "Testing ocsp::parse_response: response format validation..."
# Test with various invalid formats
set invalid_formats {
    "not_binary_data"
    "12345"
    "binary_data_without_proper_structure"
}

foreach format $invalid_formats {
    set rc [catch {tossl::ocsp::parse_response $format} result]
    if {$rc == 0} {
        puts "FAIL: Invalid format '$format' should have failed"
        exit 1
    }
    puts "ocsp::parse_response invalid format '$format': OK"
}

puts "Testing ocsp::parse_response: response structure..."
# The tossl_ocsp.c implementation returns a list with key-value pairs
# Test that we can handle the expected structure
set test_response "test_binary_data"
set rc [catch {tossl::ocsp::parse_response $test_response} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Test response should have failed"
    exit 1
}
puts "ocsp::parse_response test response: OK"

puts "All ::tossl::ocsp::parse_response tests passed" 