# Test for ::tossl::x509::parse
load ./libtossl.so

puts "Testing x509::parse: missing required args..."
set rc [catch {tossl::x509::parse} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "x509::parse missing args: OK"

puts "Testing x509::parse: invalid certificate data..."
set rc [catch {tossl::x509::parse "invalid_cert_data"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid certificate data did not error"
    exit 1
}
puts "x509::parse invalid data: OK"

puts "Testing x509::parse: basic functionality..."
# Generate test certificate
set keys [tossl::key::generate -type rsa -bits 2048]
set private_key [dict get $keys private]
set public_key [dict get $keys public]

# Create a self-signed certificate
set cert [tossl::x509::create -subject "CN=test.example.com" -issuer "CN=test.example.com" \
          -pubkey $public_key -privkey $private_key -days 365]

if {[string length $cert] == 0} {
    puts "FAIL: Certificate should not be empty"
    exit 1
}
puts "Test certificate created successfully"

# Parse the certificate
set parse_rc [catch {set parsed [tossl::x509::parse $cert]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse failed - $parse_err"
    exit 1
}

# Verify the parsed data structure
if {[llength $parsed] < 8} {
    puts "FAIL: Parsed data should have at least 8 elements (4 key-value pairs)"
    puts "Got: [llength $parsed] elements"
    exit 1
}

# Convert list to dict for easier access
set parsed_dict [dict create {*}$parsed]

# Check required fields
set required_fields {subject issuer serial not_before not_after}
foreach field $required_fields {
    if {![dict exists $parsed_dict $field]} {
        puts "FAIL: Missing required field: $field"
        exit 1
    }
    set value [dict get $parsed_dict $field]
    if {[string length $value] == 0} {
        puts "FAIL: Empty value for field: $field"
        exit 1
    }
    puts "Field $field: $value"
}

puts "x509::parse basic functionality: OK"

puts "Testing x509::parse: certificate with extensions..."
# Create certificate with SAN extension
set cert_with_san [tossl::x509::modify -cert $cert -add_extension "subjectAltName" "DNS:test.example.com,DNS:www.test.example.com" "false"]

set parse_rc [catch {set parsed_san [tossl::x509::parse $cert_with_san]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse with extensions failed - $parse_err"
    exit 1
}

set parsed_san_dict [dict create {*}$parsed_san]
foreach field $required_fields {
    if {![dict exists $parsed_san_dict $field]} {
        puts "FAIL: Missing required field in SAN cert: $field"
        exit 1
    }
}
puts "x509::parse with extensions: OK"

puts "Testing x509::parse: certificate chain..."
# Create CA certificate
set ca_keys [tossl::key::generate -type rsa -bits 2048]
set ca_private [dict get $ca_keys private]
set ca_public [dict get $ca_keys public]

set ca_cert [tossl::x509::create -subject "CN=Test CA" -issuer "CN=Test CA" \
             -pubkey $ca_public -privkey $ca_private -days 365]

# Create certificate signed by CA
set cert_keys [tossl::key::generate -type rsa -bits 2048]
set cert_public [dict get $cert_keys public]

set signed_cert [tossl::x509::create -subject "CN=Test Cert" -issuer "CN=Test CA" \
                 -pubkey $cert_public -privkey $ca_private -days 365]

# Parse both certificates
set parse_rc [catch {set parsed_ca [tossl::x509::parse $ca_cert]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse CA cert failed - $parse_err"
    exit 1
}

set parse_rc [catch {set parsed_signed [tossl::x509::parse $signed_cert]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse signed cert failed - $parse_err"
    exit 1
}

set parsed_ca_dict [dict create {*}$parsed_ca]
set parsed_signed_dict [dict create {*}$parsed_signed]

# Verify CA certificate is self-signed
if {[dict get $parsed_ca_dict subject] ne [dict get $parsed_ca_dict issuer]} {
    puts "FAIL: CA certificate should be self-signed"
    exit 1
}

# Verify signed certificate has different subject and issuer
if {[dict get $parsed_signed_dict subject] eq [dict get $parsed_signed_dict issuer]} {
    puts "FAIL: Signed certificate should not be self-signed"
    exit 1
}

# Verify issuer of signed cert matches CA subject
if {[dict get $parsed_signed_dict issuer] ne [dict get $parsed_ca_dict subject]} {
    puts "FAIL: Signed certificate issuer should match CA subject"
    exit 1
}

puts "x509::parse certificate chain: OK"

puts "Testing x509::parse: different key types..."
# Test with EC certificate
set ec_keys [tossl::key::generate -type ec -curve "prime256v1"]
set ec_private [dict get $ec_keys private]
set ec_public [dict get $ec_keys public]

set ec_cert [tossl::x509::create -subject "CN=EC Test" -issuer "CN=EC Test" \
             -pubkey $ec_public -privkey $ec_private -days 365]

set parse_rc [catch {set parsed_ec [tossl::x509::parse $ec_cert]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse EC cert failed - $parse_err"
    exit 1
}

set parsed_ec_dict [dict create {*}$parsed_ec]
foreach field $required_fields {
    if {![dict exists $parsed_ec_dict $field]} {
        puts "FAIL: Missing required field in EC cert: $field"
        exit 1
    }
}
puts "x509::parse EC certificate: OK"

puts "Testing x509::parse: edge cases..."
# Test with very short validity period
set short_cert [tossl::x509::create -subject "CN=Short Test" -issuer "CN=Short Test" \
                -pubkey $public_key -privkey $private_key -days 1]

set parse_rc [catch {set parsed_short [tossl::x509::parse $short_cert]} parse_err]
if {$parse_rc != 0} {
    puts "FAIL: x509::parse short validity cert failed - $parse_err"
    exit 1
}

set parsed_short_dict [dict create {*}$parsed_short]
if {![dict exists $parsed_short_dict not_before] || ![dict exists $parsed_short_dict not_after]} {
    puts "FAIL: Short validity certificate missing date fields"
    exit 1
}
puts "x509::parse short validity: OK"

puts "Testing x509::parse: security validation..."
# Test with corrupted certificate data
set corrupted_cert [string replace $cert 100 150 "CORRUPTED_DATA_HERE"]
set parse_rc [catch {tossl::x509::parse $corrupted_cert} parse_err]
if {$parse_rc == 0} {
    puts "FAIL: Corrupted certificate should not parse successfully"
    exit 1
}
puts "x509::parse corrupted data: OK"

# Test with empty certificate
set parse_rc [catch {tossl::x509::parse ""} parse_err]
if {$parse_rc == 0} {
    puts "FAIL: Empty certificate should not parse successfully"
    exit 1
}
puts "x509::parse empty data: OK"

puts "Testing x509::parse: performance..."
# Test parsing multiple certificates
set start_time [clock milliseconds]
for {set i 0} {$i < 10} {incr i} {
    set parse_rc [catch {tossl::x509::parse $cert} parse_err]
    if {$parse_rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $parse_err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "x509::parse performance (10 iterations): ${duration}ms"

puts "All ::tossl::x509::parse tests passed" 