# Test for ::tossl::oauth2::validate_introspection
load ./libtossl.so

puts "Testing validate_introspection: valid case..."
set result [tossl::oauth2::validate_introspection -active 1 -scope "openid profile" -audience "client1" -issuer "https://issuer.example.com"]
if {$result ne "valid"} {
    puts "FAIL: Expected valid, got $result"
    exit 1
}
puts "validate_introspection valid: OK"

puts "Testing validate_introspection: inactive token..."
set result [tossl::oauth2::validate_introspection -active 0 -scope "openid profile" -audience "client1" -issuer "https://issuer.example.com"]
if {$result ne "invalid"} {
    puts "FAIL: Expected invalid for inactive, got $result"
    exit 1
}
puts "validate_introspection inactive: OK"

puts "Testing validate_introspection: missing audience..."
set rc [catch {tossl::oauth2::validate_introspection -active 1 -scope "openid profile" -issuer "https://issuer.example.com"} result]
if {$rc == 0} {
    puts "FAIL: Missing audience did not error"
    exit 1
}
puts "validate_introspection missing audience: OK"

puts "Testing validate_introspection: missing issuer..."
set rc [catch {tossl::oauth2::validate_introspection -active 1 -scope "openid profile" -audience "client1"} result]
if {$rc == 0} {
    puts "FAIL: Missing issuer did not error"
    exit 1
}
puts "validate_introspection missing issuer: OK"

puts "Testing validate_introspection: wrong arg..."
set rc [catch {tossl::oauth2::validate_introspection -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "validate_introspection wrong arg: OK" 