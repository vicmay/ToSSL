# Test for ::tossl::oauth2::create_code_challenge
load ./libtossl.so

puts "Testing PKCE code challenge: normal case..."
set verifier [tossl::oauth2::generate_code_verifier -length 64]
set challenge [tossl::oauth2::create_code_challenge -verifier $verifier]
puts "Verifier: $verifier"
puts "Challenge: $challenge"
if {[string length $challenge] < 43} {
    puts "FAIL: Code challenge too short"
    exit 1
}
puts "PKCE code challenge normal: OK"

puts "Testing PKCE code challenge: minimum length verifier..."
set verifier [tossl::oauth2::generate_code_verifier -length 43]
set challenge [tossl::oauth2::create_code_challenge -verifier $verifier]
if {[string length $challenge] < 43} {
    puts "FAIL: Code challenge too short for min verifier"
    exit 1
}
puts "PKCE code challenge min length: OK"

puts "Testing PKCE code challenge: maximum length verifier..."
set verifier [tossl::oauth2::generate_code_verifier -length 128]
set challenge [tossl::oauth2::create_code_challenge -verifier $verifier]
if {[string length $challenge] < 43} {
    puts "FAIL: Code challenge too short for max verifier"
    exit 1
}
puts "PKCE code challenge max length: OK"

puts "Testing PKCE code challenge: error on missing arg..."
set rc [catch {tossl::oauth2::create_code_challenge} result]
if {$rc == 0} {
    puts "FAIL: Missing arg did not error"
    exit 1
}
puts "PKCE code challenge missing arg: OK"

puts "Testing PKCE code challenge: error on wrong arg name..."
set rc [catch {tossl::oauth2::create_code_challenge -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg name did not error"
    exit 1
}
puts "PKCE code challenge wrong arg name: OK" 