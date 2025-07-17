# Test for ::tossl::oauth2::generate_code_verifier
load ./libtossl.so

puts "Testing PKCE code verifier: normal case..."
set verifier [tossl::oauth2::generate_code_verifier -length 64]
puts "Verifier: $verifier"
if {[string length $verifier] < 43} {
    puts "FAIL: Code verifier too short"
    exit 1
}
if {[string length $verifier] > 128} {
    puts "FAIL: Code verifier too long"
    exit 1
}
puts "PKCE code verifier normal: OK"

puts "Testing PKCE code verifier: minimum length..."
set verifier [tossl::oauth2::generate_code_verifier -length 43]
if {[string length $verifier] != 43} {
    puts "FAIL: Code verifier not min length"
    exit 1
}
puts "PKCE code verifier min length: OK"

puts "Testing PKCE code verifier: maximum length..."
set verifier [tossl::oauth2::generate_code_verifier -length 128]
if {[string length $verifier] != 128} {
    puts "FAIL: Code verifier not max length"
    exit 1
}
puts "PKCE code verifier max length: OK"

puts "Testing PKCE code verifier: error on too short..."
set rc [catch {tossl::oauth2::generate_code_verifier -length 10} result]
if {$rc == 0} {
    puts "FAIL: Too short did not error"
    exit 1
}
puts "PKCE code verifier too short: OK"

puts "Testing PKCE code verifier: error on too long..."
set rc [catch {tossl::oauth2::generate_code_verifier -length 200} result]
if {$rc == 0} {
    puts "FAIL: Too long did not error"
    exit 1
}
puts "PKCE code verifier too long: OK"

puts "Testing PKCE code verifier: error on wrong arg..."
set rc [catch {tossl::oauth2::generate_code_verifier -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "PKCE code verifier wrong arg: OK" 