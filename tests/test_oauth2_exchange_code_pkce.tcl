# Test for ::tossl::oauth2::exchange_code_pkce
load ./libtossl.so

puts "Testing oauth2::exchange_code_pkce: missing required args..."
set rc [catch {tossl::oauth2::exchange_code_pkce} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing code_verifier did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -code_verifier bar} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -code baz} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -redirect_uri qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -token_url quux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo -code_verifier bar -code baz -redirect_uri qux -token_url quux -extra arg} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::oauth2::exchange_code_pkce argument tests passed"

puts "Testing oauth2::exchange_code_pkce: missing required parameters..."
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo -code_verifier bar -code baz -redirect_uri qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo -code_verifier bar -code baz -token_url quux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing redirect_uri did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo -code_verifier bar -redirect_uri qux -token_url quux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing code did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -client_id foo -code baz -redirect_uri qux -token_url quux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing code_verifier did not error"
    exit 1
}
set rc [catch {tossl::oauth2::exchange_code_pkce -code_verifier bar -code baz -redirect_uri qux -token_url quux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
puts "All ::tossl::oauth2::exchange_code_pkce parameter validation tests passed"

puts "Testing oauth2::exchange_code_pkce: PKCE flow integration..."
set code_verifier [tossl::oauth2::generate_code_verifier -length 64]
set code_challenge [tossl::oauth2::create_code_challenge -verifier $code_verifier]
puts "Generated code_verifier: $code_verifier"
puts "Generated code_challenge: $code_challenge"
puts "PKCE parameters generated successfully"

puts "NOTE: Live PKCE code exchange requires a real OAuth2 server and is not tested here."
puts "The command is designed to exchange authorization codes with PKCE code verifiers for access tokens."
puts "All ::tossl::oauth2::exchange_code_pkce tests passed" 