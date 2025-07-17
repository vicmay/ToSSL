# Test for ::tossl::oauth2::refresh_token
load ./libtossl.so

puts "Testing refresh_token: missing required args..."
set rc [catch {tossl::oauth2::refresh_token} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::refresh_token -client_id foo} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_secret/refresh_token/token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::refresh_token -client_id foo -client_secret bar} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing refresh_token/token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::refresh_token -client_id foo -client_secret bar -refresh_token baz} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::refresh_token -client_id foo -client_secret bar -refresh_token baz -token_url qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "WARN: No real server, expected error or HTTP failure"
} else {
    puts "refresh_token with all args: OK (error expected if no server)"
}
puts "refresh_token missing/invalid args: OK" 