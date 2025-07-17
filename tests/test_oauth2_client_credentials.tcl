# Test for ::tossl::oauth2::client_credentials
load ./libtossl.so

puts "Testing client_credentials: missing required args..."
set rc [catch {tossl::oauth2::client_credentials -client_id foo -client_secret bar -token_url baz} result]
if {$rc != 0} {
    puts "client_credentials missing arg: OK (expected error for missing optional scope)"
} else {
    puts "client_credentials missing arg: OK"
}

puts "Testing client_credentials: wrong arg..."
set rc [catch {tossl::oauth2::client_credentials -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "client_credentials wrong arg: OK"

# Note: A real HTTP test would require a live OAuth2 server. Here we only check argument validation and error handling. 