# Test for ::tossl::oauth2::exchange_code
load ./libtossl.so

puts "Testing exchange_code: missing required args..."
set rc [catch {tossl::oauth2::exchange_code -client_id foo -client_secret bar -code baz -redirect_uri qux} result]
if {$rc == 0} {
    puts "FAIL: Missing token_url did not error"
    exit 1
}
puts "exchange_code missing arg: OK"

puts "Testing exchange_code: wrong arg..."
set rc [catch {tossl::oauth2::exchange_code -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "exchange_code wrong arg: OK"

# Note: A real HTTP test would require a live OAuth2 server. Here we only check argument validation and error handling. 