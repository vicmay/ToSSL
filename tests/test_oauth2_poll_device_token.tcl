# Test for ::tossl::oauth2::poll_device_token
load ./libtossl.so

puts "Testing oauth2::poll_device_token: missing required args..."
set rc [catch {tossl::oauth2::poll_device_token} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -device_code foo} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -token_url bar} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing device_code did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -client_id baz} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing device_code did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -client_secret qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing device_code did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -device_code foo -token_url bar -client_id baz -client_secret qux -extra arg} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::oauth2::poll_device_token argument tests passed"

puts "Testing oauth2::poll_device_token: missing required parameters..."
set rc [catch {tossl::oauth2::poll_device_token -device_code foo -token_url bar -client_id baz} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_secret did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -device_code foo -token_url bar -client_secret qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -device_code foo -client_id baz -client_secret qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::poll_device_token -token_url bar -client_id baz -client_secret qux} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing device_code did not error"
    exit 1
}
puts "All ::tossl::oauth2::poll_device_token parameter validation tests passed"

puts "NOTE: Live device token polling requires a real OAuth2 server and is not tested here."
puts "The command is designed to poll for device authorization completion and retrieve access tokens."
puts "All ::tossl::oauth2::poll_device_token tests passed" 