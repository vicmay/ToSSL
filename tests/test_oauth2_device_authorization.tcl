# Test for ::tossl::oauth2::device_authorization
load ./libtossl.so

puts "Testing oauth2::device_authorization: missing required args..."
set rc [catch {tossl::oauth2::device_authorization} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::device_authorization -client_id foo} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing device_authorization_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::device_authorization -device_authorization_url bar} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_id did not error"
    exit 1
}
set rc [catch {tossl::oauth2::device_authorization -client_id foo -device_authorization_url bar -scope test -extra arg} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::oauth2::device_authorization argument tests passed"

puts "NOTE: Live device authorization flow requires a real OAuth2 server and is not tested here." 