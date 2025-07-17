# Test for ::tossl::oauth2::is_token_expired
load ./libtossl.so

puts "Testing is_token_expired: expired token (expires_at in past)..."
set now [clock seconds]
puts "Current time: $now"
set expired_at [expr {$now - 10}]
puts "expires_at: $expired_at"
set expired_json "{\"expires_in\":3600,\"expires_at\":$expired_at}"
set rc [catch {tossl::oauth2::is_token_expired -token $expired_json} result]
puts "Result: $result"
if {$rc != 0} {
    puts "FAIL: Command errored: $result"
    exit 1
}
if {$result != 1} {
    puts "FAIL: Expired token not detected"
    exit 1
}
puts "is_token_expired expired: OK"

puts "Testing is_token_expired: valid token (expires_at in future)..."
set valid_at [expr {$now + 3600}]
puts "expires_at: $valid_at"
set valid_json "{\"expires_in\":3600,\"expires_at\":$valid_at}"
set rc [catch {tossl::oauth2::is_token_expired -token $valid_json} result]
puts "Result: $result"
if {$rc != 0} {
    puts "FAIL: Command errored: $result"
    exit 1
}
if {$result != 0} {
    puts "FAIL: Valid token detected as expired"
    exit 1
}
puts "is_token_expired valid: OK"

puts "Testing is_token_expired: missing expires_at (should not be expired)..."
set no_expiry_json "{\"expires_in\":3600}"
set rc [catch {tossl::oauth2::is_token_expired -token $no_expiry_json} result]
puts "Result: $result"
if {$rc != 0} {
    puts "FAIL: Command errored: $result"
    exit 1
}
if {$result != 0} {
    puts "FAIL: Token without expires_at detected as expired"
    exit 1
}
puts "is_token_expired no expires_at: OK"

puts "Testing is_token_expired: invalid JSON..."
set rc [catch {tossl::oauth2::is_token_expired -token "not_json"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Invalid JSON did not error"
    exit 1
}
puts "is_token_expired invalid JSON: OK" 