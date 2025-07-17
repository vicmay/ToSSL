# Test for ::tossl::oauth2::load_token
load ./libtossl.so

puts "Testing oauth2::load_token: round-trip with store_token..."
set token_data [dict create access_token "test_access_token" refresh_token "test_refresh_token" expires_in 3600 token_type "Bearer"]
set token_json [tossl::json::generate $token_data]
set encryption_key "test_key_12345"

# Store token
set encrypted_data [tossl::oauth2::store_token -token_data $token_json -encryption_key $encryption_key]
if {[string length $encrypted_data] == 0} {
    puts "FAIL: Encrypted data should not be empty"
    exit 1
}

# Load token
set decrypted_data [tossl::oauth2::load_token -encrypted_data $encrypted_data -encryption_key $encryption_key]
if {$decrypted_data != $token_json} {
    puts "FAIL: Decrypted data does not match original"
    exit 1
}
puts "oauth2::load_token round-trip: OK"

puts "Testing error: wrong arg count..."
set rc [catch {tossl::oauth2::load_token} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::load_token -encrypted_data $encrypted_data} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing encryption_key did not error"
    exit 1
}
set rc [catch {tossl::oauth2::load_token -encrypted_data $encrypted_data -encryption_key $encryption_key extra} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::oauth2::load_token tests passed" 