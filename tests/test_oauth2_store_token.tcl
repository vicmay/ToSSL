# Test for ::tossl::oauth2::store_token
load ./libtossl.so

puts "Testing store_token: normal round-trip..."
set token_data "{\"access_token\":\"abc123\",\"expires_in\":3600}"
set key "testkey"
set rc [catch {tossl::oauth2::store_token -token_data $token_data -encryption_key $key} encrypted]
puts "Encrypted: $encrypted"
if {$rc != 0 || [string length $encrypted] == 0} {
    puts "FAIL: store_token failed"
    exit 1
}
set rc [catch {tossl::oauth2::load_token -encrypted_data $encrypted -encryption_key $key} decrypted]
puts "Decrypted: $decrypted"
if {$rc != 0 || $decrypted ne $token_data} {
    puts "FAIL: load_token round-trip failed"
    exit 1
}
puts "store_token round-trip: OK"

puts "Testing store_token: empty encryption key (should fail)..."
set rc [catch {tossl::oauth2::store_token -token_data $token_data -encryption_key ""} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Empty encryption key did not error"
    exit 1
}
puts "store_token empty key: OK"

puts "Testing store_token: missing args (should fail)..."
set rc [catch {tossl::oauth2::store_token -token_data $token_data} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing encryption key did not error"
    exit 1
}
puts "store_token missing arg: OK" 