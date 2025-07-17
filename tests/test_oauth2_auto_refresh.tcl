# Test for ::tossl::oauth2::auto_refresh
load ./libtossl.so

puts "Testing auto_refresh: missing required args..."
set rc [catch {tossl::oauth2::auto_refresh} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::oauth2::auto_refresh -token_data "{}" -client_id foo} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing client_secret/token_url did not error"
    exit 1
}
set rc [catch {tossl::oauth2::auto_refresh -token_data "{}" -client_id foo -client_secret bar -token_url baz} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: No refresh_token did not error"
    exit 1
}
puts "auto_refresh missing/invalid args: OK" 