# Test for ::tossl::oauth2::parse_token
load ./libtossl.so

puts "Testing parse_token: normal token response..."
set response "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\",\"refresh_token\":\"def456\",\"scope\":\"read write\",\"expires_in\":3600}"
set rc [catch {tossl::oauth2::parse_token $response} parsed]
puts "Return code: $rc"
puts "Parsed: $parsed ([llength $parsed])"
set keys_rc [catch {dict keys $parsed} keys]
puts "dict keys rc: $keys_rc"
puts "dict keys: $keys"
if {$rc != 0} {
    puts "FAIL: parse_token returned error: $parsed"
    exit 1
}
if {[catch {dict get $parsed access_token} val]} {
    puts "FAIL: access_token not found in parsed dict"
    puts "Raw parsed: $parsed"
    exit 1
}
if {$val ne "abc123"} {
    puts "FAIL: access_token mismatch"
    exit 1
}
if {[dict get $parsed token_type] ne "Bearer"} {
    puts "FAIL: token_type mismatch"
    exit 1
}
if {[dict get $parsed refresh_token] ne "def456"} {
    puts "FAIL: refresh_token mismatch"
    exit 1
}
if {[dict get $parsed scope] ne "read write"} {
    puts "FAIL: scope mismatch"
    exit 1
}
if {[dict get $parsed expires_in] != 3600} {
    puts "FAIL: expires_in mismatch"
    exit 1
}
puts "parse_token normal: OK"

puts "Testing parse_token: error response..."
set response "{\"error\":\"invalid_grant\",\"error_description\":\"Bad code\"}"
set parsed [tossl::oauth2::parse_token $response]
puts "Parsed: $parsed"
if {[dict get $parsed error] ne "invalid_grant"} {
    puts "FAIL: error field missing"
    exit 1
}
if {[dict get $parsed error_description] ne "Bad code"} {
    puts "FAIL: error_description field missing"
    exit 1
}
puts "parse_token error: OK"

puts "Testing parse_token: missing required arg..."
set rc [catch {tossl::oauth2::parse_token} result]
if {$rc == 0} {
    puts "FAIL: Missing arg did not error"
    exit 1
}
puts "parse_token missing arg: OK" 