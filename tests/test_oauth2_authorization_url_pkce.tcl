# Test for ::tossl::oauth2::authorization_url_pkce
load ./libtossl.so

puts "Testing authorization_url_pkce: normal case..."
set code_verifier [tossl::oauth2::generate_code_verifier -length 64]
set code_challenge [tossl::oauth2::create_code_challenge -verifier $code_verifier]
set url [tossl::oauth2::authorization_url_pkce \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile" \
    -state "test_state" \
    -authorization_url "https://auth.example.com/oauth/authorize" \
    -code_challenge $code_challenge \
    -code_challenge_method S256]
puts "URL: $url"
if {![string match "*client_id=test_client*" $url]} {
    puts "FAIL: client_id missing"
    exit 1
}
if {![string match "*code_challenge=$code_challenge*" $url]} {
    puts "FAIL: code_challenge missing"
    exit 1
}
if {![string match "*code_challenge_method=S256*" $url]} {
    puts "FAIL: code_challenge_method missing"
    exit 1
}
puts "authorization_url_pkce normal: OK"

puts "Testing authorization_url_pkce: missing required arg..."
set rc [catch {tossl::oauth2::authorization_url_pkce -client_id foo -redirect_uri bar -authorization_url baz} result]
if {$rc == 0} {
    puts "FAIL: Missing code_challenge did not error"
    exit 1
}
puts "authorization_url_pkce missing arg: OK"

puts "Testing authorization_url_pkce: wrong arg..."
set rc [catch {tossl::oauth2::authorization_url_pkce -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "authorization_url_pkce wrong arg: OK" 