# Test for ::tossl::oauth2::authorization_url
load ./libtossl.so

puts "Testing authorization_url: normal case..."
set url [tossl::oauth2::authorization_url \
    -client_id "test_client" \
    -redirect_uri "https://example.com/callback" \
    -scope "openid profile" \
    -state "test_state" \
    -authorization_url "https://auth.example.com/oauth/authorize"]
puts "URL: $url"
if {![string match "*client_id=test_client*" $url]} {
    puts "FAIL: client_id missing"
    exit 1
}
if {![string match "*redirect_uri=https%3A%2F%2Fexample.com%2Fcallback*" $url]} {
    puts "FAIL: redirect_uri missing or not encoded"
    exit 1
}
if {![string match "*scope=openid%20profile*" $url]} {
    puts "FAIL: scope missing or not encoded"
    exit 1
}
if {![string match "*state=test_state*" $url]} {
    puts "FAIL: state missing"
    exit 1
}
puts "authorization_url normal: OK"

puts "Testing authorization_url: missing required arg..."
set rc [catch {tossl::oauth2::authorization_url -client_id foo -redirect_uri bar -scope baz} result]
if {$rc == 0} {
    puts "FAIL: Missing authorization_url did not error"
    exit 1
}
puts "authorization_url missing arg: OK"

puts "Testing authorization_url: wrong arg..."
set rc [catch {tossl::oauth2::authorization_url -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "authorization_url wrong arg: OK" 