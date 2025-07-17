# Test for ::tossl::oauth2::introspect_token
load ./libtossl.so

puts "Testing introspect_token: missing required args..."
set rc [catch {tossl::oauth2::introspect_token -token foo -introspection_url bar -client_id baz} result]
if {$rc == 0} {
    puts "FAIL: Missing client_secret did not error"
    exit 1
}
puts "introspect_token missing arg: OK"

puts "Testing introspect_token: wrong arg..."
set rc [catch {tossl::oauth2::introspect_token -foo bar} result]
if {$rc == 0} {
    puts "FAIL: Wrong arg did not error"
    exit 1
}
puts "introspect_token wrong arg: OK"

# Note: A real HTTP test would require a live OAuth2 server. Here we only check argument validation and error handling. 