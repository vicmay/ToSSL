#!/usr/bin/env tclsh
# Set ACME challenge on the running HTTP server

if {[llength $argv] != 2} {
    puts "Usage: tclsh set_challenge.tcl <token> <response>"
    puts "Example: tclsh set_challenge.tcl test123 test123.abc456"
    exit 1
}

set token [lindex $argv 0]
set response [lindex $argv 1]

# Source the HTTP server to get access to its functions
source simple_http_server.tcl

# Set the challenge
http_server::set_challenge $token $response

puts "Challenge set successfully!"
puts "Test with: curl http://localhost:8080/.well-known/acme-challenge/$token" 