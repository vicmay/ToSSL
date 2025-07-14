#!/usr/bin/env tclsh
# Test script for the HTTP server - External testing approach

package require http

puts "Testing HTTP Server (External Method)..."
puts "========================================"

# Create a simple test file
set test_content "<html><head><title>Test</title></head><body><h1>Simple HTTP Server Test</h1></body></html>"
set f [open "index.html" w]
puts $f $test_content
close $f

# Start server in background process
puts "Starting server in background..."
set server_pid [exec tclsh simple_http_server.tcl start 8080 &]

# Wait for server to start
puts "Waiting for server to start..."
after 2000

# Set a test challenge using the helper script
puts "Setting test challenge..."
if {[catch {
    exec tclsh set_challenge.tcl test456 test456.def789
} err]} {
    puts "Warning: Could not set challenge via helper: $err"
    puts "Challenge may already be set from previous runs"
}

# Test ACME challenge
puts "Testing ACME challenge..."
set acme_success 0
if {[catch {
    set token [http::geturl "http://localhost:8080/.well-known/acme-challenge/test456" -timeout 10000]
    set status [http::status $token]
    set data [http::data $token]
    http::cleanup $token
    
    puts "ACME HTTP status: $status"
    puts "ACME Response: '$data'"
    
    if {$data eq "test456.def789"} {
        puts "✅ ACME challenge test PASSED!"
        set acme_success 1
    } else {
        puts "❌ ACME challenge test FAILED!"
        puts "Expected: 'test456.def789'"
        puts "Got: '$data'"
    }
} err]} {
    puts "ACME challenge test error: $err"
    puts "❌ ACME challenge test FAILED!"
}

# Test file serving
puts "Testing file serving..."
set file_success 0
if {[catch {
    set token [http::geturl "http://localhost:8080/" -timeout 10000]
    set status [http::status $token]
    set data [http::data $token]
    http::cleanup $token
    
    puts "File serving status: $status"
    if {[string first "Simple HTTP Server Test" $data] != -1} {
        puts "✅ File serving test PASSED!"
        set file_success 1
    } else {
        puts "❌ File serving test FAILED!"
        puts "Response: '$data'"
    }
} err]} {
    puts "File serving test error: $err"
    puts "❌ File serving test FAILED!"
}

# Stop the server process
puts "Stopping server..."
catch {exec kill $server_pid}
catch {exec pkill -f "tclsh simple_http_server.tcl"}

# Clean up
catch {file delete "index.html"}
catch {http::cleanup}

puts "========================================"
puts "Test completed. Passed: [expr {$acme_success + $file_success}]/2 tests"
if {$acme_success && $file_success} {
    puts "✅ All tests PASSED!"
    exit 0
} else {
    puts "❌ Some tests FAILED!"
    exit 1
} 