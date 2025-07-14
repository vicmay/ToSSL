#!/usr/bin/env tclsh
# Manual test script for HTTP server

package require http

puts "Manual HTTP Server Test"
puts "======================"
puts "This script will help you test the HTTP server manually."
puts ""

# Check if server is running
puts "Checking if server is running on port 8080..."
if {[catch {
    set token [http::geturl "http://localhost:8080/" -timeout 3000]
    set status [http::status $token]
    http::cleanup $token
    puts "✅ Server is running (status: $status)"
} err]} {
    puts "❌ Server is not running or not responding: $err"
    puts ""
    puts "To start the server, run:"
    puts "  tclsh simple_http_server.tcl start 8080"
    puts ""
    puts "Or in interactive mode:"
    puts "  tclsh simple_http_server.tcl interactive"
    exit 1
}

puts ""
puts "Server is ready for testing!"
puts ""
puts "Available test commands:"
puts "  1. test_acme <token> <response>  - Test ACME challenge"
puts "  2. test_file <path>              - Test file serving"
puts "  3. test_root                     - Test root path (/)"
puts "  4. quit                          - Exit"
puts ""

proc test_acme {token response} {
    puts "Testing ACME challenge: $token -> $response"
    
    # Set the challenge
    if {[catch {
        exec tclsh set_challenge.tcl $token $response
        puts "Challenge set successfully"
    } err]} {
        puts "Warning: Could not set challenge: $err"
    }
    
    # Test the challenge
    if {[catch {
        set url "http://localhost:8080/.well-known/acme-challenge/$token"
        set token_http [http::geturl $url -timeout 5000]
        set status [http::status $token_http]
        set data [http::data $token_http]
        http::cleanup $token_http
        
        puts "HTTP status: $status"
        puts "Response: '$data'"
        
        if {$data eq $response} {
            puts "✅ ACME challenge test PASSED!"
        } else {
            puts "❌ ACME challenge test FAILED!"
            puts "Expected: '$response'"
            puts "Got: '$data'"
        }
    } err]} {
        puts "❌ ACME challenge test error: $err"
    }
    puts ""
}

proc test_file {path} {
    puts "Testing file serving: $path"
    
    if {[catch {
        set url "http://localhost:8080/$path"
        set token [http::geturl $url -timeout 5000]
        set status [http::status $token]
        set data [http::data $token]
        http::cleanup $token
        
        puts "HTTP status: $status"
        puts "Response length: [string length $data]"
        puts "First 100 chars: '[string range $data 0 99]'"
        
        if {$status eq "ok"} {
            puts "✅ File serving test PASSED!"
        } else {
            puts "❌ File serving test FAILED!"
        }
    } err]} {
        puts "❌ File serving test error: $err"
    }
    puts ""
}

proc test_root {} {
    puts "Testing root path (/)"
    test_file ""
}

# Interactive loop
while {1} {
    puts -nonewline "test> "
    flush stdout
    
    if {[catch {
        set line [gets stdin]
        if {[eof stdin]} break
        
        set cmd [lindex $line 0]
        switch $cmd {
            "test_acme" {
                if {[llength $line] >= 3} {
                    set token [lindex $line 1]
                    set response [lindex $line 2]
                    test_acme $token $response
                } else {
                    puts "Usage: test_acme <token> <response>"
                }
            }
            "test_file" {
                if {[llength $line] >= 2} {
                    set path [lindex $line 1]
                    test_file $path
                } else {
                    puts "Usage: test_file <path>"
                }
            }
            "test_root" {
                test_root
            }
            "quit" {
                puts "Goodbye!"
                break
            }
            default {
                if {$cmd ne ""} {
                    puts "Unknown command: $cmd"
                    puts "Available commands: test_acme, test_file, test_root, quit"
                }
            }
        }
    } err]} {
        puts "Error: $err"
    }
}

catch {http::cleanup} 