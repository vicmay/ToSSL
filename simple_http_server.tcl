#!/usr/bin/env tclsh
# Simple HTTP Server for ACME Testing
# Built from scratch using Tcl sockets

package require http

namespace eval http_server {
    variable port 8080
    variable server_socket ""
    variable challenge_responses
    array set challenge_responses {}
    
    # MIME types
    variable mime_types {
        .html "text/html"
        .htm "text/html"
        .txt "text/plain"
        .css "text/css"
        .js "application/javascript"
        .json "application/json"
        .png "image/png"
        .jpg "image/jpeg"
        .jpeg "image/jpeg"
        .gif "image/gif"
        .ico "image/x-icon"
        .pdf "application/pdf"
        .xml "application/xml"
        .zip "application/zip"
    }
}

# Set challenge response for ACME HTTP-01
proc http_server::set_challenge {token response} {
    variable challenge_responses
    set challenge_responses($token) $response
    
    # Also save to file for persistence
    set f [open ".acme_challenges" a]
    puts $f "$token $response"
    close $f
    
    puts "Set ACME challenge: $token -> $response"
}

# Load challenges from file
proc http_server::load_challenges {} {
    variable challenge_responses
    
    if {[file exists ".acme_challenges"]} {
        set f [open ".acme_challenges" r]
        while {[gets $f line] >= 0} {
            if {[llength $line] >= 2} {
                set token [lindex $line 0]
                set response [lindex $line 1]
                set challenge_responses($token) $response
            }
        }
        close $f
        puts "Loaded [array size challenge_responses] challenges from file"
    }
}

# Remove challenge response
proc http_server::remove_challenge {token} {
    variable challenge_responses
    if {[info exists challenge_responses($token)]} {
        unset challenge_responses($token)
        
        # Rewrite file without this challenge
        if {[file exists ".acme_challenges"]} {
            set f [open ".acme_challenges" r]
            set lines {}
            while {[gets $f line] >= 0} {
                if {[lindex $line 0] ne $token} {
                    lappend lines $line
                }
            }
            close $f
            
            set f [open ".acme_challenges" w]
            foreach line $lines {
                puts $f $line
            }
            close $f
        }
        
        puts "Removed ACME challenge: $token"
    }
}

# List all active challenges
proc http_server::list_challenges {} {
    variable challenge_responses
    puts "Active ACME challenges:"
    if {[array size challenge_responses] == 0} {
        puts "  None"
    } else {
        foreach token [array names challenge_responses] {
            puts "  $token -> $challenge_responses($token)"
        }
    }
}

# Get MIME type for file extension
proc http_server::get_mime_type {filename} {
    variable mime_types
    set ext [string tolower [file extension $filename]]
    if {[info exists mime_types($ext)]} {
        return $mime_types($ext)
    }
    return "application/octet-stream"
}

# Send HTTP response
proc http_server::send_response {sock status_code status_text headers body} {
    puts $sock "HTTP/1.1 $status_code $status_text"
    puts $sock "Server: Simple-HTTP-Server/1.0"
    puts $sock "Date: [clock format [clock seconds] -format "%a, %d %b %Y %H:%M:%S GMT" -gmt 1]"
    puts $sock "Content-Length: [string length $body]"
    puts $sock "Connection: close"
    
    # Add custom headers
    foreach {name value} $headers {
        puts $sock "$name: $value"
    }
    
    puts $sock ""
    puts -nonewline $sock $body
    flush $sock
}

# Send error response
proc http_server::send_error {sock status_code status_text message} {
    set body "<html><head><title>$status_code $status_text</title></head>"
    append body "<body><h1>$status_code $status_text</h1>"
    append body "<p>$message</p>"
    append body "<hr><p><em>Simple HTTP Server</em></p></body></html>"
    
    http_server::send_response $sock $status_code $status_text [list "Content-Type" "text/html"] $body
}

# Handle ACME challenge requests
proc http_server::handle_acme_challenge {sock token} {
    variable challenge_responses
    
    if {[info exists challenge_responses($token)]} {
        set response $challenge_responses($token)
        puts "Serving ACME challenge: $token -> $response"
        
        http_server::send_response $sock 200 "OK" \
            [list "Content-Type" "text/plain"] $response
    } else {
        puts "ACME challenge not found: $token"
        http_server::send_error $sock 404 "Not Found" "ACME challenge not found"
    }
}

# Handle file requests
proc http_server::handle_file_request {sock path} {
    # Remove leading slash and normalize path
    set file_path [string trimleft $path "/"]
    if {$file_path eq ""} {
        set file_path "index.html"
    }
    
    # Security: prevent directory traversal
    if {[string first ".." $file_path] != -1} {
        http_server::send_error $sock 403 "Forbidden" "Directory traversal not allowed"
        return
    }
    
    # Check if file exists
    if {![file exists $file_path] || ![file isfile $file_path]} {
        http_server::send_error $sock 404 "Not Found" "File not found: $file_path"
        return
    }
    
    # Read file content
    if {[catch {
        set f [open $file_path r]
        set content [read $f]
        close $f
    } err]} {
        http_server::send_error $sock 500 "Internal Server Error" "Error reading file: $err"
        return
    }
    
    # Determine MIME type
    set mime_type [http_server::get_mime_type $file_path]
    
    puts "Serving file: $file_path ($mime_type)"
    http_server::send_response $sock 200 "OK" \
        [list "Content-Type" $mime_type] $content
}

# Handle HTTP request
proc http_server::handle_request {sock addr port} {
    if {[catch {
        # Read request line
        set line [gets $sock]
        if {[eof $sock]} {
            close $sock
            return
        }
        
        # Parse request line
        if {![regexp {^(\w+)\s+([^\s]+)\s+HTTP/(\d+\.\d+)$} $line -> method path version]} {
            puts "Invalid request line: $line"
            http_server::send_error $sock 400 "Bad Request" "Invalid request line"
            close $sock
            return
        }
        
        puts "Request: $method $path"
        
        # Read headers (we'll skip them for simplicity)
        while {1} {
            set header [gets $sock]
            if {$header eq "" || [eof $sock]} {
                break
            }
        }
        
        # Handle different request types
        switch [string toupper $method] {
            "GET" {
                # Check for ACME challenge
                if {[regexp {^/.well-known/acme-challenge/(.+)$} $path -> token]} {
                    http_server::handle_acme_challenge $sock $token
                } else {
                    http_server::handle_file_request $sock $path
                }
            }
            "HEAD" {
                # Similar to GET but without body
                if {[regexp {^/.well-known/acme-challenge/(.+)$} $path -> token]} {
                    variable challenge_responses
                    if {[info exists challenge_responses($token)]} {
                        set response $challenge_responses($token)
                        http_server::send_response $sock 200 "OK" \
                            [list "Content-Type" "text/plain"] ""
                    } else {
                        http_server::send_error $sock 404 "Not Found" "ACME challenge not found"
                    }
                } else {
                    http_server::handle_file_request $sock $path
                }
            }
            "POST" {
                # Read POST data (simplified)
                set post_data ""
                while {![eof $sock]} {
                    set chunk [read $sock 1024]
                    if {$chunk eq ""} break
                    append post_data $chunk
                }
                
                puts "POST data: [string length $post_data] bytes"
                http_server::send_response $sock 200 "OK" \
                    [list "Content-Type" "text/plain"] "POST received"
            }
            default {
                http_server::send_error $sock 405 "Method Not Allowed" "Method $method not supported"
            }
        }
        
    } err]} {
        puts "Error handling request: $err"
        catch {http_server::send_error $sock 500 "Internal Server Error" "Server error: $err"}
    }
    
    close $sock
}

# Start the server
proc http_server::start {{port_num 8080}} {
    variable port
    variable server_socket
    
    set port $port_num
    
    if {$port < 1024} {
        puts "Warning: Binding to port $port requires root privileges"
    }
    
    # Load existing challenges
    http_server::load_challenges
    
    set server_socket [socket -server http_server::handle_request $port]
    puts "Simple HTTP Server started on port $port"
    puts "Ready to serve ACME challenges and files"
    puts ""
    puts "Commands:"
    puts "  http_server::set_challenge <token> <response>"
    puts "  http_server::remove_challenge <token>"
    puts "  http_server::list_challenges"
    puts "  http_server::stop"
    puts ""
    puts "ACME challenge URL format:"
    puts "  http://localhost:$port/.well-known/acme-challenge/<token>"
}

# Stop the server
proc http_server::stop {} {
    variable server_socket
    if {$server_socket ne ""} {
        close $server_socket
        set server_socket ""
        puts "HTTP server stopped"
    }
}

# Interactive mode
proc http_server::interactive {} {
    puts "Simple HTTP Server Interactive Mode"
    puts "==================================="
    puts "Commands:"
    puts "  set <token> <response>  - Set ACME challenge response"
    puts "  remove <token>          - Remove ACME challenge"
    puts "  list                    - List all challenges"
    puts "  start ?port?            - Start server (default: 8080)"
    puts "  stop                    - Stop server"
    puts "  status                  - Show server status"
    puts "  quit                    - Exit"
    puts ""
    
    while {1} {
        puts -nonewline "http> "
        flush stdout
        
        if {[catch {
            set line [gets stdin]
            if {[eof stdin]} break
            
            set cmd [lindex $line 0]
            switch $cmd {
                "set" {
                    if {[llength $line] >= 3} {
                        set token [lindex $line 1]
                        set response [lindex $line 2]
                        http_server::set_challenge $token $response
                    } else {
                        puts "Usage: set <token> <response>"
                    }
                }
                "remove" {
                    if {[llength $line] >= 2} {
                        set token [lindex $line 1]
                        http_server::remove_challenge $token
                    } else {
                        puts "Usage: remove <token>"
                    }
                }
                "list" {
                    http_server::list_challenges
                }
                "start" {
                    set port [lindex $line 1]
                    if {$port eq ""} { set port 8080 }
                    http_server::start $port
                }
                "stop" {
                    http_server::stop
                }
                "status" {
                    variable server_socket
                    variable port
                    if {$server_socket ne ""} {
                        puts "Server is running on port $port"
                    } else {
                        puts "Server is not running"
                    }
                }
                "quit" {
                    http_server::stop
                    break
                }
                default {
                    if {$cmd ne ""} {
                        puts "Unknown command: $cmd"
                    }
                }
            }
        } err]} {
            puts "Error: $err"
        }
    }
}

# Test the server
proc http_server::test {} {
    puts "Testing HTTP Server..."
    
    # Start server
    http_server::start 8080
    
    # Set a test challenge
    http_server::set_challenge "test123" "test123.abc456"
    
    # Wait for server to start
    after 1000
    
    # Test the challenge
    if {[catch {
        set token [http::geturl "http://localhost:8080/.well-known/acme-challenge/test123"]
        set status [http::status $token]
        set data [http::data $token]
        http::cleanup $token
        
        puts "Test result: $status"
        puts "Response: '$data'"
        
        if {$data eq "test123.abc456"} {
            puts "Test PASSED!"
        } else {
            puts "Test FAILED!"
        }
    } err]} {
        puts "Test error: $err"
        puts "Test FAILED!"
    }
    
    # Stop server and exit
    http_server::stop
    puts "Test completed."
}

# Command line interface
if {[info exists argv]} {
    switch [lindex $argv 0] {
        "start" {
            set port [lindex $argv 1]
            if {$port eq ""} { set port 8080 }
            http_server::start $port
            vwait forever
        }
        "interactive" {
            http_server::interactive
        }
        "test" {
            http_server::test
        }
        default {
            puts "Usage: tclsh simple_http_server.tcl {start ?port?|interactive|test}"
            puts ""
            puts "  start ?port?    - Start server on specified port (default: 8080)"
            puts "  interactive     - Start interactive mode"
            puts "  test            - Run self-test"
            puts ""
            puts "Example:"
            puts "  tclsh simple_http_server.tcl start 8080"
            puts "  tclsh simple_http_server.tcl interactive"
            puts "  tclsh simple_http_server.tcl test"
        }
    }
} else {
    puts "Usage: tclsh simple_http_server.tcl {start ?port?|interactive|test}"
} 