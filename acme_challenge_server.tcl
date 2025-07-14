#!/usr/bin/env tclsh
# ACME HTTP-01 Challenge Server
# Serves challenge responses for ACME domain validation

package require http

namespace eval acme_server {
    variable challenge_responses
    array set challenge_responses {}
    
    variable port 80
    variable server_socket ""
}

# Set challenge response for a token
proc acme_server::set_challenge {token response} {
    variable challenge_responses
    set challenge_responses($token) $response
    puts "Set challenge for token '$token': $response"
}

# Remove challenge response
proc acme_server::remove_challenge {token} {
    variable challenge_responses
    if {[info exists challenge_responses($token)]} {
        unset challenge_responses($token)
        puts "Removed challenge for token '$token'"
    }
}

# List all active challenges
proc acme_server::list_challenges {} {
    variable challenge_responses
    puts "Active ACME challenges:"
    foreach token [array names challenge_responses] {
        puts "  $token -> $challenge_responses($token)"
    }
}

# Handle HTTP request
proc acme_server::handle_request {sock} {
    variable challenge_responses
    
    if {[catch {
        set line [gets $sock]
        if {[eof $sock]} {
            close $sock
            return
        }
        
        # Parse request line
        if {![regexp {^GET\s+([^\s]+)\s+HTTP} $line -> path]} {
            puts "Invalid request: $line"
            close $sock
            return
        }
        
        puts "Request: $path"
        
        # Check if this is an ACME challenge
        if {[regexp {^/.well-known/acme-challenge/(.+)$} $path -> token]} {
            if {[info exists challenge_responses($token)]} {
                set response $challenge_responses($token)
                puts "Serving ACME challenge for token '$token': $response"
                
                puts $sock "HTTP/1.1 200 OK"
                puts $sock "Content-Type: text/plain"
                puts $sock "Content-Length: [string length $response]"
                puts $sock "Connection: close"
                puts $sock ""
                puts $sock $response
            } else {
                puts "Challenge not found for token: $token"
                puts $sock "HTTP/1.1 404 Not Found"
                puts $sock "Content-Type: text/plain"
                puts $sock "Connection: close"
                puts $sock ""
                puts $sock "Challenge not found"
            }
        } else {
            # Serve a simple status page
            puts $sock "HTTP/1.1 200 OK"
            puts $sock "Content-Type: text/html"
            puts $sock "Connection: close"
            puts $sock ""
            puts $sock "<html><head><title>ACME Challenge Server</title></head>"
            puts $sock "<body><h1>ACME Challenge Server</h1>"
            puts $sock "<p>This server is ready to serve ACME HTTP-01 challenges.</p>"
            puts $sock "<p>Active challenges:</p><ul>"
            foreach token [array names challenge_responses] {
                puts $sock "<li>$token</li>"
            }
            puts $sock "</ul></body></html>"
        }
        
        flush $sock
        close $sock
        
    } err]} {
        puts "Error handling request: $err"
        catch {close $sock}
    }
}

# Start the server
proc acme_server::start {{port_num 80}} {
    variable port
    variable server_socket
    
    set port $port_num
    
    if {$port < 1024} {
        puts "Warning: Binding to port $port requires root privileges"
    }
    
    set server_socket [socket -server acme_server::handle_request $port]
    puts "ACME Challenge Server started on port $port"
    puts "Ready to serve HTTP-01 challenges"
    puts "Use 'acme_server::set_challenge <token> <response>' to add challenges"
    puts "Use 'acme_server::list_challenges' to see active challenges"
    puts "Use 'acme_server::stop' to stop the server"
}

# Stop the server
proc acme_server::stop {} {
    variable server_socket
    if {$server_socket ne ""} {
        close $server_socket
        set server_socket ""
        puts "ACME Challenge Server stopped"
    }
}

# Interactive mode
proc acme_server::interactive {} {
    puts "ACME Challenge Server Interactive Mode"
    puts "====================================="
    puts "Commands:"
    puts "  set <token> <response>  - Set challenge response"
    puts "  remove <token>          - Remove challenge response"
    puts "  list                    - List all challenges"
    puts "  start ?port?            - Start server (default: 80)"
    puts "  stop                    - Stop server"
    puts "  quit                    - Exit"
    puts ""
    
    while {1} {
        puts -nonewline "acme> "
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
                        acme_server::set_challenge $token $response
                    } else {
                        puts "Usage: set <token> <response>"
                    }
                }
                "remove" {
                    if {[llength $line] >= 2} {
                        set token [lindex $line 1]
                        acme_server::remove_challenge $token
                    } else {
                        puts "Usage: remove <token>"
                    }
                }
                "list" {
                    acme_server::list_challenges
                }
                "start" {
                    set port [lindex $line 1]
                    if {$port eq ""} { set port 80 }
                    acme_server::start $port
                }
                "stop" {
                    acme_server::stop
                }
                "quit" {
                    acme_server::stop
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

# Command line interface
if {[info exists argv]} {
    switch [lindex $argv 0] {
        "start" {
            set port [lindex $argv 1]
            if {$port eq ""} { set port 80 }
            acme_server::start $port
            vwait forever
        }
        "interactive" {
            acme_server::interactive
        }
        default {
            puts "Usage: tclsh acme_challenge_server.tcl {start ?port?|interactive}"
            puts ""
            puts "  start ?port?    - Start server on specified port (default: 80)"
            puts "  interactive     - Start interactive mode"
            puts ""
            puts "Example:"
            puts "  tclsh acme_challenge_server.tcl start 8080"
            puts "  tclsh acme_challenge_server.tcl interactive"
        }
    }
} else {
    puts "Usage: tclsh acme_challenge_server.tcl {start ?port?|interactive}"
} 