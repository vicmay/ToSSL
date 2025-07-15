#!/usr/bin/env tclsh

# Basic SSL test without ALPN
package require tossl

set port 18080
set cert_file "server.pem"
set key_file "server.key"

puts "Testing basic SSL functionality without ALPN..."

# Create server context
set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
puts "Server context created: $server_ctx"

# Create server socket
puts "Creating server socket..."
set server_sock [socket -server accept_cb $port]
puts "Server listening on port $port"

proc accept_cb {sock addr port} {
    global server_ctx
    puts "DEBUG: Accepted connection from $addr:$port"
    
    if {[catch {
        puts "DEBUG: Configuring socket..."
        fconfigure $sock -blocking 1
        
        puts "DEBUG: Starting SSL accept..."
        set conn [tossl::ssl::accept -ctx $server_ctx -socket $sock]
        puts "DEBUG: SSL connection established"
        
        puts "DEBUG: Sending response..."
        puts $sock "hello"
        flush $sock
        
        puts "DEBUG: Closing connection..."
        close $sock
        puts "DEBUG: Connection closed"
    } err]} {
        puts "Server error: $err"
        close $sock
    }
}

# Start client after delay
after 2000 {
    puts "Starting client..."
    if {[catch {
        puts "DEBUG: Creating client context..."
        set client_ctx [tossl::ssl::context create]
        
        puts "DEBUG: Connecting to server..."
        set conn [tossl::ssl::connect -ctx $client_ctx -host 127.0.0.1 -port $port]
        puts "DEBUG: Client SSL connection established"
        
        puts "DEBUG: Reading response..."
        set line [gets $conn]
        puts "DEBUG: Client received: $line"
        
        puts "DEBUG: Closing client connection..."
        close $conn
        puts "DEBUG: Client connection closed"
    } err]} {
        puts "Client error: $err"
    }
    
    puts "Test completed"
    exit 0
}

# Set timeout
after 15000 {
    puts "Test timeout - exiting"
    exit 1
}

puts "Waiting for connections..."
vwait forever 