#!/usr/bin/env tclsh

# Debug test for ALPN callback
package require tossl

set port 18080
set cert_file "server.pem"
set key_file "server.key"

# Simple ALPN callback that just returns the first protocol
proc alpn_select {protos} {
    puts "DEBUG: ALPN callback called with: $protos"
    set selected [lindex $protos 0]
    puts "DEBUG: Selecting: $selected"
    return $selected
}

puts "Starting server with debugging..."

# Create server context
set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
puts "Server context created: $server_ctx"

# Set ALPN callback
puts "Setting ALPN callback..."
if {[catch {tossl::ssl::set_alpn_callback -ctx $server_ctx -callback alpn_select} err]} {
    puts "Failed to set ALPN callback: $err"
    exit 1
}
puts "ALPN callback set successfully"

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
        
        puts "DEBUG: Getting ALPN selected protocol..."
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "DEBUG: Negotiated ALPN protocol: $proto"
        
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
        set conn [tossl::ssl::connect -ctx $client_ctx -host 127.0.0.1 -port $port -alpn h2,http/1.1]
        puts "DEBUG: Client SSL connection established"
        
        puts "DEBUG: Getting client ALPN protocol..."
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "DEBUG: Client negotiated ALPN protocol: $proto"
        
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