#!/usr/bin/env tclsh

# Robust test for ALPN callback with better error handling
package require tossl

set port 18080
set cert_file "server.pem"
set key_file "server.key"

# Check if certificate files exist
if {![file exists $cert_file] || ![file exists $key_file]} {
    puts "Certificate files not found. Please run the original test first to generate them."
    exit 1
}

# ALPN callback: select 'h2' if offered, else first
proc alpn_select {protos} {
    puts "[clock format [clock seconds]] ALPN callback called with: $protos"
    if {"h2" in $protos} {
        puts "Selecting h2"
        return "h2"
    }
    set selected [lindex $protos 0]
    puts "Selecting $selected"
    return $selected
}

# Start server with error handling
puts "Starting server..."
set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
if {[catch {tossl::ssl::set_alpn_callback -ctx $server_ctx -callback alpn_select} err]} {
    puts "Failed to set ALPN callback: $err"
    exit 1
}

set server_sock [socket -server accept_cb $port]
puts "Server listening on port $port"

proc accept_cb {sock addr port} {
    global server_ctx
    puts "Server: Accepted connection from $addr:$port"
    
    if {[catch {
        fconfigure $sock -blocking 1
        set conn [tossl::ssl::accept -ctx $server_ctx -socket $sock]
        puts "Server: SSL connection established"
        
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "Server: Negotiated ALPN protocol: $proto"
        
        puts $sock "hello"
        flush $sock
        close $sock
    } err]} {
        puts "Server error: $err"
        close $sock
    }
}

# Start client after a short delay
after 1000 {
    puts "Starting client..."
    if {[catch {
        set client_ctx [tossl::ssl::context create]
        set conn [tossl::ssl::connect -ctx $client_ctx -host 127.0.0.1 -port $port -alpn h2,http/1.1]
        puts "Client: SSL connection established"
        
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "Client: Negotiated ALPN protocol: $proto"
        
        set line [gets $conn]
        puts "Client received: $line"
        close $conn
    } err]} {
        puts "Client error: $err"
    }
    
    puts "Test completed"
    exit 0
}

# Set a timeout to prevent hanging
after 10000 {
    puts "Test timeout - exiting"
    exit 1
}

vwait forever 