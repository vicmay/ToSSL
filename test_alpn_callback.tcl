#!/usr/bin/env tclsh

# Test for TOSSL ALPN callback invoking Tcl code
package require tossl

set port 18080
set cert_file "server.pem"
set key_file "server.key"

# Generate self-signed cert if needed
if {![file exists $cert_file] || ![file exists $key_file]} {
    puts "Generating self-signed cert..."
    exec openssl req -x509 -newkey rsa:2048 -keyout $key_file -out $cert_file -days 1 -nodes -subj "/CN=localhost"
}

# ALPN callback: select 'h2' if offered, else first
proc alpn_select {protos} {
    puts "[clock format [clock seconds]] ALPN callback called with: $protos"
    if {"h2" in $protos} {return "h2"}
    return [lindex $protos 0]
}

# Start server
set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
tossl::ssl::set_alpn_callback -ctx $server_ctx -callback alpn_select
set server_sock [socket -server accept_cb $port]
puts "Server listening on port $port"

proc accept_cb {sock addr port} {
    global server_ctx
    fconfigure $sock -blocking 1
    set conn [tossl::ssl::accept -ctx $server_ctx -socket $sock]
    puts "Server: SSL connection established"
    set proto [tossl::ssl::alpn_selected -conn $conn]
    puts "Server: Negotiated ALPN protocol: $proto"
    puts $sock "hello"
    flush $sock
    close $sock
}

# Start client after a short delay
after 500 {
    set client_ctx [tossl::ssl::context create]
    set conn [tossl::ssl::connect -ctx $client_ctx -host 127.0.0.1 -port $port -alpn h2,http/1.1]
    puts "Client: SSL connection established"
    set proto [tossl::ssl::alpn_selected -conn $conn]
    puts "Client: Negotiated ALPN protocol: $proto"
    set line [gets $conn]
    puts "Client received: $line"
    close $conn
    exit 0
}

vwait forever 