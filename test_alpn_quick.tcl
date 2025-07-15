#!/usr/bin/env tclsh

# Quick ALPN test with timeout
package require tossl

set port 18080
set cert_file "server.pem"
set key_file "server.key"

# ALPN callback that logs the invocation
proc alpn_select {protos} {
    puts "🎯 ALPN CALLBACK INVOKED with protocols: $protos"
    if {"h2" in $protos} {
        puts "   → Selecting HTTP/2 (h2)"
        return "h2"
    }
    puts "   → Selecting first protocol: [lindex $protos 0]"
    return [lindex $protos 0]
}

puts "=== Quick ALPN Test ==="

# Start server
set server_ctx [tossl::ssl::context create -cert $cert_file -key $key_file]
tossl::ssl::set_alpn_callback -ctx $server_ctx -callback alpn_select
set server_sock [socket -server accept_cb $port]
puts "Server listening on port $port"

proc accept_cb {sock addr port} {
    global server_ctx
    puts "📥 Server: Accepted connection from $addr:$port"
    
    if {[catch {
        fconfigure $sock -blocking 1
        set conn [tossl::ssl::accept -ctx $server_ctx -socket $sock]
        puts "🔒 Server: SSL connection established"
        
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "📋 Server: Negotiated ALPN protocol: '$proto'"
        
        puts $sock "Hello from server!"
        flush $sock
        close $sock
    } err]} {
        puts "❌ Server error: $err"
        close $sock
    }
}

# Start client after 1 second
after 1000 {
    puts "🚀 Starting client..."
    if {[catch {
        set client_ctx [tossl::ssl::context create]
        set conn [tossl::ssl::connect -ctx $client_ctx -host 127.0.0.1 -port $port -alpn h2,http/1.1]
        puts "🔒 Client: SSL connection established"
        
        set proto [tossl::ssl::alpn_selected -conn $conn]
        puts "📋 Client: Negotiated ALPN protocol: '$proto'"
        
        set line [gets $conn]
        puts "📨 Client received: '$line'"
        close $conn
    } err]} {
        puts "❌ Client error: $err"
    }
    
    puts "✅ Test completed"
    exit 0
}

# Exit after 5 seconds
after 5000 {
    puts "⏰ Test timeout - exiting"
    exit 1
}

puts "⏳ Waiting for connection (5 second timeout)..."
vwait forever 