# gen_selfsigned_cert.tcl - Generate a self-signed X.509 certificate and private key using ToSSL
# Usage: tclsh gen_selfsigned_cert.tcl [CN] [days] > cert_and_key.pem
# If no CN is given, uses "localhost". If no days, uses 365.

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set cn [lindex $argv 0]
if {$cn eq ""} { set cn "localhost" }
set days [lindex $argv 1]
if {$days eq ""} { set days 365 }

# Generate EC key (prime256v1)
set keys [tossl::key::generate -type ec -curve prime256v1]
set priv [dict get $keys private]
set pub  [dict get $keys public]

# Generate self-signed cert
set cert [tossl::x509::create -subject $cn -issuer $cn -pubkey $pub -privkey $priv -days $days -keyusage {digitalSignature keyEncipherment}]

puts "# Private key:"
puts $priv
puts "# Certificate:"
puts $cert
