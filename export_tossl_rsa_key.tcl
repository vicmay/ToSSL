# Export a ToSSL-generated RSA private key to PEM for OpenSSL CLI testing
if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set keys [tossl::key::generate]
set priv [dict get $keys private]
set f [open "test_rsa_priv.pem" w]
puts $f $priv
close $f
puts "Wrote test_rsa_priv.pem"
