package require tossl
set keys [tossl::key::generate -type rsa -bits 2048]
set key [dict get $keys private]
set pub [dict get $keys public]
set cert [tossl::x509::create -subject "Test Cert" -issuer "Test Cert" -pubkey $pub -privkey $key -days 365]
set f [open "test_cert.pem" w]
puts $f $cert
close $f
set f [open "test_key.pem" w]
puts $f $key
close $f 