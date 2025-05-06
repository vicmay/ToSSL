# test_tossl.tcl - Smoke test: verify presence of all ToSSL commands
# This script loads the extension and checks that every documented command exists in the interpreter.

#package require tossl
load ./libtossl.so
set errors 0

proc check_cmd {cmd} {
    if {[llength [info commands $cmd]] == 0} {
        puts stderr "MISSING: $cmd"
        incr ::errors
    } else {
        puts "OK: $cmd"
    }
}

# Top-level commands
set commands {
    tossl::digest
    tossl::hmac
    tossl::randbytes
    tossl::encrypt
    tossl::decrypt
    tossl::rsa::generate
    tossl::rsa::encrypt
    tossl::rsa::decrypt
    tossl::rsa::sign
    tossl::rsa::verify
    tossl::dsa::sign
    tossl::dsa::verify
    tossl::ec::sign
    tossl::ec::verify
    tossl::key::generate
    tossl::key::parse
    tossl::key::write
    tossl::x509::parse
    tossl::x509::create
    tossl::x509::verify
    tossl::base64::encode
    tossl::base64::decode
    tossl::hex::encode
    tossl::hex::decode
    tossl::pkcs12::parse
    tossl::pkcs12::create
    tossl::pkcs7::sign
    tossl::pkcs7::verify
    tossl::pkcs7::encrypt
    tossl::pkcs7::decrypt
    tossl::pkcs7::info
    tossl::ssl::context
    tossl::ssl::context_free
    tossl::ssl::socket
    tossl::ssl::connect
    tossl::ssl::accept
    tossl::ssl::read
    tossl::ssl::write
    tossl::ssl::close
    tossl::ssl::session_export
    tossl::ssl::session_import
    tossl::ssl::session_info
    tossl::ssl::peer_cert
}

foreach cmd $commands {
    check_cmd $cmd
}

if {$errors > 0} {
    puts stderr "\n$errors command(s) missing."
    exit 1
} else {
    puts "\nAll ToSSL commands present."
    exit 0
}
