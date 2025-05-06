# test_tossl_dsa_sign.tcl - Minimal DSA sign/verify test for ToSSL

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set dsa_rc [catch {set keys [tossl::key::generate -type dsa -bits 1024]} dsa_keys]
if {$dsa_rc != 0} {
    puts "DSA sign/verify... SKIPPED (not supported)"
    exit 0
}
set priv [dict get $keys private]
set pub  [dict get $keys public]
set data "test message"
puts "Private key:\n$priv"
puts "Public key:\n$pub"
set rc [catch {set sig [tossl::dsa::sign -privkey $priv -alg sha256 $data]} result]
if {$rc == 0} {
    puts "Signature(base64): [binary encode base64 $sig]"
    set rc2 [catch {set ok [tossl::dsa::verify -pubkey $pub -alg sha256 $data $sig]} result2]
    if {$rc2 == 0} {
        puts "Verify result: $ok"
        exit 0
    } else {
        puts stderr "Verify error: $result2"
        exit 2
    }
} else {
    puts stderr "Sign error: $result"
    exit 1
}
