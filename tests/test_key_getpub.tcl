# Test for ::tossl::key::getpub
load ./libtossl.so

;# Generate RSA key and extract public key
set rsa [tossl::key::generate -type rsa -bits 2048]
set priv_rsa [dict get $rsa private]
set pub_rsa [dict get $rsa public]
set pub_rsa_extracted [tossl::key::getpub -key $priv_rsa]
if {$pub_rsa_extracted eq $pub_rsa} {
    puts "RSA getpub: OK"
} else {
    puts "RSA getpub: FAIL"
    puts "Expected: $pub_rsa"
    puts "Got: $pub_rsa_extracted"
    exit 1
}

;# Generate EC key and extract public key
set ec [tossl::key::generate -type ec -curve prime256v1]
set priv_ec [dict get $ec private]
set pub_ec [dict get $ec public]
set pub_ec_extracted [tossl::key::getpub -key $priv_ec]
if {$pub_ec_extracted eq $pub_ec} {
    puts "EC getpub: OK"
} else {
    puts "EC getpub: FAIL"
    puts "Expected: $pub_ec"
    puts "Got: $pub_ec_extracted"
    exit 1
}

;# Generate DSA key and extract public key (if supported)
if {[catch {set dsa [tossl::key::generate -type dsa -bits 1024]} err]} {
    puts "DSA not supported: $err"
} else {
    set priv_dsa [dict get $dsa private]
    set pub_dsa [dict get $dsa public]
    set pub_dsa_extracted [tossl::key::getpub -key $priv_dsa]
    if {$pub_dsa_extracted eq $pub_dsa} {
        puts "DSA getpub: OK"
    } else {
        puts "DSA getpub: FAIL"
        puts "Expected: $pub_dsa"
        puts "Got: $pub_dsa_extracted"
        exit 1
    }
}

;# Error handling: invalid key
if {[catch {tossl::key::getpub -key "not a key"} err]} {
    puts "Invalid key error: $err"
} else {
    puts "FAIL: Invalid key did not error"
    exit 1
}

;# Error handling: empty string
if {[catch {tossl::key::getpub -key ""} err]} {
    puts "Empty key error: $err"
} else {
    puts "FAIL: Empty key did not error"
    exit 1
}

puts "All ::tossl::key::getpub tests passed" 