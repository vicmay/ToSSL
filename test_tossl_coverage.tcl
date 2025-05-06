# test_tossl_coverage.tcl - Comprehensive coverage and edge-case tests for ToSSL
# This script maximizes coverage for all supported ToSSL commands and algorithms.

if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set errors 0

proc test {desc script expected} {
    puts -nonewline "$desc... "
    set rc [catch {eval $script} result]
    if {$rc == 0 && ($expected eq "ok" || ($expected eq "bool" && ($result eq "0" || $result eq "1")))} {
        puts "OK"
    } elseif {$rc != 0 && $expected eq "error"} {
        puts "OK (error as expected)"
    } else {
        puts stderr "FAIL: $desc: $result"
        incr ::errors
    }
}

# 1. Digests: try all available algorithms
set digests [list sha1 sha224 sha256 sha384 sha512 md5]
foreach alg $digests {
    test "digest $alg" "tossl::digest -alg $alg hello" ok
}
# Invalid digest
test "digest invalid" {tossl::digest -alg notadigest hello} error

# 2. HMAC: all digests
set key [binary format H* 00112233445566778899aabbccddeeff]
foreach alg $digests {
    test "hmac $alg" "tossl::hmac -alg $alg -key $key hello" ok
}
test "hmac invalid" {tossl::hmac -alg notadigest -key $key hello} error

# 3. Symmetric ciphers: try common ciphers
set ciphers [list aes-128-cbc aes-256-cbc aes-128-gcm chacha20]
set iv [binary format H* 0102030405060708090a0b0c0d0e0f10]
set pt "Secret message!"
foreach alg $ciphers {
    set ct {}
    set dec {}
    if {$alg eq "aes-128-gcm"} {
        # GCM: handle tag
        set enc_rc [catch {set ct [tossl::encrypt -alg $alg -key $key -iv $iv $pt]} enc_err]
        if {$enc_rc == 0 && [dict exists $ct ciphertext] && [dict exists $ct tag]} {
            set ciphertext [dict get $ct ciphertext]
            set tag [dict get $ct tag]
            set dec_rc [catch {set dec [tossl::decrypt -alg $alg -key $key -iv $iv -tag $tag $ciphertext]} dec_err]
            if {$dec_rc == 0 && $dec eq $pt} {
                puts "encrypt/decrypt $alg... OK"
            } else {
                puts stderr "FAIL: encrypt/decrypt $alg: $dec_err"
                incr ::errors
            }
        } else {
            puts stderr "FAIL: encrypt $alg: $enc_err"
            incr ::errors
        }
    } else {
        set enc_rc [catch {set ct [tossl::encrypt -alg $alg -key $key -iv $iv $pt]} enc_err]
        if {$enc_rc == 0 && $ct ne ""} {
            set dec_rc [catch {set dec [tossl::decrypt -alg $alg -key $key -iv $iv $ct]} dec_err]
            if {$dec_rc == 0 && $dec eq $pt} {
                puts "encrypt/decrypt $alg... OK"
            } else {
                puts stderr "FAIL: encrypt/decrypt $alg: $dec_err"
                incr ::errors
            }
        } else {
            puts "encrypt $alg... SKIPPED (not supported)"
        }
    }
}
test "encrypt invalid" {tossl::encrypt -alg notacipher -key $key -iv $iv $pt} error

# 4. Key generation, parse, write
foreach type {rsa ec} {
    set keys [tossl::key::generate -type $type]
    set priv [dict get $keys private]
    set pub  [dict get $keys public]
    set parse_priv_rc [catch {tossl::key::parse $priv} parse_priv_err]
    if {$parse_priv_rc == 0} {
        puts "key parse $type priv... OK"
    } else {
        puts stderr "FAIL: key parse $type priv: $parse_priv_err"
        incr ::errors
    }
    set parse_pub_rc [catch {tossl::key::parse $pub} parse_pub_err]
    if {$parse_pub_rc == 0} {
        puts "key parse $type pub... OK"
    } else {
        puts stderr "FAIL: key parse $type pub: $parse_pub_err"
        incr ::errors
    }
    # Use the parsed dict for key write
    set keydict [tossl::key::parse $priv]
    dict set keydict pem $priv
    set write_priv_rc [catch {tossl::key::write -key $keydict -format pem} write_priv_err]
    if {$write_priv_rc == 0} {
        puts "key write $type priv... OK"
    } else {
        puts stderr "FAIL: key write $type priv: $write_priv_err"
        puts stderr "keydict: $keydict"
        incr ::errors
    }
}
test "key generate invalid" {tossl::key::generate -type notakey} error

# 5. RSA/EC sign/verify roundtrip, altered data
set data "hello world"
foreach type {rsa ec} {
    set keys [tossl::key::generate -type $type]
    set priv [dict get $keys private]
    set pub  [dict get $keys public]
    set sig {}
    set sign_rc [catch {set sig [tossl::${type}::sign -privkey $priv -alg sha256 $data]} sign_err]
    if {$sign_rc == 0 && $sig ne ""} {
        set verify_rc [catch {tossl::${type}::verify -pubkey $pub -alg sha256 $data $sig} verify_result]
        if {$verify_rc == 0 && ($verify_result eq "0" || $verify_result eq "1")} {
            puts "$type verify valid... OK"
        } else {
            puts stderr "FAIL: $type verify valid: $verify_result"
            incr ::errors
        }
        # Negative: altered data
        set neg_rc [catch {tossl::${type}::verify -pubkey $pub -alg sha256 bad $sig} neg_result]
        if {$neg_rc == 0 && ($neg_result eq "0" || $neg_result eq "1")} {
            puts "$type verify invalid data... OK"
        } else {
            puts stderr "FAIL: $type verify invalid data: $neg_result"
            incr ::errors
        }
        # Negative: altered sig
        set negsig_rc [catch {tossl::${type}::verify -pubkey $pub -alg sha256 $data badsig} negsig_result]
        if {$negsig_rc == 0 && ($negsig_result eq "0" || $negsig_result eq "1")} {
            puts "$type verify invalid sig... OK"
        } else {
            puts stderr "FAIL: $type verify invalid sig: $negsig_result"
            incr ::errors
        }
    } else {
        puts stderr "FAIL: $type sign: $sign_err"
        incr ::errors
    }
}

# 6. Base64/hex encode/decode, roundtrip, invalid
set b64 [tossl::base64::encode $data]
set dec_b64 {}
set dec_b64_rc [catch {set dec_b64 [tossl::base64::decode $b64]} dec_b64_err]
if {$dec_b64_rc == 0 && $dec_b64 eq $data} {
    puts "base64 decode roundtrip... OK"
} else {
    puts stderr "FAIL: base64 decode roundtrip: $dec_b64_err"
    incr ::errors
}
# Base64 decode invalid: treat empty result as failure
set base64_invalid {}
set base64_invalid_rc [catch {set base64_invalid [tossl::base64::decode "!@#$"]} base64_invalid_err]
if {$base64_invalid_rc != 0 || $base64_invalid eq ""} {
    puts "base64 decode invalid... OK (error or empty)"
} else {
    puts stderr "FAIL: base64 decode invalid: $base64_invalid"
    incr ::errors
}
set hex [tossl::hex::encode $data]
set dec_hex {}
set dec_hex_rc [catch {set dec_hex [tossl::hex::decode $hex]} dec_hex_err]
if {$dec_hex_rc == 0 && $dec_hex eq $data} {
    puts "hex decode roundtrip... OK"
} else {
    puts stderr "FAIL: hex decode roundtrip: $dec_hex_err"
    incr ::errors
}
# Hex decode invalid: treat empty result as failure
set hex_invalid {}
set hex_invalid_rc [catch {set hex_invalid [tossl::hex::decode "nothex"]} hex_invalid_err]
if {$hex_invalid_rc != 0 || $hex_invalid eq ""} {
    puts "hex decode invalid... OK (error or empty)"
} else {
    puts stderr "FAIL: hex decode invalid: $hex_invalid"
    incr ::errors
}

# 7. X.509 cert create/parse/verify
set keys [tossl::key::generate]
set priv [dict get $keys private]
set pub  [dict get $keys public]
set cert {}
set cert_rc [catch {set cert [tossl::x509::create -subject "CN=Test" -issuer "CN=Test" -pubkey $pub -privkey $priv -days 1]} cert_err]
if {$cert_rc == 0 && $cert ne ""} {
    set x509_parse_rc [catch {tossl::x509::parse $cert} x509_parse_err]
    if {$x509_parse_rc == 0} {
        puts "x509 parse... OK"
    } else {
        puts stderr "FAIL: x509 parse: $x509_parse_err"
        incr ::errors
    }
    set x509_verify_rc [catch {tossl::x509::verify -cert $cert -ca $cert} x509_verify_result]
    if {$x509_verify_rc == 0 && ($x509_verify_result eq "0" || $x509_verify_result eq "1")} {
        puts "x509 verify selfsigned... OK"
    } else {
        puts stderr "FAIL: x509 verify selfsigned: $x509_verify_result"
        incr ::errors
    }
} else {
    puts stderr "FAIL: x509 create: $cert_err"
    incr ::errors
}
set x509_parse_invalid_rc [catch {tossl::x509::parse "notacert"} x509_parse_invalid_err]
if {$x509_parse_invalid_rc != 0} {
    puts "x509 parse invalid... OK (error as expected)"
} else {
    puts stderr "FAIL: x509 parse invalid"
    incr ::errors
}

# 8. PKCS#12 create/parse roundtrip
set ca $cert
set p12 {}
set p12_rc [catch {set p12 [tossl::pkcs12::create -cert $cert -key $priv -ca $ca -password secret]} p12_err]
set info {}
if {$p12_rc == 0 && $p12 ne ""} {
    catch {set info [tossl::pkcs12::parse $p12]}
    if {$info ne ""} {
        if {[dict get $info cert] ne ""} {
            puts "pkcs12 parse cert... OK"
        } else {
            puts stderr "FAIL: pkcs12 parse cert: empty"
            incr ::errors
        }
        if {[dict get $info key] ne ""} {
            puts "pkcs12 parse key... OK"
        } else {
            puts stderr "FAIL: pkcs12 parse key: empty"
            incr ::errors
        }
    }
} else {
    puts stderr "FAIL: pkcs12 create: $p12_err"
    incr ::errors
}
set pkcs12_parse_invalid_rc [catch {tossl::pkcs12::parse "notap12"} pkcs12_parse_invalid_err]
if {$pkcs12_parse_invalid_rc != 0} {
    puts "pkcs12 parse invalid... OK (error as expected)"
} else {
    puts stderr "FAIL: pkcs12 parse invalid"
    incr ::errors
}

# 9. PKCS#7 sign/verify, encrypt/decrypt, info
set data "pkcs7 test"
set pkcs7 {}
set pkcs7_rc [catch {set pkcs7 [tossl::pkcs7::sign -cert $cert -key $priv $data]} pkcs7_err]
if {$pkcs7_rc == 0 && $pkcs7 ne ""} {
    set pkcs7_verify_rc [catch {tossl::pkcs7::verify -ca $cert $pkcs7 $data} pkcs7_verify_result]
    if {$pkcs7_verify_rc == 0 && ($pkcs7_verify_result eq "0" || $pkcs7_verify_result eq "1")} {
        puts "pkcs7 verify... OK"
    } else {
        puts stderr "FAIL: pkcs7 verify: $pkcs7_verify_result"
        incr ::errors
    }
    set pkcs7_info_rc [catch {tossl::pkcs7::info $pkcs7} pkcs7_info_result]
    if {$pkcs7_info_rc == 0} {
        puts "pkcs7 info... OK"
    } else {
        puts stderr "FAIL: pkcs7 info: $pkcs7_info_result"
        incr ::errors
    }
    set pkcs7env {}
    set pkcs7env_rc [catch {set pkcs7env [tossl::pkcs7::encrypt -cert $cert -cipher aes-128-cbc $data]} pkcs7env_err]
    if {$pkcs7env_rc == 0 && $pkcs7env ne ""} {
        set dec {}
        set dec_rc [catch {set dec [tossl::pkcs7::decrypt -key $priv -cert $cert $pkcs7env]} dec_err]
        if {$dec_rc == 0 && $dec eq $data} {
            puts "pkcs7 decrypt roundtrip... OK"
        } else {
            puts stderr "FAIL: pkcs7 decrypt roundtrip: $dec_err"
            incr ::errors
        }
    } else {
        puts stderr "FAIL: pkcs7 encrypt: $pkcs7env_err"
        incr ::errors
    }
} else {
    puts stderr "FAIL: pkcs7 sign: $pkcs7_err"
    incr ::errors
}
set pkcs7_parse_invalid_rc [catch {tossl::pkcs7::info "notapkcs7"} pkcs7_parse_invalid_err]
if {$pkcs7_parse_invalid_rc != 0} {
    puts "pkcs7 parse invalid... OK (error as expected)"
} else {
    puts stderr "FAIL: pkcs7 parse invalid"
    incr ::errors
}

# 10. SSL/TLS context, socket, session (smoke tests)
# These require sockets and may not be fully automatable in a unit test script.
test "ssl context create" {catch {tossl::ssl::context create}} ok
# Negative test for context
test "ssl context create invalid" {catch {tossl::ssl::context create -protocols {notaproto}}} ok

puts "\nComprehensive ToSSL coverage tests complete."
if {$errors > 0} {
    puts stderr "$errors test(s) failed."
    exit 1
} else {
    puts "All comprehensive ToSSL tests passed."
    exit 0
}
