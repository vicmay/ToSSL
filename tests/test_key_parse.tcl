# Test for ::tossl::key::parse
load ./libtossl.so

;# Generate RSA key
set rsa [tossl::key::generate -type rsa -bits 2048]
set priv_rsa [dict get $rsa private]
set pub_rsa [dict get $rsa public]

puts "Testing RSA private PEM parse..."
set info [tossl::key::parse $priv_rsa]
if {[dict get $info type] ne "rsa" || [dict get $info kind] ne "private"} {
    puts "FAIL: RSA private PEM parse"
    exit 1
}
puts "OK"

puts "Testing RSA public PEM parse..."
set info [tossl::key::parse $pub_rsa]
if {[dict get $info type] ne "rsa" || [dict get $info kind] ne "public"} {
    puts "FAIL: RSA public PEM parse"
    exit 1
}
puts "OK"

puts "Testing RSA private DER parse..."
set priv_der [tossl::key::write -key $priv_rsa -format der -type private]
set info [tossl::key::parse $priv_der]
if {[dict get $info type] ne "rsa" || [dict get $info kind] ne "private"} {
    puts "FAIL: RSA private DER parse"
    exit 1
}
puts "OK"

puts "Testing RSA public DER parse..."
set pub_der [tossl::key::write -key $pub_rsa -format der -type public]
set info [tossl::key::parse $pub_der]
if {[dict get $info type] ne "rsa" || [dict get $info kind] ne "public"} {
    puts "FAIL: RSA public DER parse"
    exit 1
}
puts "OK"

;# EC key
set ec [tossl::key::generate -type ec -curve prime256v1]
set priv_ec [dict get $ec private]
set pub_ec [dict get $ec public]
set curve_ec [dict get $ec curve]

puts "Testing EC private PEM parse..."
set info [tossl::key::parse $priv_ec]
if {[dict get $info type] ne "ec" || [dict get $info kind] ne "private" || [dict get $info curve] ne $curve_ec} {
    puts "FAIL: EC private PEM parse"
    exit 1
}
puts "OK"

puts "Testing EC public PEM parse..."
set info [tossl::key::parse $pub_ec]
if {[dict get $info type] ne "ec" || [dict get $info kind] ne "public" || [dict get $info curve] ne $curve_ec} {
    puts "FAIL: EC public PEM parse"
    exit 1
}
puts "OK"

puts "Testing EC private DER parse..."
set priv_der_ec [tossl::key::write -key $priv_ec -format der -type private]
set info [tossl::key::parse $priv_der_ec]
if {[dict get $info type] ne "ec" || [dict get $info kind] ne "private" || [dict get $info curve] ne $curve_ec} {
    puts "FAIL: EC private DER parse"
    exit 1
}
puts "OK"

puts "Testing EC public DER parse..."
set pub_der_ec [tossl::key::write -key $pub_ec -format der -type public]
set info [tossl::key::parse $pub_der_ec]
if {[dict get $info type] ne "ec" || [dict get $info kind] ne "public" || [dict get $info curve] ne $curve_ec} {
    puts "FAIL: EC public DER parse"
    exit 1
}
puts "OK"

;# DSA (if supported)
if {[catch {set dsa [tossl::key::generate -type dsa -bits 1024]} err]} {
    puts "DSA not supported: $err"
} else {
    set priv_dsa [dict get $dsa private]
    set pub_dsa [dict get $dsa public]
    puts "Testing DSA private PEM parse..."
    set info [tossl::key::parse $priv_dsa]
    if {[dict get $info type] ne "dsa" || [dict get $info kind] ne "private"} {
        puts "FAIL: DSA private PEM parse"
        exit 1
    }
    puts "OK"
    puts "Testing DSA public PEM parse..."
    set info [tossl::key::parse $pub_dsa]
    if {[dict get $info type] ne "dsa" || [dict get $info kind] ne "public"} {
        puts "FAIL: DSA public PEM parse"
        exit 1
    }
    puts "OK"
    set priv_der_dsa [tossl::key::write -key $priv_dsa -format der -type private]
    set info [tossl::key::parse $priv_der_dsa]
    if {[dict get $info type] ne "dsa" || [dict get $info kind] ne "private"} {
        puts "FAIL: DSA private DER parse"
        exit 1
    }
    puts "OK"
    set pub_der_dsa [tossl::key::write -key $pub_dsa -format der -type public]
    set info [tossl::key::parse $pub_der_dsa]
    if {[dict get $info type] ne "dsa" || [dict get $info kind] ne "public"} {
        puts "FAIL: DSA public DER parse"
        exit 1
    }
    puts "OK"
}

;# Error: invalid input
if {[catch {tossl::key::parse "not a key"} err]} {
    puts "Invalid input error: $err"
} else {
    puts "FAIL: Invalid input did not error"
    exit 1
}

puts "All ::tossl::key::parse tests passed" 