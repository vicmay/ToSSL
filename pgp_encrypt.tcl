# Usage: tclsh pgp_encrypt.tcl pubkey.pem "Secret message" outfile.bin

if {[llength $argv] != 3} {
    puts "Usage: tclsh pgp_encrypt.tcl pubkey.pem \"message\" outfile.bin"
    exit 1
}
set pubfile [lindex $argv 0]
set message [lindex $argv 1]
set outfile [lindex $argv 2]

# Load ToSSL
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Read the public key
set f [open $pubfile r]
set pub [read $f]
close $f

# Generate random AES key and IV
set aes_key [tossl::randbytes 16]
set aes_iv  [tossl::randbytes 16]

# Encrypt the message
set ciphertext [tossl::encrypt -alg aes-128-cbc -key $aes_key -iv $aes_iv $message]
set wrapped_key [tossl::rsa::encrypt -pubkey $pub $aes_key]

# Write lengths and data to outfile (format: keylen, ivlen, ctlen, then each blob)
set f [open $outfile wb]
# Write lengths as 4 bytes each, big-endian
set lengths [list [string length $wrapped_key] [string length $aes_iv] [string length $ciphertext]]
foreach val $lengths {
    puts -nonewline $f [binary format "cccc" \
        [expr {($val>>24)&0xff}] \
        [expr {($val>>16)&0xff}] \
        [expr {($val>>8)&0xff}] \
        [expr {$val&0xff}]]
}
puts -nonewline $f $wrapped_key
puts -nonewline $f $aes_iv
puts -nonewline $f $ciphertext
close $f

puts "Encrypted message written to $outfile"
