# Usage: tclsh pgp_decrypt.tcl privkey.pem infile.bin

if {[llength $argv] != 2} {
    puts "Usage: tclsh pgp_decrypt.tcl privkey.pem infile.bin"
    exit 1
}
set privfile [lindex $argv 0]
set infile [lindex $argv 1]

# Load ToSSL
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Read the private key
set f [open $privfile r]
set priv [read $f]
close $f

# Read the encrypted file
set f [open $infile rb]
fconfigure $f -translation binary
set raw [read $f]
close $f

# Check file length
if {[string length $raw] < 12} {
    puts stderr "Error: Encrypted file is too short or corrupt."
    exit 2
}

# Parse lengths (big-endian 4 bytes each)
set n [binary scan $raw "cccccccccccc" k1 k2 k3 k4 i1 i2 i3 i4 c1 c2 c3 c4]
if {$n != 12} {
    puts stderr "Error: Failed to parse length headers from encrypted file."
    exit 2
}
set keylen [expr {($k1<<24)|($k2<<16)|($k3<<8)|($k4&0xff)}]
set ivlen  [expr {($i1<<24)|($i2<<16)|($i3<<8)|($i4&0xff)}]
set ctlen  [expr {($c1<<24)|($c2<<16)|($c3<<8)|($c4&0xff)}]

set offset 12
set wrapped_key [string range $raw $offset [expr {$offset+$keylen-1}]]
set offset [expr {$offset+$keylen}]
set aes_iv [string range $raw $offset [expr {$offset+$ivlen-1}]]
set offset [expr {$offset+$ivlen}]
set ciphertext [string range $raw $offset [expr {$offset+$ctlen-1}]]

if {[string length $wrapped_key] != $keylen || [string length $aes_iv] != $ivlen || [string length $ciphertext] != $ctlen} {
    puts stderr "Error: Encrypted file is truncated or corrupt (bad lengths)."
    exit 2
}

# Decrypt AES key
set aes_key [tossl::rsa::decrypt -privkey $priv $wrapped_key]
# Decrypt message
set message [tossl::decrypt -alg aes-128-cbc -key $aes_key -iv $aes_iv $ciphertext]

puts "Decrypted message: $message"
