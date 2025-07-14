# Minimal encrypt test to isolate error
if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set test_key [binary format H* 00112233445566778899aabbccddeeff]
set test_iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
set test_plain "Test message!"
puts "Minimal encrypt test:"
set test_cipher [tossl::encrypt -alg aes-128-cbc -key $test_key -iv $test_iv $test_plain]
puts "Minimal encrypt test succeeded."

# test_tossl_pgp.tcl - Basic PGP-style hybrid encryption/decryption using ToSSL

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "Testing OpenPGP RSA key generation..."
set key_bin [tossl::pgp::key::generate -type rsa -bits 1024 -userid "Test User <test@example.com>" -armor 0]
puts "PGP key (binary, length): [string length $key_bin]"
set key_arm [tossl::pgp::key::generate -type rsa -bits 1024 -userid "Test User <test@example.com>" -armor 1]
puts "PGP key (ASCII-armored):\n$key_arm"
if {[string length $key_bin] == 0 || [string length $key_arm] == 0} {
    error "PGP key generation failed!"
} else {
    puts "PGP key generation succeeded."
}
puts "Parsing generated PGP key..."
set parsed [tossl::pgp::key::parse $key_arm]
puts "Parsed key info: $parsed"
puts "Importing generated PGP key..."
set imported [tossl::pgp::key::import $key_arm]
puts "Imported key info: $imported"
puts "Exporting imported key (ASCII-armored)..."
set exported [tossl::pgp::key::export $imported -armor 1]
puts "Exported key (ASCII-armored):\n$exported"
puts "Parsing exported key..."
set parsed2 [tossl::pgp::key::parse $exported]
puts "Parsed exported key info: $parsed2"
if {[dict get $parsed2 userid] ne "Test User <test@example.com>"} {
    error "Round-trip user ID mismatch!"
}
puts "PGP key round-trip import/export/parse succeeded."

# Generate RSA keypair for the recipient
set keys [tossl::key::generate -type rsa]
set pub [dict get $keys public]
set priv [dict get $keys private]

# Generate a random AES key and IV
set aes_key [binary format H* 00112233445566778899aabbccddeeff]
set aes_iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]

# The message to encrypt
set message "Hello, PGP-style world!"

puts "aes_key length: [string length $aes_key]"
puts "aes_iv length: [string length $aes_iv]"
puts "message length: [string length $message]"
# Encrypt the message with AES-128-CBC
set ciphertext [tossl::encrypt -alg aes-128-cbc -key $aes_key -iv $aes_iv $message]

# Encrypt the AES key with the recipient's RSA public key
set wrapped_key [tossl::rsa::encrypt -key $pub -data $aes_key -padding pkcs1]

# Compose the "PGP message" as a dict
set pgp_message [dict create wrapped_key $wrapped_key iv $aes_iv ciphertext $ciphertext]

# Save the PGP message to a file
set f [open "pgp_message.bin" wb]
puts -nonewline $f [binary format a* [dict get $pgp_message wrapped_key]]
puts -nonewline $f [binary format a* [dict get $pgp_message iv]]
puts -nonewline $f [binary format a* [dict get $pgp_message ciphertext]]
close $f
puts "PGP message written to pgp_message.bin"

# --- Recipient side: Decrypt ---
# (In a real scenario, the recipient would load the keys and message from files)

# Decrypt the AES key with the recipient's RSA private key
set decrypted_key [tossl::rsa::decrypt -key $priv -data [dict get $pgp_message wrapped_key] -padding pkcs1]

# Decrypt the message with the decrypted AES key and IV
set decrypted_message [tossl::decrypt -alg aes-128-cbc -key $decrypted_key -iv [dict get $pgp_message iv] [dict get $pgp_message ciphertext]]

puts "Original message: $message"
puts "Decrypted message: $decrypted_message"
