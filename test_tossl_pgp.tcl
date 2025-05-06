# test_tossl_pgp.tcl - Basic PGP-style hybrid encryption/decryption using ToSSL

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Generate RSA keypair for the recipient
set keys [tossl::key::generate -type rsa]
set pub [dict get $keys public]
set priv [dict get $keys private]

# Generate a random AES key and IV
set aes_key [tossl::randbytes 16]
set aes_iv  [tossl::randbytes 16]

# The message to encrypt
set message "Hello, PGP-style world!"

# Encrypt the message with AES-128-CBC
set ciphertext [tossl::encrypt -alg aes-128-cbc -key $aes_key -iv $aes_iv $message]

# Encrypt the AES key with the recipient's RSA public key
set wrapped_key [tossl::rsa::encrypt -pubkey $pub $aes_key]

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
set decrypted_key [tossl::rsa::decrypt -privkey $priv [dict get $pgp_message wrapped_key]]

# Decrypt the message with the decrypted AES key and IV
set decrypted_message [tossl::decrypt -alg aes-128-cbc -key $decrypted_key -iv [dict get $pgp_message iv] [dict get $pgp_message ciphertext]]

puts "Original message: $message"
puts "Decrypted message: $decrypted_message"
