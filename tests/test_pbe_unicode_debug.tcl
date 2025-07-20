# Debug Unicode handling in PBE
load ./libtossl.so

puts "Debugging Unicode handling in PBE..."

set algorithm "sha256"
set password "test_password_123"
set salt [tossl::pbe::saltgen 16]

# Test with simple Unicode string
set unicode_data "Hello, 世界! 🌍"
puts "Original Unicode: '$unicode_data'"
puts "Original length: [string length $unicode_data]"

# Check encoding
puts "Encoding: [encoding system]"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $unicode_data]} err]
if {$rc != 0} {
    puts "Encryption failed: $err"
    exit 1
}
puts "Encrypted length: [string length $encrypted]"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "Decryption failed: $err"
    exit 1
}
puts "Decrypted: '$decrypted'"
puts "Decrypted length: [string length $decrypted]"

# Compare
if {$unicode_data eq $decrypted} {
    puts "SUCCESS: Unicode round-trip works"
} else {
    puts "FAIL: Unicode mismatch"
    puts "Original bytes: [binary format H* [encoding convertto utf-8 $unicode_data]]"
    puts "Decrypted bytes: [binary format H* [encoding convertto utf-8 $decrypted]]"
} 