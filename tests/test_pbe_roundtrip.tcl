# Test PBE round-trip encryption/decryption with fixed implementation
load ./libtossl.so

puts "Testing PBE round-trip encryption/decryption with fixed implementation..."

# Test 1: Basic text data
set algorithm "sha256"
set password "test_password_123"
set salt [tossl::pbe::saltgen 16]
set original_data "Hello, World! This is a test message for PBE encryption/decryption."

puts "Test 1: Basic text data"
puts "  Original: '$original_data'"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $original_data]} err]
if {$rc != 0} {
    puts "  FAIL: Encryption failed - $err"
    exit 1
}
puts "  Encrypted: [string length $encrypted] bytes"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "  FAIL: Decryption failed - $err"
    exit 1
}
puts "  Decrypted: '$decrypted'"

# Compare
if {$original_data eq $decrypted} {
    puts "  SUCCESS: Round-trip works correctly"
} else {
    puts "  FAIL: Data mismatch"
    puts "    Original length: [string length $original_data]"
    puts "    Decrypted length: [string length $decrypted]"
    exit 1
}

# Test 2: Binary data with null bytes
puts "\nTest 2: Binary data with null bytes"
set binary_data "Hello\0World\0Test"
puts "  Original: [string length $binary_data] bytes (contains null bytes)"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $binary_data]} err]
if {$rc != 0} {
    puts "  FAIL: Encryption failed - $err"
    exit 1
}
puts "  Encrypted: [string length $encrypted] bytes"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "  FAIL: Decryption failed - $err"
    exit 1
}
puts "  Decrypted: [string length $decrypted] bytes"

# Compare
if {$binary_data eq $decrypted} {
    puts "  SUCCESS: Binary data round-trip works correctly"
} else {
    puts "  FAIL: Binary data mismatch"
    puts "    Original length: [string length $binary_data]"
    puts "    Decrypted length: [string length $decrypted]"
    exit 1
}

# Test 3: Unicode data
puts "\nTest 3: Unicode data"
set unicode_data "Hello, 世界! 🌍"
puts "  Original: '$unicode_data'"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $unicode_data]} err]
if {$rc != 0} {
    puts "  FAIL: Encryption failed - $err"
    exit 1
}
puts "  Encrypted: [string length $encrypted] bytes"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "  FAIL: Decryption failed - $err"
    exit 1
}
puts "  Decrypted: '$decrypted'"

# Compare
if {$unicode_data eq $decrypted} {
    puts "  SUCCESS: Unicode data round-trip works correctly"
} else {
    puts "  FAIL: Unicode data mismatch"
    exit 1
}

# Test 4: Empty data
puts "\nTest 4: Empty data"
set empty_data ""
puts "  Original: [string length $empty_data] bytes"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $empty_data]} err]
if {$rc != 0} {
    puts "  FAIL: Encryption failed - $err"
    exit 1
}
puts "  Encrypted: [string length $encrypted] bytes"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "  FAIL: Decryption failed - $err"
    exit 1
}
puts "  Decrypted: [string length $decrypted] bytes"

# Compare
if {$empty_data eq $decrypted} {
    puts "  SUCCESS: Empty data round-trip works correctly"
} else {
    puts "  FAIL: Empty data mismatch"
    exit 1
}

# Test 5: Large data
puts "\nTest 5: Large data"
set large_data [string repeat "A" 10000]
puts "  Original: [string length $large_data] bytes"

# Encrypt
set rc [catch {set encrypted [tossl::pbe::encrypt $algorithm $password $salt $large_data]} err]
if {$rc != 0} {
    puts "  FAIL: Encryption failed - $err"
    exit 1
}
puts "  Encrypted: [string length $encrypted] bytes"

# Decrypt
set rc [catch {set decrypted [tossl::pbe::decrypt $algorithm $password $salt $encrypted]} err]
if {$rc != 0} {
    puts "  FAIL: Decryption failed - $err"
    exit 1
}
puts "  Decrypted: [string length $decrypted] bytes"

# Compare
if {$large_data eq $decrypted} {
    puts "  SUCCESS: Large data round-trip works correctly"
} else {
    puts "  FAIL: Large data mismatch"
    exit 1
}

puts "\n🎉 ALL TESTS PASSED! PBE implementation is now working correctly."
puts "The strlen() bug has been successfully fixed."
puts "Both encryption and decryption now handle binary data properly." 