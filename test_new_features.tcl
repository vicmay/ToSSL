#!/usr/bin/env tclsh

;# Test script for new TOSSL high priority features
;# This tests the additional hash algorithms, hash streaming, cipher support, and SSL enhancements

package require tossl

puts "=== Testing New TOSSL High Priority Features ===\n"

;# Test 1: Additional Hash Algorithms
puts "1. Testing Additional Hash Algorithms:"
set test_data "Hello, World!"
puts "   Test data: $test_data"

set new_algorithms {
    ripemd256 ripemd320 blake2b256 blake2b512 blake2s256 sm3
}

foreach alg $new_algorithms {
    if {[catch {tossl::digest -alg $alg $test_data} result]} {
        puts "   $alg: NOT SUPPORTED ($result)"
    } else {
        puts "   $alg: $result"
    }
}

;# Test 2: Hash Streaming for Large Files
puts "\n2. Testing Hash Streaming:"
set test_file "testdata.txt"
set test_content [string repeat "This is a test file for hash streaming functionality.\n" 1000]
set f [open $test_file w]
puts $f $test_content
close $f

foreach alg {sha256 sha512} {
    if {[catch {tossl::digest::stream -alg $alg -file $test_file} result]} {
        puts "   $alg streaming: ERROR ($result)"
    } else {
        puts "   $alg streaming: $result"
    }
}

;# Test 3: Hash Comparison
puts "\n3. Testing Hash Comparison:"
set hash1 [tossl::digest -alg sha256 "Hello"]
set hash2 [tossl::digest -alg sha256 "Hello"]
set hash3 [tossl::digest -alg sha256 "World"]

puts "   Comparing identical hashes: [tossl::digest::compare $hash1 $hash2]"
puts "   Comparing different hashes: [tossl::digest::compare $hash1 $hash3]"

;# Test 4: Available Hash Algorithms
puts "\n4. Available Hash Algorithms:"
if {[catch {tossl::digest::list} result]} {
    puts "   ERROR: $result"
} else {
    puts "   Supported algorithms: $result"
}

;# Test 5: Cipher Information and Listing
puts "\n5. Testing Cipher Support:"
if {[catch {tossl::cipher::list} result]} {
    puts "   ERROR listing ciphers: $result"
} else {
    puts "   Available ciphers: [llength $result] algorithms"
    puts "   Sample ciphers: [lrange $result 0 4]"
}

;# Test specific cipher types
foreach mode {cbc gcm ecb} {
    if {[catch {tossl::cipher::list -type $mode} result]} {
        puts "   $mode ciphers: ERROR ($result)"
    } else {
        puts "   $mode ciphers: [llength $result] algorithms"
    }
}

;# Test 6: Random Key and IV Generation
puts "\n6. Testing Random Key/IV Generation:"
set test_cipher "aes-256-cbc"

if {[catch {tossl::rand::key -alg $test_cipher} key]} {
    puts "   Key generation: ERROR ($key)"
} else {
    puts "   Generated key: [string length $key] bytes"
}

if {[catch {tossl::rand::iv -alg $test_cipher} iv]} {
    puts "   IV generation: ERROR ($iv)"
} else {
    puts "   Generated IV: [string length $iv] bytes"
}

;# Test 7: Enhanced Encryption/Decryption
puts "\n7. Testing Enhanced Encryption:"
set plaintext "Secret message for encryption testing"
set test_ciphers {aes-256-cbc aes-128-gcm chacha20}

foreach cipher $test_ciphers {
    if {[catch {
        set key [tossl::rand::key -alg $cipher]
        set iv [tossl::rand::iv -alg $cipher]
        set encrypted [tossl::encrypt -alg $cipher -key $key -iv $iv $plaintext]
        
        if {[string match "*gcm*" $cipher]} {
            # GCM returns a dict with ciphertext and tag
            set ciphertext [dict get $encrypted ciphertext]
            set tag [dict get $encrypted tag]
            set decrypted [tossl::decrypt -alg $cipher -key $key -iv $iv $ciphertext -tag $tag]
        } else {
            set decrypted [tossl::decrypt -alg $cipher -key $key -iv $iv $encrypted]
        }
        
        if {$decrypted eq $plaintext} {
            puts "   $cipher: SUCCESS"
        } else {
            puts "   $cipher: FAILED (decryption mismatch)"
        }
    } result]} {
        puts "   $cipher: ERROR ($result)"
    }
}

;# Test 8: SSL/TLS Enhanced Context
puts "\n8. Testing Enhanced SSL Context:"
if {[catch {
    # Create a self-signed certificate for testing
    set key [tossl::rsa::generate -bits 2048]
    set cert [tossl::x509::create -key $key -subject "/CN=test.example.com" -days 365]
    
    # Write to temporary files
    set key_file "test_key.pem"
    set cert_file "test_cert.pem"
    
    set f [open $key_file w]
    puts $f $key
    close $f
    
    set f [open $cert_file w]
    puts $f $cert
    close $f
    
    # Create SSL context with enhanced features
    set ctx [tossl::ssl::context -cert $cert_file -key $key_file -verify 0]
    puts "   SSL context created: $ctx"
    
    # Clean up
    tossl::ssl::context_free $ctx
    file delete $key_file $cert_file
    
} result]} {
    puts "   SSL context: ERROR ($result)"
}

;# Test 9: Cipher Information
puts "\n9. Testing Cipher Information:"
set test_ciphers {aes-256-cbc aes-128-gcm chacha20 des-cbc}

foreach cipher $test_ciphers {
    if {[catch {tossl::cipher::info $cipher} info]} {
        puts "   $cipher: ERROR ($info)"
    } else {
        puts "   $cipher: [dict get $info block_size] block, [dict get $info key_length] key, [dict get $info mode] mode"
    }
}

;# Test 10: Performance Test - Large File Hashing
puts "\n10. Performance Test - Large File Hashing:"
set large_file "large_test.dat"
set large_content [string repeat "Large file content for performance testing.\n" 10000]
set f [open $large_file w]
puts $f $large_content
close $f

set start_time [clock milliseconds]
if {[catch {tossl::digest::stream -alg sha256 -file $large_file} result]} {
    puts "   Large file hash: ERROR ($result)"
} else {
    set end_time [clock milliseconds]
    set duration [expr {$end_time - $start_time}]
    puts "   Large file hash: $result (${duration}ms)"
}

;# Cleanup
file delete testdata.txt large_test.dat

puts "\n=== Testing Complete ===" 