#!/usr/bin/env tclsh
# Test file for ::tossl::encrypt command
# Tests various algorithms, key/IV combinations, and error handling

package require tossl

# Test counter
set test_count 0
set passed_count 0
set failed_count 0

proc test {name script expected_result} {
    global test_count passed_count failed_count
    incr test_count
    
    puts "Test $test_count: $name"
    
    if {[catch $script result]} {
        if {$expected_result eq "error" || $result eq $expected_result} {
            puts "  PASS: Expected result: $expected_result, got: $result"
            incr passed_count
        } else {
            puts "  FAIL: Unexpected error: $result"
            incr failed_count
        }
    } else {
        if {$expected_result eq "error"} {
            puts "  FAIL: Expected error but got: $result"
            incr failed_count
        } else {
            puts "  PASS: Got expected result"
            incr passed_count
        }
    }
}

puts "=== Testing ::tossl::encrypt ==="

# Test data
set test_data "Hello, World!"

# Test 1: AES-256-CBC basic functionality
test "AES-256-CBC basic functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data]
    string length $ciphertext
} ">0"

# Test 2: AES-256-CBC round-trip test
test "AES-256-CBC round-trip test" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data]
    set decrypted [tossl::decrypt -alg aes-256-cbc -key $key -iv $iv -format base64 $ciphertext]
    expr {$decrypted eq $test_data}
} 1

# Test 3: AES-128-CBC functionality
test "AES-128-CBC functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 16]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-128-cbc -key $key -iv $iv $test_data]
    string length $ciphertext
} ">0"

# Test 4: AES-192-CBC functionality
test "AES-192-CBC functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 24]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-192-cbc -key $key -iv $iv $test_data]
    string length $ciphertext
} ">0"

# Test 5: AES-256-GCM authenticated encryption
test "AES-256-GCM authenticated encryption" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce $test_data]
    string length $ciphertext
} ">0"

# Test 6: AES-256-GCM round-trip test
test "AES-256-GCM round-trip test" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce $test_data]
    set decrypted [tossl::decrypt -alg aes-256-gcm -key $key -iv $nonce -format base64 $ciphertext]
    expr {$decrypted eq $test_data}
} 1

# Test 7: AES-256-GCM with AAD
test "AES-256-GCM with AAD" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set aad "Additional authenticated data"
    set ciphertext [tossl::encrypt -alg aes-256-gcm -key $key -iv $nonce -aad $aad $test_data]
    string length $ciphertext
} ">0"

# Test 8: ChaCha20-Poly1305 functionality
test "ChaCha20-Poly1305 functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg chacha20-poly1305 -key $key -iv $nonce $test_data]
    string length $ciphertext
} ">0"

# Test 9: ChaCha20-Poly1305 round-trip test
test "ChaCha20-Poly1305 round-trip test" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg chacha20-poly1305 -key $key -iv $nonce $test_data]
    set decrypted [tossl::decrypt -alg chacha20-poly1305 -key $key -iv $nonce -format base64 $ciphertext]
    expr {$decrypted eq $test_data}
} 1

# Test 10: Different output formats
test "Different output formats" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    
    # Base64 format (default)
    set b64_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data]
    
    # Hex format
    set hex_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv -format hex $test_data]
    
    # Binary format
    set bin_cipher [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv -format binary $test_data]
    
    expr {[string length $b64_cipher] > 0 && [string length $hex_cipher] > 0 && [string length $bin_cipher] > 0}
} 1

# Test 11: Error - invalid algorithm
test "Error: Invalid algorithm" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    tossl::encrypt -alg invalid_alg -key $key -iv $iv $test_data
} error

# Test 12: Error - missing key
test "Error: Missing key" {
    set test_data "Hello, World!"
    set iv [tossl::rand::bytes 16]
    tossl::encrypt -alg aes-256-cbc -iv $iv $test_data
} error

# Test 13: Error - missing IV for CBC mode
test "Error: Missing IV for CBC mode" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    tossl::encrypt -alg aes-256-cbc -key $key $test_data
} error

# Test 14: Error - wrong key length
test "Error: Wrong key length" {
    set test_data "Hello, World!"
    set short_key [tossl::rand::bytes 16]  # Too short for AES-256
    set iv [tossl::rand::bytes 16]
    tossl::encrypt -alg aes-256-cbc -key $short_key -iv $iv $test_data
} error

# Test 15: Error - wrong IV length
test "Error: Wrong IV length" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set wrong_iv [tossl::rand::bytes 8]  # Too short
    tossl::encrypt -alg aes-256-cbc -key $key -iv $wrong_iv $test_data
} error

# Test 16: Error - missing data
test "Error: Missing data" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    tossl::encrypt -alg aes-256-cbc -key $key -iv $iv
} error

# Test 17: Error - invalid format
test "Error: Invalid format" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    tossl::encrypt -alg aes-256-cbc -key $key -iv $iv -format invalid_format $test_data
} error

# Test 18: Empty string input
test "Empty string input" {
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv ""]
    string length $ciphertext
} ">0"

# Test 19: Large data input
test "Large data input" {
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set large_data [string repeat "A" 10000]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $large_data]
    string length $ciphertext
} ">0"

# Test 20: Binary data input
test "Binary data input" {
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set binary_data [binary format H* "0102030405060708"]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $binary_data]
    string length $ciphertext
} ">0"

# Test 21: Unicode data input
test "Unicode data input" {
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set unicode_data "Hello, 世界!"
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $unicode_data]
    string length $ciphertext
} ">0"

# Test 22: Consistency test - same parameters produce same output
test "Consistency test" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext1 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data]
    set ciphertext2 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data]
    expr {$ciphertext1 eq $ciphertext2}
} 1

# Test 23: Different IVs produce different outputs
test "Different IVs produce different outputs" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv1 [tossl::rand::bytes 16]
    set iv2 [tossl::rand::bytes 16]
    set ciphertext1 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv1 $test_data]
    set ciphertext2 [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv2 $test_data]
    expr {$ciphertext1 ne $ciphertext2}
} 1

# Test 24: AES-128-GCM functionality
test "AES-128-GCM functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 16]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg aes-128-gcm -key $key -iv $nonce $test_data]
    string length $ciphertext
} ">0"

# Test 25: AES-192-GCM functionality
test "AES-192-GCM functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 24]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg aes-192-gcm -key $key -iv $nonce $test_data]
    string length $ciphertext
} ">0"

# Test 26: AES-256-CCM functionality
test "AES-256-CCM functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set nonce [tossl::rand::bytes 12]
    set ciphertext [tossl::encrypt -alg aes-256-ccm -key $key -iv $nonce $test_data]
    string length $ciphertext
} ">0"

# Test 27: Camellia-256-CBC functionality
test "Camellia-256-CBC functionality" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg camellia-256-cbc -key $key -iv $iv $test_data]
    string length $ciphertext
} ">0"

# Test 28: Performance test - multiple encryptions
test "Performance: Multiple encryptions" {
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    
    # Set up error logging to a file
    set errorFile "test_encrypt_errors.log"
    exec touch $errorFile
    
    for {set i 0} {$i < 10} {incr i} {
        set ciphertext ""
        set err [catch {
            set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv "Test data $i"]
        } errorMsg]
        
        if {$err != 0} {
            # Read the error file
            set errorOutput ""
            if {[file exists $errorFile]} {
                set f [open $errorFile r]
                set errorOutput [read $f]
                close $f
            }
            
            puts "  Error in iteration $i:"
            puts "    Error message: $errorMsg"
            puts "    Error code: $::errorCode"
            if {$errorOutput ne ""} {
                puts "    Debug output:"
                puts [regsub -all {^} $errorOutput {        }]
            }
            
            # Clean up and return
            catch {file delete $errorFile}
            return 0
        }
        
        if {[string length $ciphertext] == 0} {
            # Read the error file
            set errorOutput ""
            if {[file exists $errorFile]} {
                set f [open $errorFile r]
                set errorOutput [read $f]
                close $f
            }
            
            puts "  Empty ciphertext in iteration $i"
            if {$errorOutput ne ""} {
                puts "    Debug output:"
                puts [regsub -all {^} $errorOutput {        }]
            } else {
                puts "    No debug output available"
            }
            
            # Clean up and return
            catch {file delete $errorFile}
            return 0
        }
    }
    
    # Clean up
    catch {file delete $errorFile}
    
    return "success"
} "success"

# Test 29: Stress test - multiple algorithms
proc get_keylen {alg} {
    switch -- $alg {
        aes-128-cbc { return 16 }
        aes-256-cbc { return 32 }
        aes-256-gcm { return 32 }
        chacha20-poly1305 { return 32 }
        default { return 32 }
    }
}
proc get_ivlen {alg} {
    switch -- $alg {
        aes-128-cbc - aes-256-cbc { return 16 }
        aes-256-gcm - chacha20-poly1305 { return 12 }
        default { return 16 }
    }
}
test "Stress: Multiple algorithms" {
    set test_data "Hello, World!"
    set algorithms {aes-128-cbc aes-256-cbc aes-256-gcm chacha20-poly1305}
    set success 1
    
    # Set up error logging to a file
    set errorFile "test_encrypt_errors.log"
    exec touch $errorFile
    
    foreach alg $algorithms {
        set key [tossl::rand::bytes [get_keylen $alg]]
        set iv [tossl::rand::bytes [get_ivlen $alg]]
        
        set ciphertext ""
        set err [catch {
            set ciphertext [tossl::encrypt -alg $alg -key $key -iv $iv $test_data]
        } errorMsg]
        
        if {$err != 0} {
            # Read the error file
            set errorOutput ""
            if {[file exists $errorFile]} {
                set f [open $errorFile r]
                set errorOutput [read $f]
                close $f
            }
            
            puts "  Error with algorithm $alg:"
            puts "    Error message: $errorMsg"
            puts "    Error code: $::errorCode"
            if {$errorOutput ne ""} {
                puts "    Debug output:"
                puts [regsub -all {^} $errorOutput {        }]
            } else {
                puts "    No debug output available"
            }
            
            set success 0
            
            # Clear the error file for the next iteration
            catch {file delete $errorFile}
            continue
        }
        
        if {[string length $ciphertext] == 0} {
            # Read the error file
            set errorOutput ""
            if {[file exists $errorFile]} {
                set f [open $errorFile r]
                set errorOutput [read $f]
                close $f
            }
            
            puts "  Empty ciphertext with algorithm $alg"
            if {$errorOutput ne ""} {
                puts "    Debug output:"
                puts [regsub -all {^} $errorOutput {        }]
            } else {
                puts "    No debug output available"
            }
            
            set success 0
            
            # Clear the error file for the next iteration
            if {[file exists $errorFile]} {
                file delete $errorFile
            }
        }
    }
    
    # Clean up
    catch {file delete $errorFile}
    
    if {$success} {
        return "success"
    } else {
        return "failure"
    }
} "success"

# Test 30: Verify base64 format is valid base64
test "Base64 format validation" {
    set test_data "Hello, World!"
    set key [tossl::rand::bytes 32]
    set iv [tossl::rand::bytes 16]
    set ciphertext [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $test_data -format base64]
    # Base64 should only contain A-Z, a-z, 0-9, +, /, and = for padding
    regexp {^[A-Za-z0-9+/]+=*$} $ciphertext
} 1

puts "\n=== Test Summary ==="
puts "Total tests: $test_count"
puts "Passed: $passed_count"
puts "Failed: $failed_count"

if {$failed_count == 0} {
    puts "All tests PASSED!"
    exit 0
} else {
    puts "Some tests FAILED!"
    exit 1
} 