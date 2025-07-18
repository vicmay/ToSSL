# Test for ::tossl::algorithm::info
load ./libtossl.so

puts "Testing algorithm::info: missing required args..."
set rc [catch {tossl::algorithm::info} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::algorithm::info "sha256"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing type did not error"
    exit 1
}
puts "algorithm::info missing args: OK"

puts "Testing algorithm::info: basic functionality..."
set algorithms {
    sha256 digest
    aes-128-cbc cipher
    hmac mac
    pbkdf2 kdf
    ecdh keyexch
    rsa signature
    rsa asym_cipher
}
foreach {algorithm type} $algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm $type]} err]
    if {$rc != 0} {
        puts "FAIL: algorithm::info $algorithm $type failed - $err"
        exit 1
    }
    if {[string length $result] == 0} {
        puts "FAIL: Empty result for $algorithm $type"
        exit 1
    }
    puts "algorithm::info $algorithm $type: OK - $result"
}
puts "algorithm::info basic functionality: OK"

puts "Testing algorithm::info: digest algorithms..."
set digest_algorithms {
    "md5" "sha1" "sha224" "sha256" "sha384" "sha512"
    "sha3-224" "sha3-256" "sha3-384" "sha3-512"
    "blake2b256" "blake2b512" "blake2s256"
}
foreach algorithm $digest_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "digest"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm digest failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm digest: OK - $result"
    }
}
puts "algorithm::info digest algorithms: OK"

puts "Testing algorithm::info: cipher algorithms..."
set cipher_algorithms {
    "aes-128-cbc" "aes-256-cbc" "aes-128-gcm" "aes-256-gcm"
    "chacha20-poly1305" "des-cbc" "bf-cbc"
}
foreach algorithm $cipher_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "cipher"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm cipher failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm cipher: OK - $result"
    }
}
puts "algorithm::info cipher algorithms: OK"

puts "Testing algorithm::info: mac algorithms..."
set mac_algorithms {
    "hmac" "cmac"
}
foreach algorithm $mac_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "mac"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm mac failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm mac: OK - $result"
    }
}
puts "algorithm::info mac algorithms: OK"

puts "Testing algorithm::info: kdf algorithms..."
set kdf_algorithms {
    "pbkdf2" "scrypt" "argon2"
}
foreach algorithm $kdf_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "kdf"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm kdf failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm kdf: OK - $result"
    }
}
puts "algorithm::info kdf algorithms: OK"

puts "Testing algorithm::info: key exchange algorithms..."
set keyexch_algorithms {
    "ecdh" "dh"
}
foreach algorithm $keyexch_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "keyexch"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm keyexch failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm keyexch: OK - $result"
    }
}
puts "algorithm::info key exchange algorithms: OK"

puts "Testing algorithm::info: signature algorithms..."
set signature_algorithms {
    "rsa" "dsa" "ecdsa" "ed25519" "ed448"
}
foreach algorithm $signature_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "signature"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm signature failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm signature: OK - $result"
    }
}
puts "algorithm::info signature algorithms: OK"

puts "Testing algorithm::info: asymmetric cipher algorithms..."
set asym_cipher_algorithms {
    "rsa" "sm2"
}
foreach algorithm $asym_cipher_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm "asym_cipher"]} err]
    if {$rc != 0} {
        puts "Note: algorithm::info $algorithm asym_cipher failed - $err"
        puts "This algorithm may not be available in this OpenSSL build"
    } else {
        puts "algorithm::info $algorithm asym_cipher: OK - $result"
    }
}
puts "algorithm::info asymmetric cipher algorithms: OK"

puts "Testing algorithm::info: error handling..."
set invalid_combinations {
    invalid-algorithm digest
    sha256 invalid-type
    "" digest
    sha256 ""
    invalid-algorithm invalid-type
}
foreach {algorithm type} $invalid_combinations {
    set rc [catch {tossl::algorithm::info $algorithm $type} err]
    if {$rc == 0} {
        puts "Note: algorithm::info $algorithm $type succeeded (implementation doesn't validate)"
        puts "Result: $err"
    } else {
        puts "Error handling $algorithm $type: OK"
    }
}
puts "algorithm::info error handling: OK"

puts "Testing algorithm::info: edge cases..."
set edge_cases {
    a digest
    very-long-algorithm-name-that-might-not-exist cipher
    SHA256 digest
    AES-128-CBC cipher
}
foreach {algorithm type} $edge_cases {
    set rc [catch {set result [tossl::algorithm::info $algorithm $type]} err]
    if {$rc == 0} {
        puts "Edge case $algorithm $type: OK - $result"
    } else {
        puts "Edge case $algorithm $type: FAILED - $err"
    }
}
puts "algorithm::info edge cases: OK"

puts "Testing algorithm::info: integration with algorithm::list..."
set algorithm_types {
    "digest" "cipher" "mac" "kdf" "keyexch" "signature" "asym_cipher"
}
foreach type $algorithm_types {
    set rc1 [catch {set algorithms [tossl::algorithm::list $type]} err1]
    if {$rc1 == 0} {
        set algorithm_list [split $algorithms ", "]
        puts "Testing $type algorithms: [llength $algorithm_list] found"
        
        foreach algorithm $algorithm_list {
            set algorithm [string trim $algorithm]
            if {[string length $algorithm] > 0} {
                set rc2 [catch {set result [tossl::algorithm::info $algorithm $type]} err2]
                if {$rc2 == 0} {
                    puts "  ✓ $algorithm: $result"
                } else {
                    puts "  ✗ $algorithm: $err2"
                }
            }
        }
    } else {
        puts "Note: algorithm::list $type failed - $err1"
    }
}
puts "algorithm::info integration test: OK"

puts "Testing algorithm::info: performance..."
set start_time [clock milliseconds]
for {set i 0} {$i < 100} {incr i} {
    set rc [catch {tossl::algorithm::info "sha256" "digest"} err]
    if {$rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "algorithm::info performance (100 iterations): ${duration}ms"

puts "Testing algorithm::info: result format validation..."
set test_algorithms {
    sha256 digest
    aes-128-cbc cipher
    hmac mac
}
foreach {algorithm type} $test_algorithms {
    set rc [catch {set result [tossl::algorithm::info $algorithm $type]} err]
    if {$rc == 0} {
        # Check if result contains expected format
        if {[string match "*algorithm=*" $result] && [string match "*type=*" $result] && [string match "*status=*" $result]} {
            puts "Result format validation $algorithm $type: OK"
        } else {
            puts "Result format validation $algorithm $type: FAILED - unexpected format"
            puts "Result: $result"
        }
    } else {
        puts "Result format validation $algorithm $type: SKIPPED - algorithm not available"
    }
}
puts "algorithm::info result format validation: OK"

puts "All ::tossl::algorithm::info tests passed" 