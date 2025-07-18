# Test for ::tossl::pfs::test
load ./libtossl.so

puts "Testing pfs::test: basic functionality..."
set rc [catch {set result [tossl::pfs::test]} err]
if {$rc != 0} {
    puts "FAIL: pfs::test basic test failed - $err"
    exit 1
}
if {![dict exists $result pfs_ciphers] || ![dict exists $result non_pfs_ciphers]} {
    puts "FAIL: pfs::test result missing expected keys"
    exit 1
}
puts "pfs::test basic functionality: OK"
puts "PFS ciphers: [dict get $result pfs_ciphers]"
puts "Non-PFS ciphers: [dict get $result non_pfs_ciphers]"
puts "PFS supported: [dict get $result pfs_supported]"
puts "PFS recommended: [dict get $result pfs_recommended]"

puts "Testing pfs::test: error handling (extra argument)..."
set rc [catch {tossl::pfs::test extra} err]
if {$rc == 0} {
    puts "FAIL: pfs::test did not error on extra argument"
    exit 1
}
puts "pfs::test error handling: OK"

puts "Testing pfs::test: edge case (call multiple times)..."
set rc [catch {set result2 [tossl::pfs::test]} err2]
if {$rc != 0} {
    puts "FAIL: pfs::test failed on repeated call - $err2"
    exit 1
}
puts "pfs::test repeated call: OK"

puts "All ::tossl::pfs::test tests passed." 