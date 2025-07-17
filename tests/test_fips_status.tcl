# Test for ::tossl::fips::status
load ./libtossl.so

puts "Testing FIPS status..."
set status [tossl::fips::status]
puts "FIPS status: $status"

if {![regexp {FIPS provider available: (yes|no), FIPS mode: (enabled|disabled)} $status]} {
    puts "FAIL: Unexpected FIPS status format"
    exit 1
}
puts "FIPS status format OK"

;# Error: extra argument
if {[catch {tossl::fips::status extra} err]} {
    puts "Error on extra argument: $err"
} else {
    puts "FAIL: Extra argument did not error"
    exit 1
}

puts "All ::tossl::fips::status tests passed" 