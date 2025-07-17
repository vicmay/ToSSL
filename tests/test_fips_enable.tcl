# Test for ::tossl::fips::enable
load ./libtossl.so

puts "Testing FIPS enable..."
set enable_result [catch {tossl::fips::enable} err]
if {$enable_result} {
    if {$err eq "Failed to enable FIPS mode"} {
        puts "FIPS enable: Not available on this system (expected if FIPS provider not installed)"
    } else {
        puts "FAIL: FIPS enable failed: $err"
        exit 1
    }
} else {
    puts "FIPS enable: OK"
}

set status [tossl::fips::status]
puts "FIPS status after enable: $status"

if {![regexp {FIPS provider available: (yes|no), FIPS mode: (enabled|disabled)} $status]} {
    puts "FAIL: Unexpected FIPS status format after enable"
    exit 1
}

;# Error: extra argument
if {[catch {tossl::fips::enable extra} err]} {
    puts "Error on extra argument: $err"
} else {
    puts "FAIL: Extra argument did not error"
    exit 1
}

;# Try enabling again (should succeed, be idempotent, or fail as not available)
set repeat_result [catch {tossl::fips::enable} err2]
if {$repeat_result} {
    if {$err2 eq "Failed to enable FIPS mode"} {
        puts "FIPS enable (repeat): Not available (expected)"
    } else {
        puts "FIPS enable (repeat): $err2"
    }
} else {
    puts "FIPS enable (repeat): OK"
}

puts "All ::tossl::fips::enable tests passed" 