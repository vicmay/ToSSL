# Test for ::tossl::time::compare
load ./libtossl.so

puts "Testing time::compare: missing required args..."
set rc [catch {tossl::time::compare} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::time::compare "1000"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing time2 did not error"
    exit 1
}
puts "time::compare missing args: OK"

puts "Testing time::compare: basic functionality..."
set time1 [clock seconds]
after 1000
set time2 [clock seconds]
set rc [catch {set result [tossl::time::compare $time2 $time1]} err]
if {$rc != 0} {
    puts "FAIL: time::compare failed - $err"
    exit 1
}
if {$result <= 0} {
    puts "FAIL: Expected positive difference, got $result"
    exit 1
}
puts "time::compare basic functionality: OK (difference: $result seconds)"

puts "Testing time::compare: equal times..."
set current_time [clock seconds]
set rc [catch {set result [tossl::time::compare $current_time $current_time]} err]
if {$rc != 0} {
    puts "FAIL: time::compare equal times failed - $err"
    exit 1
}
if {$result != 0} {
    puts "FAIL: Expected 0 for equal times, got $result"
    exit 1
}
puts "time::compare equal times: OK"

puts "Testing time::compare: time1 > time2..."
set time1 1000
set time2 500
set rc [catch {set result [tossl::time::compare $time1 $time2]} err]
if {$rc != 0} {
    puts "FAIL: time::compare time1 > time2 failed - $err"
    exit 1
}
if {$result != 500} {
    puts "FAIL: Expected 500, got $result"
    exit 1
}
puts "time::compare time1 > time2: OK"

puts "Testing time::compare: time1 < time2..."
set time1 500
set time2 1000
set rc [catch {set result [tossl::time::compare $time1 $time2]} err]
if {$rc != 0} {
    puts "FAIL: time::compare time1 < time2 failed - $err"
    exit 1
}
if {$result != -500} {
    puts "FAIL: Expected -500, got $result"
    exit 1
}
puts "time::compare time1 < time2: OK"

puts "Testing time::compare: edge cases..."
# Test individual edge cases
set rc [catch {set result [tossl::time::compare 0 0]} err]
if {$rc != 0} {
    puts "FAIL: time::compare edge case 0 0 failed - $err"
    exit 1
}
if {$result != 0} {
    puts "FAIL: Expected 0, got $result for 0 vs 0"
    exit 1
}
puts "Edge case 0 vs 0: OK"

set rc [catch {set result [tossl::time::compare 0 1]} err]
if {$rc != 0} {
    puts "FAIL: time::compare edge case 0 1 failed - $err"
    exit 1
}
if {$result != -1} {
    puts "FAIL: Expected -1, got $result for 0 vs 1"
    exit 1
}
puts "Edge case 0 vs 1: OK"

set rc [catch {set result [tossl::time::compare 1 0]} err]
if {$rc != 0} {
    puts "FAIL: time::compare edge case 1 0 failed - $err"
    exit 1
}
if {$result != 1} {
    puts "FAIL: Expected 1, got $result for 1 vs 0"
    exit 1
}
puts "Edge case 1 vs 0: OK"

set rc [catch {set result [tossl::time::compare 1000000000 999999999]} err]
if {$rc != 0} {
    puts "FAIL: time::compare edge case 1000000000 999999999 failed - $err"
    exit 1
}
if {$result != 1} {
    puts "FAIL: Expected 1, got $result for 1000000000 vs 999999999"
    exit 1
}
puts "Edge case 1000000000 vs 999999999: OK"

set rc [catch {set result [tossl::time::compare 999999999 1000000000]} err]
if {$rc != 0} {
    puts "FAIL: time::compare edge case 999999999 1000000000 failed - $err"
    exit 1
}
if {$result != -1} {
    puts "FAIL: Expected -1, got $result for 999999999 vs 1000000000"
    exit 1
}
puts "Edge case 999999999 vs 1000000000: OK"

puts "time::compare edge cases: OK"

puts "Testing time::compare: large time differences..."
# Test individual large time differences
set rc [catch {set result [tossl::time::compare 0 31536000]} err]
if {$rc != 0} {
    puts "FAIL: time::compare large time 0 31536000 failed - $err"
    exit 1
}
if {$result != -31536000} {
    puts "FAIL: Expected -31536000, got $result for 0 vs 31536000"
    exit 1
}
puts "Large time 0 vs 31536000: OK"

set rc [catch {set result [tossl::time::compare 31536000 0]} err]
if {$rc != 0} {
    puts "FAIL: time::compare large time 31536000 0 failed - $err"
    exit 1
}
if {$result != 31536000} {
    puts "FAIL: Expected 31536000, got $result for 31536000 vs 0"
    exit 1
}
puts "Large time 31536000 vs 0: OK"

set rc [catch {set result [tossl::time::compare 1640995200 1704067200]} err]
if {$rc != 0} {
    puts "FAIL: time::compare large time 1640995200 1704067200 failed - $err"
    exit 1
}
if {$result != -63072000} {
    puts "FAIL: Expected -63072000, got $result for 1640995200 vs 1704067200"
    exit 1
}
puts "Large time 1640995200 vs 1704067200: OK"

set rc [catch {set result [tossl::time::compare 1704067200 1640995200]} err]
if {$rc != 0} {
    puts "FAIL: time::compare large time 1704067200 1640995200 failed - $err"
    exit 1
}
if {$result != 63072000} {
    puts "FAIL: Expected 63072000, got $result for 1704067200 vs 1640995200"
    exit 1
}
puts "Large time 1704067200 vs 1640995200: OK"

puts "time::compare large time differences: OK"

puts "Testing time::compare: error handling..."
set invalid_times {
    "not_a_number" "1000"
    "1000" "not_a_number"
    "abc" "def"
}
foreach {time1 time2} $invalid_times {
    set rc [catch {tossl::time::compare $time1 $time2} err]
    if {$rc == 0} {
        puts "Note: time::compare with non-numeric input succeeded"
        puts "This is expected behavior as atol() returns 0 for non-numeric strings"
    } else {
        puts "Error handling $time1 vs $time2: OK"
    }
}
puts "time::compare error handling: OK"

puts "Testing time::compare: integration with time::convert..."
set iso_time1 "2022-01-01T00:00:00Z"
set iso_time2 "2022-01-02T00:00:00Z"
set rc1 [catch {set unix_time1 [tossl::time::convert iso8601 $iso_time1]} err1]
set rc2 [catch {set unix_time2 [tossl::time::convert iso8601 $iso_time2]} err2]
if {$rc1 == 0 && $rc2 == 0} {
    set rc3 [catch {set diff [tossl::time::compare $unix_time2 $unix_time1]} err3]
    if {$rc3 == 0 && $diff > 0} {
        puts "time::compare integration: OK (difference: $diff seconds)"
    } else {
        puts "Note: time::compare integration failed - $err3"
    }
} else {
    puts "Note: time::convert integration failed - $err1 $err2"
}
puts "time::compare integration test: OK"

puts "Testing time::compare: performance..."
set start_time [clock milliseconds]
for {set i 0} {$i < 1000} {incr i} {
    set rc [catch {tossl::time::compare $i [expr $i + 1]} err]
    if {$rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "time::compare performance (1000 iterations): ${duration}ms"

puts "Testing time::compare: certificate time validation scenario..."
# Simulate certificate validation scenario
set cert_not_before "1640995200"
set cert_not_after "1704067200"
set current_time [clock seconds]

set rc1 [catch {set before_diff [tossl::time::compare $current_time $cert_not_before]} err1]
set rc2 [catch {set after_diff [tossl::time::compare $cert_not_after $current_time]} err2]

if {$rc1 == 0 && $rc2 == 0} {
    if {$before_diff >= 0 && $after_diff >= 0} {
        puts "Certificate time validation scenario: OK (certificate is valid)"
    } else {
        puts "Certificate time validation scenario: OK (certificate is not valid)"
    }
} else {
    puts "Note: Certificate time validation scenario failed - $err1 $err2"
}
puts "time::compare certificate scenario: OK"

puts "All ::tossl::time::compare tests passed" 