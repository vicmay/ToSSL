# Test for ::tossl::provider::load
load ./libtossl.so

puts "Testing provider load: default..."
set rc [catch {tossl::provider::load default} result]
puts "Result: $result"
if {$rc != 0 || $result ne "ok"} {
    puts "FAIL: Could not load default provider"
    exit 1
}
puts "Provider load default: OK"

puts "Testing provider load: legacy..."
set rc [catch {tossl::provider::load legacy} result]
puts "Result: $result"
if {$rc != 0 || $result ne "ok"} {
    puts "FAIL: Could not load legacy provider"
    exit 1
}
puts "Provider load legacy: OK"

puts "Testing provider load: bogus (should fail)..."
set rc [catch {tossl::provider::load bogus} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Loading bogus provider did not error"
    exit 1
}
puts "Provider load bogus: OK (error as expected)"

puts "Testing error: wrong arg count..."
set rc [catch {tossl::provider::load} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing arg did not error"
    exit 1
}
set rc [catch {tossl::provider::load default extra} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::provider::load tests passed" 