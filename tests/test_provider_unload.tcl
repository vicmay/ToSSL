# Test for ::tossl::provider::unload
load ./libtossl.so

puts "Testing provider unload: default..."
set rc [catch {tossl::provider::unload default} result]
puts "Result: $result"
if {$rc != 0 || $result ne "ok"} {
    puts "FAIL: Could not unload default provider"
    exit 1
}
puts "Provider unload default: OK"

puts "Testing provider unload: legacy..."
set rc [catch {tossl::provider::unload legacy} result]
puts "Result: $result"
if {$rc != 0 || $result ne "ok"} {
    puts "FAIL: Could not unload legacy provider"
    exit 1
}
puts "Provider unload legacy: OK"

puts "Testing provider unload: bogus (should fail)..."
set rc [catch {tossl::provider::unload bogus} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Unloading bogus provider did not error"
    exit 1
}
puts "Provider unload bogus: OK (error as expected)"

puts "Testing error: wrong arg count..."
set rc [catch {tossl::provider::unload} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing arg did not error"
    exit 1
}
set rc [catch {tossl::provider::unload default extra} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::provider::unload tests passed" 