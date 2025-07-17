# Test for ::tossl::oauth2::generate_state
load ./libtossl.so

puts "Testing generate_state: normal case..."
set state1 [tossl::oauth2::generate_state]
puts "State1: $state1"
if {[string length $state1] != 64} {
    puts "FAIL: State length is not 64"
    exit 1
}
puts "generate_state normal: OK"

puts "Testing generate_state: uniqueness..."
set state2 [tossl::oauth2::generate_state]
if {$state1 eq $state2} {
    puts "FAIL: State values are not unique"
    exit 1
}
puts "generate_state uniqueness: OK"

puts "Testing generate_state: error on extra arg..."
set rc [catch {tossl::oauth2::generate_state foo} result]
if {$rc == 0} {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "generate_state extra arg: OK" 