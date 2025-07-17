# Test for ::tossl::oauth2::validate_state
load ./libtossl.so

puts "Testing state validation: matching states..."
set state [tossl::oauth2::generate_state]
set valid [tossl::oauth2::validate_state $state $state]
puts "Result: $valid"
if {!$valid} {
    puts "FAIL: Matching states should be valid"
    exit 1
}
puts "State validation (match): OK"

puts "Testing state validation: non-matching states..."
set state1 [tossl::oauth2::generate_state]
set state2 [tossl::oauth2::generate_state]
set valid [tossl::oauth2::validate_state $state1 $state2]
puts "Result: $valid"
if {$valid} {
    puts "FAIL: Non-matching states should be invalid"
    exit 1
}
puts "State validation (non-match): OK"

puts "Testing state validation: error on missing args..."
set rc [catch {tossl::oauth2::validate_state} result]
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "State validation missing args: OK"

puts "Testing state validation: error on too many args..."
set rc [catch {tossl::oauth2::validate_state foo bar baz} result]
if {$rc == 0} {
    puts "FAIL: Too many args did not error"
    exit 1
}
puts "State validation too many args: OK" 