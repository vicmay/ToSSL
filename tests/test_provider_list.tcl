# Test for ::tossl::provider::list
load ./libtossl.so

puts "Testing provider list basic..."
set providers [tossl::provider::list]
puts "Providers: $providers"
if {$providers eq ""} {
    puts "FAIL: Provider list is empty"
    exit 1
}
puts "Provider list basic: OK"

puts "Testing provider list contains default..."
if {[string first "default" $providers] < 0} {
    puts "FAIL: Provider list missing 'default'"
    exit 1
}
puts "Provider list contains default: OK"

puts "Testing provider list contains legacy..."
if {[string first "legacy" $providers] < 0} {
    puts "FAIL: Provider list missing 'legacy'"
    exit 1
}
puts "Provider list contains legacy: OK"

puts "Testing error: wrong arg count..."
if {[catch {tossl::provider::list foo} err]} {
    puts "Error on extra arg: $err"
} else {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::provider::list tests passed" 