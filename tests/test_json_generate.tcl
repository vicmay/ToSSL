# Test for ::tossl::json::generate
load ./libtossl.so

puts "Testing JSON generate from dict..."
set dict {foo bar baz 42 qux {a b c d}}
set json [tossl::json::generate $dict]
puts "JSON: $json"
if {![string match *foo* $json] || ![string match *baz* $json]} {
    puts "FAIL: Dict to JSON did not include expected keys"
    exit 1
}
puts "Dict to JSON: OK"

puts "Testing JSON generate from list..."
set list {1 2 3 4}
set json [tossl::json::generate $list]
puts "JSON: $json"
if {![string match *1* $json] || ![string match *4* $json]} {
    puts "FAIL: List to JSON did not include expected values"
    exit 1
}
puts "List to JSON: OK"

puts "Testing JSON generate from nested dict..."
set nested {outer {inner {x 1 y 2}}}
set json [tossl::json::generate $nested]
puts "JSON: $json"
if {![string match *outer* $json] || ![string match *inner* $json]} {
    puts "FAIL: Nested dict to JSON did not include expected keys"
    exit 1
}
puts "Nested dict to JSON: OK"

puts "Testing JSON generate from boolean..."
set json [tossl::json::generate true]
puts "JSON: $json"
if {$json ne "true"} {
    puts "FAIL: Boolean true to JSON"
    exit 1
}
set json [tossl::json::generate false]
puts "JSON: $json"
if {$json ne "false"} {
    puts "FAIL: Boolean false to JSON"
    exit 1
}
puts "Boolean to JSON: OK"

puts "Testing JSON generate from number..."
set json [tossl::json::generate 123]
puts "JSON: $json"
if {$json ne "123"} {
    puts "FAIL: Number to JSON"
    exit 1
}
puts "Number to JSON: OK"

puts "Testing JSON generate from string..."
set json [tossl::json::generate "hello world"]
puts "JSON: $json"
if {$json ne "\"hello world\""} {
    puts "FAIL: String to JSON"
    exit 1
}
puts "String to JSON: OK"

puts "Testing error: wrong arg count..."
if {[catch {tossl::json::generate} err]} {
    puts "Error on missing arg: $err"
} else {
    puts "FAIL: Missing arg did not error"
    exit 1
}
if {[catch {tossl::json::generate a b} err]} {
    puts "Error on extra arg: $err"
} else {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "All ::tossl::json::generate tests passed" 