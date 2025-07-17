# Test for ::tossl::json::parse
load ./libtossl.so

puts "Testing JSON parse to dict..."
set json { {"foo":"bar","baz":42,"qux":["a","b","c","d"]} }
set dict [tossl::json::parse $json]
puts "DICT: $dict"
if {[dict get $dict foo] ne "bar" || [dict get $dict baz] ne 42} {
    puts "FAIL: JSON to dict did not include expected keys"
    exit 1
}
puts "JSON to dict: OK"

puts "Testing JSON parse to list..."
set json {[1,2,3,4]}
set list [tossl::json::parse $json]
puts "LIST: $list"
if {[lindex $list 0] != 1 || [lindex $list 3] != 4} {
    puts "FAIL: JSON to list did not include expected values"
    exit 1
}
puts "JSON to list: OK"

puts "Testing JSON parse to nested dict..."
set json { {"outer":{"inner":{"x":1,"y":2}}} }
set nested [tossl::json::parse $json]
puts "NESTED: $nested"
if {[dict get [dict get $nested outer] inner] eq ""} {
    puts "FAIL: Nested JSON to dict did not include expected keys"
    exit 1
}
puts "Nested JSON to dict: OK"

puts "Testing JSON parse to boolean..."
set val [tossl::json::parse true]
if {$val ne 1} {
    puts "FAIL: JSON true to Tcl boolean"
    exit 1
}
set val [tossl::json::parse false]
if {$val ne 0} {
    puts "FAIL: JSON false to Tcl boolean"
    exit 1
}
puts "Boolean JSON to Tcl: OK"

puts "Testing JSON parse to number..."
set val [tossl::json::parse 123]
if {$val ne 123} {
    puts "FAIL: JSON number to Tcl"
    exit 1
}
puts "Number JSON to Tcl: OK"

puts "Testing JSON parse to string..."
set val [tossl::json::parse {"hello world"}]
if {$val ne "hello world"} {
    puts "FAIL: JSON string to Tcl"
    exit 1
}
puts "String JSON to Tcl: OK"

puts "Testing error: wrong arg count..."
if {[catch {tossl::json::parse} err]} {
    puts "Error on missing arg: $err"
} else {
    puts "FAIL: Missing arg did not error"
    exit 1
}
if {[catch {tossl::json::parse a b} err]} {
    puts "Error on extra arg: $err"
} else {
    puts "FAIL: Extra arg did not error"
    exit 1
}
puts "Testing error: invalid JSON..."
if {[catch {tossl::json::parse {not a json}} err]} {
    puts "Error on invalid JSON: $err"
} else {
    puts "FAIL: Invalid JSON did not error"
    exit 1
}
puts "All ::tossl::json::parse tests passed" 