#!/usr/bin/env tclsh
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

puts "=== TOSSL JSON Test ==="

# Test 1: JSON parsing
puts "\n1. Testing JSON parsing..."
if {[catch {
    set json_str "{\"name\": \"test\", \"value\": 42, \"active\": true, \"score\": 3.14}"
    set parsed [tossl::json::parse $json_str]
    puts "   ✓ JSON parsing successful"
    puts "   Parsed dict: $parsed"
} err]} {
    puts "   ✗ JSON parsing failed: $err"
}

# Test 2: JSON generation
puts "\n2. Testing JSON generation..."
if {[catch {
    set test_dict [dict create name "test" value 42 active true score 3.14]
    set generated [tossl::json::generate $test_dict]
    puts "   ✓ JSON generation successful"
    puts "   Generated JSON: $generated"
} err]} {
    puts "   ✗ JSON generation failed: $err"
}

# Test 3: Round-trip test
puts "\n3. Testing round-trip (parse -> generate -> parse)..."
if {[catch {
    set original_json "{\"user\": \"john\", \"age\": 30, \"verified\": false}"
    set parsed [tossl::json::parse $original_json]
    set regenerated [tossl::json::generate $parsed]
    puts "   ✓ Round-trip test successful"
    puts "   Original: $original_json"
    puts "   Regenerated: $regenerated"
} err]} {
    puts "   ✗ Round-trip test failed: $err"
}

# Test 4: Error handling - invalid JSON
puts "\n4. Testing error handling (invalid JSON)..."
if {[catch {
    set result [tossl::json::parse "{invalid json}"]
    puts "   ✗ Should have failed but didn't"
} err]} {
    puts "   ✓ Error handling working: $err"
}

# Test 5: Complex JSON structure
puts "\n5. Testing complex JSON structure..."
if {[catch {
    #set complex_json {{\"users\": [{\"name\": \"alice\", \"age\": 25}, {\"name\": \"bob\", \"age\": 30}], \"total\": 2}}
    set complex_json {{"users": [{"name": "alice", "age": 25}, {"name": "bob", "age": 30}], "total": 2}}
    set parsed [tossl::json::parse $complex_json]
    puts "   ✓ Complex JSON parsing successful"
    puts "   Parsed: $parsed"
} err]} {
    puts "   ✗ Complex JSON test failed: $err"
    puts $complex_json
}

puts "\n=== JSON Test Complete ==="
puts "If all tests passed, json-c integration is working correctly!" 
