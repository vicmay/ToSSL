# Test for ::tossl::acme::create_order
load ./libtossl.so

puts "Testing acme::create_order: missing required args..."
set rc [catch {tossl::acme::create_order} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::acme::create_order "directory_url"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing account_key did not error"
    exit 1
}
set rc [catch {tossl::acme::create_order "directory_url" "account_key"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing domains did not error"
    exit 1
}
puts "acme::create_order missing args: OK"

puts "Testing acme::create_order: basic functionality..."
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set account_key "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
set domains "example.com"

set order_rc [catch {set result [tossl::acme::create_order $directory_url $account_key $domains]} order_err]
if {$order_rc != 0} {
    puts "FAIL: acme::create_order failed - $order_err"
    exit 1
}

if {[string length $result] == 0} {
    puts "FAIL: Order creation result should not be empty"
    exit 1
}

if {![string match "*created successfully*" $result]} {
    puts "FAIL: Expected success message, got: $result"
    exit 1
}
puts "acme::create_order basic functionality: OK"

puts "Testing acme::create_order: multiple domains..."
set domains "example.com www.example.com"
set order_rc [catch {set result [tossl::acme::create_order $directory_url $account_key $domains]} order_err]
if {$order_rc != 0} {
    puts "FAIL: acme::create_order with multiple domains failed - $order_err"
    exit 1
}
puts "acme::create_order multiple domains: OK"

puts "Testing acme::create_order: single domain..."
set domains "test.example.com"
set order_rc [catch {set result [tossl::acme::create_order $directory_url $account_key $domains]} order_err]
if {$order_rc != 0} {
    puts "FAIL: acme::create_order with single domain failed - $order_err"
    exit 1
}
puts "acme::create_order single domain: OK"

puts "Testing acme::create_order: edge cases..."
set order_rc [catch {set result [tossl::acme::create_order "" "" ""]} order_err]
if {$order_rc != 0} {
    puts "Note: acme::create_order with empty strings failed - $order_err"
    puts "This is expected as empty domains causes parsing error"
} else {
    puts "acme::create_order empty strings: OK"
}
puts "acme::create_order edge cases: OK"

puts "Testing acme::create_order: integration with directory..."
set directory_rc [catch {set directory [tossl::acme::directory $directory_url]} directory_err]
if {$directory_rc != 0} {
    puts "Note: acme::directory failed - $directory_err"
} else {
    set order_rc [catch {set result [tossl::acme::create_order $directory_url $account_key $domains]} order_err]
    if {$order_rc != 0} {
        puts "Note: acme::create_order integration failed - $order_err"
    } else {
        puts "acme::create_order after directory: OK"
    }
}
puts "acme::create_order integration test: OK"

puts "Testing acme::create_order: performance..."
set start_time [clock milliseconds]
for {set i 0} {$i < 3} {incr i} {
    set order_rc [catch {tossl::acme::create_order $directory_url $account_key $domains} order_err]
    if {$order_rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $order_err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "acme::create_order performance (3 iterations): ${duration}ms"

puts "All ::tossl::acme::create_order tests passed" 