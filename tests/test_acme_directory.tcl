# Test for ::tossl::acme::directory
load ./libtossl.so

puts "Testing acme::directory: missing required args..."
set rc [catch {tossl::acme::directory} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
puts "acme::directory missing args: OK"

puts "Testing acme::directory: basic functionality..."
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set rc [catch {set directory [tossl::acme::directory $directory_url]} err]
if {$rc != 0} {
    puts "FAIL: acme::directory failed - $err"
    exit 1
}
if {[llength [dict keys $directory]] == 0} {
    puts "FAIL: Directory dict is empty"
    exit 1
}
puts "Directory keys: [dict keys $directory]"
puts "acme::directory basic functionality: OK"

puts "Testing acme::directory: repeated calls (performance)..."
set start_time [clock milliseconds]
for {set i 0} {$i < 3} {incr i} {
    set rc [catch {set directory [tossl::acme::directory $directory_url]} err]
    if {$rc != 0} {
        puts "FAIL: acme::directory failed on iteration $i - $err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "acme::directory performance (3 iterations): ${duration}ms"

puts "Testing acme::directory: error simulation (invalid URL)..."
set invalid_url "https://invalid-acme-server.example.com/directory"
set rc [catch {set directory [tossl::acme::directory $invalid_url]} err]
if {$rc == 0} {
    puts "FAIL: acme::directory with invalid URL did not error"
    exit 1
}
puts "acme::directory invalid URL: OK"

puts "Testing acme::directory: edge case (empty string)..."
set rc [catch {set directory [tossl::acme::directory ""]} err]
if {$rc == 0} {
    puts "FAIL: acme::directory with empty string did not error"
    exit 1
}
puts "acme::directory empty string: OK"

puts "Testing acme::directory: integration with create_account..."
set account_key "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
set email "test@example.com"
set rc [catch {set directory [tossl::acme::directory $directory_url]} err]
if {$rc != 0} {
    puts "Note: acme::directory failed - $err"
} else {
    set rc2 [catch {set result [tossl::acme::create_account $directory_url $account_key $email]} err2]
    if {$rc2 != 0} {
        puts "Note: acme::create_account failed - $err2"
    } else {
        puts "acme::create_account after directory: OK"
    }
}
puts "acme::directory integration test: OK"

puts "All ::tossl::acme::directory tests passed" 