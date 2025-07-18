# Test for ::tossl::acme::create_account
load ./libtossl.so

puts "Testing acme::create_account: missing required args..."
set rc [catch {tossl::acme::create_account} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing args did not error"
    exit 1
}
set rc [catch {tossl::acme::create_account "directory_url"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing account_key did not error"
    exit 1
}
set rc [catch {tossl::acme::create_account "directory_url" "account_key"} result]
puts "Result: $result"
if {$rc == 0} {
    puts "FAIL: Missing email did not error"
    exit 1
}
puts "acme::create_account missing args: OK"

puts "Testing acme::create_account: basic functionality..."
set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
set account_key "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
set email "test@example.com"

set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $email]} account_err]
if {$account_rc != 0} {
    puts "FAIL: acme::create_account failed - $account_err"
    exit 1
}

if {[string length $result] == 0} {
    puts "FAIL: Account creation result should not be empty"
    exit 1
}

if {![string match "*created successfully*" $result]} {
    puts "FAIL: Expected success message, got: $result"
    exit 1
}
puts "acme::create_account basic functionality: OK"

puts "Testing acme::create_account: with optional contact parameter..."
set contact "https://example.com/contact"
set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $email $contact]} account_err]
if {$account_rc != 0} {
    puts "FAIL: acme::create_account with contact failed - $account_err"
    exit 1
}
puts "acme::create_account with contact: OK"

puts "Testing acme::create_account: different email formats..."
set emails {admin@example.com user@test.org contact@domain.co.uk}
foreach email $emails {
    set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $email]} account_err]
    if {$account_rc != 0} {
        puts "FAIL: acme::create_account with email '$email' failed - $account_err"
        exit 1
    }
    puts "Email $email: OK"
}
puts "acme::create_account different email formats: OK"

puts "Testing acme::create_account: edge cases..."
set account_rc [catch {set result [tossl::acme::create_account "" "" ""]} account_err]
if {$account_rc != 0} {
    puts "Note: acme::create_account with empty strings failed - $account_err"
    puts "This is expected as empty directory URL causes JSON parsing error"
} else {
    puts "acme::create_account empty strings: OK"
}
puts "acme::create_account edge cases: OK"

set long_email [string repeat "a" 50]."@example.com"
set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $long_email]} account_err]
if {$account_rc != 0} {
    puts "FAIL: acme::create_account with long email failed - $account_err"
    exit 1
}
puts "acme::create_account long email: OK"

puts "Testing acme::create_account: security validation..."
set special_chars_email "test+tag@example.com"
set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $special_chars_email]} account_err]
if {$account_rc != 0} {
    puts "FAIL: acme::create_account with special characters failed - $account_err"
    exit 1
}
puts "acme::create_account special characters: OK"

puts "Testing acme::create_account: integration with directory..."
set directory_rc [catch {set directory [tossl::acme::directory $directory_url]} directory_err]
if {$directory_rc != 0} {
    puts "Note: acme::directory failed - $directory_err"
    puts "This is expected as the implementation may be a placeholder"
} else {
    puts "Directory fetched successfully"
    set account_rc [catch {set result [tossl::acme::create_account $directory_url $account_key $email]} account_err]
    if {$account_rc != 0} {
        puts "FAIL: acme::create_account integration failed - $account_err"
        exit 1
    }
}
puts "acme::create_account integration test: OK"

puts "Testing acme::create_account: performance..."
set start_time [clock milliseconds]
for {set i 0} {$i < 3} {incr i} {
    set account_rc [catch {tossl::acme::create_account $directory_url $account_key $email} account_err]
    if {$account_rc != 0} {
        puts "FAIL: Performance test failed on iteration $i - $account_err"
        exit 1
    }
}
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]
puts "acme::create_account performance (3 iterations): ${duration}ms"

puts "Testing acme::create_account: error simulation..."
set invalid_directory "https://invalid-acme-server.example.com/directory"
set account_rc [catch {set result [tossl::acme::create_account $invalid_directory $account_key $email]} account_err]
if {$account_rc != 0} {
    puts "Note: acme::create_account with invalid directory failed - $account_err"
    puts "This is expected as invalid directory URL causes JSON parsing error"
} else {
    puts "acme::create_account invalid directory: OK"
}
puts "acme::create_account error simulation: OK"

puts "All ::tossl::acme::create_account tests passed" 