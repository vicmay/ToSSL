#!/usr/bin/env tclsh
if {[catch {package require tossl}]} {
    load ./libtossl.so
}
puts "Testing tossl::http::get..."
set get_result [tossl::http::get "https://httpbin.org/get"]
puts "GET result: $get_result\n"
puts "Testing tossl::http::post..."
set post_result [tossl::http::post "https://httpbin.org/post" "foo=bar&baz=qux"]
puts "POST result: $post_result\n"
puts "Done." 