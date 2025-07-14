#!/usr/bin/env tclsh

# Test PGP functionality loading
puts "Loading TOSSL library..."
load ./libtossl.so

puts "Available tossl commands:"
puts [info commands tossl::*]

puts "Testing package require:"
catch {package require tossl} result
puts "Package require result: $result"

puts "Available commands after package require:"
puts [info commands tossl::*]

puts "Testing PGP commands specifically:"
puts [info commands tossl::pgp::*]

puts "Testing direct function call:"
catch {
    set test_dict [dict create type rsa bits 2048 userid "Test User <test@example.com>"]
    puts "Test dict: $test_dict"
} err
puts "Error: $err" 