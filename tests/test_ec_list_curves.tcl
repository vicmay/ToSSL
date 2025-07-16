# tests/test_ec_list_curves.tcl ;# Test for ::tossl::ec::list_curves

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Normal case: get list of curves
set rc [catch {set curves [tossl::ec::list_curves]} res]
if {$rc == 0} {
    if {[llength $curves] == 0} {
        puts stderr ";# FAIL: list_curves returned empty list"
        exit 1
    }
    set found_prime256v1 0
    foreach curve $curves {
        if {[llength $curve] != 2} {
            puts stderr ";# FAIL: curve entry not length 2: $curve"
            exit 2
        }
        set comment [lindex $curve 0]
        set name [lindex $curve 1]
        if {$name eq "prime256v1"} {
            set found_prime256v1 1
        }
    }
    if {!$found_prime256v1} {
        puts stderr ";# FAIL: prime256v1 not found in curve list"
        exit 3
    }
    puts ";# PASS: list_curves normal case"
} else {
    puts stderr ";# FAIL: list_curves error: $res"
    exit 4
}

# Error: extra argument
set rc [catch {tossl::ec::list_curves extra} res]
if {$rc != 0} {
    puts ";# PASS: error on extra argument"
} else {
    puts stderr ";# FAIL: expected error on extra argument"
    exit 5
}

puts ";# All tests passed."
exit 0 