# tests/test_ec_point_add.tcl ;# Test for ::tossl::ec::point_add

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate two EC keys to get two valid points
set keys1 [tossl::key::generate -type ec -curve $curve]
set keys2 [tossl::key::generate -type ec -curve $curve]
set pub1 [dict get $keys1 public]
set pub2 [dict get $keys2 public]

# Extract public points in hex
set comps1 [tossl::ec::components $pub1]
set comps2 [tossl::ec::components $pub2]
set idx1 [lsearch $comps1 public]
set idx2 [lsearch $comps2 public]
if {$idx1 >= 0 && [expr {$idx1+1}] < [llength $comps1] && $idx2 >= 0 && [expr {$idx2+1}] < [llength $comps2]} {
    set point1_raw [lindex $comps1 [expr {$idx1+1}]]
    set point2_raw [lindex $comps2 [expr {$idx2+1}]]
    set point1 [string map {":" ""} $point1_raw]
    set point2 [string map {":" ""} $point2_raw]
} else {
    puts stderr ";# Failed to extract EC public points: $comps1 $comps2"
    exit 1
}

# Normal case: add two points
set rc [catch {set result [tossl::ec::point_add $curve $point1 $point2]} res]
if {$rc == 0} {
    puts ";# PASS: point_add normal case"
    puts "Result: $result"
} else {
    puts stderr ";# FAIL: point_add normal case: $res"
    exit 2
}

# Error: invalid curve
set rc [catch {tossl::ec::point_add invalidcurve $point1 $point2} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid curve"
} else {
    puts stderr ";# FAIL: expected error on invalid curve"
    exit 3
}

# Error: invalid point1
set rc [catch {tossl::ec::point_add $curve "ZZZZ" $point2} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid point1"
} else {
    puts stderr ";# FAIL: expected error on invalid point1"
    exit 4
}

# Error: invalid point2
set rc [catch {tossl::ec::point_add $curve $point1 "nothex"} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid point2"
} else {
    puts stderr ";# FAIL: expected error on invalid point2"
    exit 5
}

puts ";# All tests passed."
exit 0 