# tests/test_ec_point_multiply.tcl ;# Test for ::tossl::ec::point_multiply

if {[catch {package require tossl}]} {
    load ./libtossl.so
}

set curve prime256v1
# Generate EC key to get a valid point
set keys [tossl::key::generate -type ec -curve $curve]
set pub [dict get $keys public]

# Extract public point in hex (list: {curve <name> public <hex>})
set comps [tossl::ec::components $pub]
set idx [lsearch $comps public]
if {$idx >= 0 && [expr {$idx+1}] < [llength $comps]} {
    set point_raw [lindex $comps [expr {$idx+1}]]
    set point [string map {":" ""} $point_raw]
} else {
    puts stderr ";# Failed to extract EC public point: $comps"
    exit 1
}

# Use scalar 02 for multiplication (hex string)
set scalar "02"
set rc [catch {set result [tossl::ec::point_multiply $curve $point $scalar]} res]
if {$rc == 0} {
    puts ";# PASS: point_multiply normal case"
    puts "Result: $result"
} else {
    puts stderr ";# FAIL: point_multiply normal case: $res"
    exit 2
}

# Error: invalid curve
set rc [catch {tossl::ec::point_multiply invalidcurve $point $scalar} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid curve"
} else {
    puts stderr ";# FAIL: expected error on invalid curve"
    exit 3
}

# Error: invalid point
set rc [catch {tossl::ec::point_multiply $curve "ZZZZ" $scalar} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid point"
} else {
    puts stderr ";# FAIL: expected error on invalid point"
    exit 4
}

# Error: invalid scalar
set rc [catch {tossl::ec::point_multiply $curve $point "nothex"} res]
if {$rc != 0} {
    puts ";# PASS: error on invalid scalar"
} else {
    puts stderr ";# FAIL: expected error on invalid scalar"
    exit 5
}

puts ";# All tests passed."
exit 0 