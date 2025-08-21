#!/usr/bin/env tclsh

set b64_with_nl "aGVsbG8K\nd29ybGQh"
puts "Input string: '$b64_with_nl'"
puts "Length: [string length $b64_with_nl]"

# Check what Tcl's base64 decoder does
set tcl_result [binary decode base64 $b64_with_nl]
puts "Tcl decode result: '$tcl_result'"

# Let's see what the individual parts decode to
set part1 "aGVsbG8K"
set part2 "d29ybGQh"
puts "Part1 '$part1' decodes to: '[binary decode base64 $part1]'"
puts "Part2 '$part2' decodes to: '[binary decode base64 $part2]'"

# So the full string should decode to
set combined "${part1}${part2}"
puts "Combined '$combined' decodes to: '[binary decode base64 $combined]'"
