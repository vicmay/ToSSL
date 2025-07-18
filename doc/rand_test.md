# ::tossl::rand::test

Perform basic statistical tests on random number generation.

## Syntax

    tossl::rand::test <count>

- `<count>`: Number of random bytes to generate and test (1 to 1,000,000)

## Description

Performs basic statistical tests on OpenSSL's random number generator to assess the quality of randomness. The command generates the specified number of random bytes and applies several statistical measures to evaluate randomness.

This command is useful for:
- Validating that the random number generator is working correctly
- Detecting potential issues with random number quality
- Basic quality assurance for cryptographic applications
- Educational purposes to understand random number testing

## Output

Returns a string containing statistical test results in the format:
```
chi_square=<value>, max_consecutive_zeros=<count>, max_consecutive_ones=<count>, count=<total>
```

### Output Components

- **chi_square**: Chi-square statistic measuring distribution uniformity
- **max_consecutive_zeros**: Maximum length of consecutive zero bytes
- **max_consecutive_ones**: Maximum length of consecutive one bytes
- **count**: Total number of bytes tested

## Examples

### Basic Randomness Testing

```tcl
# Test 1000 random bytes
set result [tossl::rand::test 1000]
puts "Test result: $result"
# Output: chi_square=245.67, max_consecutive_zeros=3, max_consecutive_ones=2, count=1000
```

### Different Sample Sizes

```tcl
# Test with different sample sizes
set sizes {100 500 1000 5000 10000}

foreach size $sizes {
    set result [tossl::rand::test $size]
    puts "Size $size: $result"
}
```

### Result Parsing

```tcl
# Parse the test results
set result [tossl::rand::test 1000]

# Extract chi-square value
if {[regexp {chi_square=([0-9.]+)} $result -> chi_square]} {
    puts "Chi-square statistic: $chi_square"
}

# Extract max consecutive ones count
if {[regexp {max_consecutive_ones=([0-9]+)} $result -> max_consecutive_ones]} {
    puts "Max consecutive ones: $max_consecutive_ones"
}

# Extract max consecutive zeros
if {[regexp {max_consecutive_zeros=([0-9]+)} $result -> max_consecutive_zeros]} {
    puts "Max consecutive zeros: $max_consecutive_zeros"
}
```

### Multiple Test Runs

```tcl
# Run multiple tests to check consistency
for {set i 0} {$i < 5} {incr i} {
    set result [tossl::rand::test 1000]
    puts "Run $i: $result"
}
```

### Statistical Validation

```tcl
# Collect multiple test results for analysis
set chi_square_values {}
set max_consecutive_zeros_values {}

for {set i 0} {$i < 10} {incr i} {
    set result [tossl::rand::test 1000]
    
    # Extract values
    if {[regexp {chi_square=([0-9.]+)} $result -> chi_square]} {
        lappend chi_square_values $chi_square
    }
    if {[regexp {max_consecutive_zeros=([0-9]+)} $result -> max_consecutive_zeros]} {
        lappend max_consecutive_zeros_values $max_consecutive_zeros
    }
}

puts "Chi-square values: $chi_square_values"
puts "Max consecutive zeros values: $max_consecutive_zeros_values"

# Check for variation (good randomness)
set unique_chi [lsort -unique -real $chi_square_values]
if {[llength $unique_chi] > 1} {
    puts "✓ Chi-square values show good variation"
} else {
    puts "✗ Chi-square values are identical (suspicious)"
}
```

### Performance Testing

```tcl
# Test performance with larger samples
set start_time [clock milliseconds]
set result [tossl::rand::test 50000]
set end_time [clock milliseconds]
set duration [expr {$end_time - $start_time}]

puts "Test result: $result"
puts "Duration: ${duration}ms for 50000 bytes"
puts "Throughput: [expr {50000.0 / ($duration / 1000.0)}] bytes/second"
```

### Edge Cases

```tcl
# Test minimum valid count
set result [tossl::rand::test 1]
puts "Minimum test: $result"

# Test maximum valid count
set result [tossl::rand::test 1000000]
puts "Maximum test: $result"
```

### Quality Assessment

```tcl
# Assess random number quality
proc assess_quality {count} {
    set result [tossl::rand::test $count]
    
    # Extract values
regexp {chi_square=([0-9.]+)} $result -> chi_square
regexp {max_consecutive_zeros=([0-9]+)} $result -> max_consecutive_zeros
regexp {max_consecutive_ones=([0-9]+)} $result -> max_consecutive_ones

puts "Quality assessment for $count bytes:"
puts "  Chi-square: $chi_square"
puts "  Max consecutive zeros: $max_consecutive_zeros"
puts "  Max consecutive ones: $max_consecutive_ones"
    
    # Basic quality checks
    if {$chi_square > 0 && $chi_square < 1000} {
        puts "  ✓ Chi-square is reasonable"
    } else {
        puts "  ✗ Chi-square is extreme"
    }
    
    if {$max_consecutive_ones >= 0 && $max_consecutive_ones < 50} {
    puts "  ✓ Max consecutive ones is reasonable"
} else {
    puts "  ✗ Max consecutive ones is extreme"
}
    
    if {$max_consecutive_zeros >= 0 && $max_consecutive_zeros < 50} {
        puts "  ✓ Max consecutive zeros is reasonable"
    } else {
        puts "  ✗ Max consecutive zeros is extreme"
    }
}

assess_quality 1000
```

## Error Handling

- If required arguments are missing, an error is returned:

```tcl
tossl::rand::test
# Error: wrong # args: should be "tossl::rand::test count"
```

- If the count is not a valid integer, an error is returned:

```tcl
tossl::rand::test "not_a_number"
# Error: expected integer but got "not_a_number"
```

- If the count is zero or negative, an error is returned:

```tcl
tossl::rand::test 0
# Error: Count must be between 1 and 1000000

tossl::rand::test -1
# Error: Count must be between 1 and 1000000
```

- If the count exceeds the maximum allowed value, an error is returned:

```tcl
tossl::rand::test 1000001
# Error: Count must be between 1 and 1000000
```

- If memory allocation fails, an error is returned:

```tcl
tossl::rand::test 1000000
# Error: Memory allocation failed
```

- If random number generation fails, an error is returned:

```tcl
tossl::rand::test 1000
# Error: Failed to generate random bytes
```

## Statistical Tests Performed

### Chi-Square Test

The chi-square statistic measures how well the distribution of byte values matches a uniform distribution. For truly random data:

- **Expected range**: Typically between 200-300 for 1000 bytes
- **Interpretation**: Values close to 255 indicate good uniformity
- **Warning signs**: Extreme values (< 100 or > 500) may indicate issues

### Max Consecutive Ones Test

Finds the longest run of consecutive one bytes:

- **Expected behavior**: Should be relatively small (< 10 for 1000 bytes)
- **Interpretation**: Long runs of identical values are rare in random data
- **Warning signs**: Very long runs may indicate poor randomness

### Maximum Consecutive Zeros Test

Finds the longest run of consecutive zero bytes:

- **Expected behavior**: Should be relatively small (< 10 for 1000 bytes)
- **Interpretation**: Long runs of identical values are rare in random data
- **Warning signs**: Very long runs may indicate poor randomness

## Interpretation Guidelines

### Good Randomness Indicators

- Chi-square values between 200-300 (for 1000 bytes)
- Max consecutive zeros < 10 (for 1000 bytes)
- Max consecutive ones < 10 (for 1000 bytes)
- Results vary between multiple runs
- No obvious patterns in the output

### Poor Randomness Indicators

- Chi-square values < 100 or > 500
- Max consecutive zeros > 20
- Max consecutive ones > 20
- Identical results across multiple runs
- Obvious patterns or bias

### Sample Size Considerations

- **Small samples (100-1000 bytes)**: Quick tests, less reliable
- **Medium samples (1000-10000 bytes)**: Good balance of speed and reliability
- **Large samples (10000+ bytes)**: More reliable but slower

## Performance Characteristics

- **Time complexity**: O(n) where n is the count
- **Memory usage**: O(n) for storing random bytes
- **Typical performance**: ~100,000 bytes/second on modern hardware
- **Maximum practical size**: 1,000,000 bytes (may take several seconds)

## Security Considerations

⚠️ **WARNING: This command is for testing and validation purposes only.**

### Limitations

- **Basic tests only**: These are simple statistical tests, not comprehensive randomness validation
- **Not cryptographically validated**: Results do not guarantee cryptographic security
- **Sample size dependent**: Larger samples provide more reliable results
- **Not a substitute**: Should not replace proper cryptographic validation

### When to Use

- **Development testing**: Validating random number generator functionality
- **Quality assurance**: Basic checks during development
- **Educational purposes**: Understanding random number properties
- **Debugging**: Identifying obvious issues with random generation

### When NOT to Use

- **Cryptographic validation**: Use specialized tools like Dieharder or NIST STS
- **Production security**: Not sufficient for security-critical applications
- **Compliance testing**: May not meet formal security requirements
- **Final validation**: Should be part of a broader testing strategy

### Best Practices

- Use multiple test runs to check consistency
- Test with different sample sizes
- Compare results across different systems
- Use as part of a broader testing strategy
- Don't rely solely on these tests for security validation

## Notes

- The command uses OpenSSL's `RAND_bytes()` function internally
- Results may vary between different OpenSSL versions and builds
- Performance depends on the underlying random number generator
- The maximum count of 1,000,000 is a safety limit to prevent excessive resource usage
- The chi-square test uses 256 degrees of freedom (one for each byte value)
- Consecutive zeros are counted across the entire byte sequence
- The command is designed for basic validation, not comprehensive statistical analysis 