# Digest List Command

## Overview

The `::tossl::digest::list` command retrieves a list of all available digest (hash) algorithms supported by the OpenSSL default provider. This command is useful for discovering which hash algorithms are available on the current system and can be used with other TOSSL digest commands.

## Syntax

```tcl
::tossl::digest::list
```

## Parameters

This command takes no parameters.

## Return Value

Returns a TCL list containing the names of all available digest algorithms as strings. The list is not sorted and the order may vary between different OpenSSL versions or builds.

## Examples

### Basic Usage

```tcl
;# Get list of all available digest algorithms
set algorithms [::tossl::digest::list]
puts "Available algorithms: $algorithms"
```

### Iterating Through Algorithms

```tcl
;# Get and iterate through available algorithms
set algorithms [::tossl::digest::list]
foreach alg $algorithms {
    puts "Found algorithm: $alg"
}
```

### Checking for Specific Algorithms

```tcl
;# Check if specific algorithms are available
set algorithms [::tossl::digest::list]

if {[lsearch -exact $algorithms "sha256"] >= 0} {
    puts "SHA-256 is available"
} else {
    puts "SHA-256 is not available"
}

if {[lsearch -exact $algorithms "md5"] >= 0} {
    puts "MD5 is available"
} else {
    puts "MD5 is not available"
}
```

### Dynamic Algorithm Selection

```tcl
;# Use the list to dynamically select algorithms
set algorithms [::tossl::digest::list]
set test_data "Hello, World!"

;# Try to use SHA-256 if available, fall back to SHA-1
if {[lsearch -exact $algorithms "sha256"] >= 0} {
    set hash [::tossl::digest -alg sha256 $test_data]
    puts "SHA-256 hash: $hash"
} elseif {[lsearch -exact $algorithms "sha1"] >= 0} {
    set hash [::tossl::digest -alg sha1 $test_data]
    puts "SHA-1 hash: $hash"
} else {
    puts "No suitable hash algorithm found"
}
```

### Algorithm Family Detection

```tcl
;# Find all SHA family algorithms
set algorithms [::tossl::digest::list]
set sha_algorithms {}

foreach alg $algorithms {
    if {[string match "sha*" $alg]} {
        lappend sha_algorithms $alg
    }
}

puts "SHA family algorithms: $sha_algorithms"
```

### Integration with Digest Command

```tcl
;# Test multiple algorithms from the list
set algorithms [::tossl::digest::list]
set test_data "test data"

foreach alg [lrange $algorithms 0 4] {
    if {[catch {
        set hash [::tossl::digest -alg $alg $test_data]
        puts "$alg: $hash"
    } error_msg]} {
        puts "Error with $alg: $error_msg"
    }
}
```

## Common Algorithm Names

The following are common digest algorithm names that may be returned by this command:

### SHA Family
- `sha1` - SHA-1 (160-bit)
- `sha224` - SHA-224 (224-bit)
- `sha256` - SHA-256 (256-bit)
- `sha384` - SHA-384 (384-bit)
- `sha512` - SHA-512 (512-bit)
- `sha512-224` - SHA-512/224 (224-bit)
- `sha512-256` - SHA-512/256 (256-bit)

### MD Family
- `md5` - MD5 (128-bit)
- `md4` - MD4 (128-bit)

### Other Common Algorithms
- `ripemd160` - RIPEMD-160 (160-bit)
- `whirlpool` - Whirlpool (512-bit)
- `blake2b512` - BLAKE2b-512 (512-bit)
- `blake2s256` - BLAKE2s-256 (256-bit)

## Error Handling

### Wrong Number of Arguments

```tcl
;# This will return an error
catch {::tossl::digest::list extra_arg} error_msg
puts $error_msg
;# Output: wrong # args: should be "tossl::digest::list"
```

### Provider Loading Issues

If the OpenSSL default provider cannot be loaded, the command will return an error:

```tcl
;# This might fail if OpenSSL is not properly configured
catch {::tossl::digest::list} error_msg
if {[string match "*Failed to load default provider*" $error_msg]} {
    puts "OpenSSL provider loading failed"
}
```

## Performance Considerations

- The command queries the OpenSSL provider system, which may involve some overhead
- Results are cached by OpenSSL internally, so subsequent calls may be faster
- The list is generated dynamically and reflects the current OpenSSL configuration

## Best Practices

### 1. Cache Results for Multiple Uses

```tcl
;# Cache the list if you need to use it multiple times
set algorithms [::tossl::digest::list]

;# Use cached list for multiple operations
foreach alg $algorithms {
    ;# Process each algorithm
}
```

### 2. Check for Required Algorithms

```tcl
;# Check for required algorithms before using them
set algorithms [::tossl::digest::list]
set required_algs {sha256 sha512}

foreach required_alg $required_algs {
    if {[lsearch -exact $algorithms $required_alg] < 0} {
        error "Required algorithm '$required_alg' is not available"
    }
}
```

### 3. Use for Dynamic Algorithm Selection

```tcl
;# Select the best available algorithm from a preference list
set algorithms [::tossl::digest::list]
set preference_order {sha256 sha512 sha1 md5}

set selected_alg ""
foreach preferred $preference_order {
    if {[lsearch -exact $algorithms $preferred] >= 0} {
        set selected_alg $preferred
        break
    }
}

if {$selected_alg eq ""} {
    error "No suitable hash algorithm found"
}

puts "Using algorithm: $selected_alg"
```

### 4. Validate Algorithm Names

```tcl
;# Validate algorithm names before using them
set algorithms [::tossl::digest::list]
set user_alg "sha256"

if {[lsearch -exact $algorithms $user_alg] >= 0} {
    set hash [::tossl::digest -alg $user_alg "data"]
} else {
    puts "Algorithm '$user_alg' is not available"
    puts "Available algorithms: $algorithms"
}
```

### 5. Handle Empty Results

```tcl
;# Handle the case where no algorithms are available
set algorithms [::tossl::digest::list]

if {[llength $algorithms] == 0} {
    error "No digest algorithms are available"
} else {
    puts "Found [llength $algorithms] digest algorithms"
}
```

## Integration with Other Commands

The `::tossl::digest::list` command is designed to work with other TOSSL digest commands:

### With `::tossl::digest`

```tcl
set algorithms [::tossl::digest::list]
set data "test data"

foreach alg $algorithms {
    set hash [::tossl::digest -alg $alg $data]
    puts "$alg: $hash"
}
```

### With `::tossl::hmac`

```tcl
set algorithms [::tossl::digest::list]
set key "secret key"
set data "test data"

foreach alg $algorithms {
    set mac [::tossl::hmac -alg $alg -key $key $data]
    puts "HMAC-$alg: $mac"
}
```

### With `::tossl::pbkdf2`

```tcl
set algorithms [::tossl::digest::list]
set password "password"
set salt "salt"

foreach alg $algorithms {
    set key [::tossl::pbkdf2 -pass $password -salt $salt -iter 1000 -len 32 -alg $alg]
    puts "PBKDF2-$alg: [::tossl::hex::encode $key]"
}
```

## Troubleshooting

### Common Issues

1. **No algorithms returned**
   - Check if OpenSSL is properly installed
   - Verify that the default provider is available
   - Check OpenSSL version compatibility

2. **Unexpected algorithm names**
   - Algorithm names may vary between OpenSSL versions
   - Some algorithms may be deprecated or removed
   - Check OpenSSL documentation for current algorithm names

3. **Performance issues**
   - Cache the result if using multiple times
   - Consider the overhead of provider queries
   - Use specific algorithm names when known

### Debugging

```tcl
;# Debug algorithm availability
set algorithms [::tossl::digest::list]
puts "Total algorithms: [llength $algorithms]"
puts "First 10 algorithms: [lrange $algorithms 0 9]"

;# Check for specific algorithm families
set sha_count 0
set md_count 0
foreach alg $algorithms {
    if {[string match "sha*" $alg]} { incr sha_count }
    if {[string match "md*" $alg]} { incr md_count }
}
puts "SHA algorithms: $sha_count"
puts "MD algorithms: $md_count"
```

## Related Commands

- `::tossl::digest` - Calculate digest/hash of data
- `::tossl::digest::stream` - Stream-based digest calculation
- `::tossl::digest::compare` - Compare two hash values
- `::tossl::hmac` - Calculate HMAC (Hash-based Message Authentication Code)
- `::tossl::pbkdf2` - Password-based key derivation function 