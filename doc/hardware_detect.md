# ::tossl::hardware::detect

Detect hardware acceleration features available on the system for cryptographic operations.

## Syntax

    tossl::hardware::detect

## Description

The `::tossl::hardware::detect` command provides information about hardware acceleration features available on the current system. These features can significantly improve the performance of cryptographic operations by utilizing specialized CPU instructions and hardware components.

This command returns a dictionary containing the status of various hardware acceleration mechanisms:

### Return Value

The command returns a dictionary with the following keys:

- **`aes_ni`** (boolean): Whether AES-NI (Advanced Encryption Standard New Instructions) is available
- **`sha_ni`** (boolean): Whether SHA-NI (Secure Hash Algorithm New Instructions) is available
- **`avx2`** (boolean): Whether AVX2 (Advanced Vector Extensions 2) is available
- **`hardware_rng`** (boolean): Whether hardware random number generator is available
- **`rsa_acceleration`** (boolean): Whether RSA acceleration is available
- **`hardware_acceleration`** (boolean): Overall hardware acceleration status

## Examples

### Basic Usage

```tcl
# Check hardware acceleration status
set hw_info [tossl::hardware::detect]
puts "Hardware acceleration info: $hw_info"

# Check specific acceleration features
if {[dict get $hw_info aes_ni]} {
    puts "AES-NI is available for faster AES operations"
}

if {[dict get $hw_info hardware_acceleration]} {
    puts "Hardware acceleration is available"
}
```

### Performance Optimization

```tcl
# Use hardware acceleration information for performance optimization
set hw_info [tossl::hardware::detect]

if {[dict get $hw_info aes_ni]} {
    puts "Using hardware-accelerated AES operations"
    # AES operations will automatically use hardware acceleration
    set key [tossl::randbytes 32]
    set iv [tossl::randbytes 16]
    set encrypted [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $data]
} else {
    puts "Using software AES implementation"
    # Same operations, but slower software implementation
    set key [tossl::randbytes 32]
    set iv [tossl::randbytes 16]
    set encrypted [tossl::encrypt -alg aes-256-cbc -key $key -iv $iv $data]
}
```

### Algorithm Selection Based on Hardware

```tcl
# Choose algorithms based on available hardware acceleration
set hw_info [tossl::hardware::detect]

if {[dict get $hw_info sha_ni]} {
    puts "Using SHA-NI accelerated hashing"
    set hash [tossl::digest -alg sha256 $data]
} else {
    puts "Using software SHA-256 implementation"
    set hash [tossl::digest -alg sha256 $data]
}

if {[dict get $hw_info rsa_acceleration]} {
    puts "RSA operations will use hardware acceleration"
    set keys [tossl::key::generate -type rsa -bits 2048]
    set signature [tossl::rsa::sign -key [dict get $keys private] -data $data -alg sha256]
} else {
    puts "RSA operations will use software implementation"
    set keys [tossl::key::generate -type rsa -bits 2048]
    set signature [tossl::rsa::sign -key [dict get $keys private] -data $data -alg sha256]
}
```

### System Capability Reporting

```tcl
# Generate a comprehensive system capability report
set hw_info [tossl::hardware::detect]

puts "=== Hardware Acceleration Report ==="
puts "AES-NI: [dict get $hw_info aes_ni]"
puts "SHA-NI: [dict get $hw_info sha_ni]"
puts "AVX2: [dict get $hw_info avx2]"
puts "Hardware RNG: [dict get $hw_info hardware_rng]"
puts "RSA Acceleration: [dict get $hw_info rsa_acceleration]"
puts "Overall Hardware Acceleration: [dict get $hw_info hardware_acceleration]"

if {[dict get $hw_info hardware_acceleration]} {
    puts "✓ System supports hardware acceleration"
} else {
    puts "⚠ System does not support hardware acceleration"
}
```

## Hardware Acceleration Features

### AES-NI (Advanced Encryption Standard New Instructions)

- **Purpose**: Accelerates AES encryption and decryption operations
- **Benefits**: Significantly faster AES operations (2-10x performance improvement)
- **Availability**: Intel processors from 2010+, AMD processors from 2011+
- **Impact**: All AES operations (`aes-128-cbc`, `aes-256-gcm`, etc.) automatically benefit

### SHA-NI (Secure Hash Algorithm New Instructions)

- **Purpose**: Accelerates SHA-1 and SHA-256 hash operations
- **Benefits**: Faster hash computation for digital signatures and integrity checking
- **Availability**: Intel processors from 2013+, AMD processors from 2016+
- **Impact**: SHA-1 and SHA-256 operations automatically benefit

### AVX2 (Advanced Vector Extensions 2)

- **Purpose**: Provides wider vector operations for parallel processing
- **Benefits**: Improved performance for various cryptographic algorithms
- **Availability**: Intel processors from 2013+, AMD processors from 2015+
- **Impact**: Some cryptographic operations may benefit from vectorization

### Hardware Random Number Generator

- **Purpose**: Provides high-quality random numbers from hardware entropy sources
- **Benefits**: Better entropy and faster random number generation
- **Availability**: Modern processors with RDRAND/RDSEED instructions
- **Impact**: Random number generation operations benefit

### RSA Acceleration

- **Purpose**: Accelerates RSA key generation, signing, and verification
- **Benefits**: Faster RSA operations, especially for larger key sizes
- **Availability**: Various processors with specialized RSA instructions
- **Impact**: RSA operations automatically benefit

## Platform Considerations

### x86_64 Architecture

- Most hardware acceleration features are available on modern x86_64 processors
- AES-NI and SHA-NI are widely supported
- AVX2 is common on processors from 2013 onwards
- Hardware RNG is available on most modern processors

### Other Architectures

- ARM processors may have different acceleration features
- Some features may not be available on non-x86 architectures
- The command will return appropriate values for the current platform

### Virtual Machines

- Hardware acceleration features may not be available in virtualized environments
- Hypervisor configuration may affect feature availability
- Performance may be limited compared to bare metal systems

## Performance Implications

### With Hardware Acceleration

- **AES operations**: 2-10x faster
- **SHA operations**: 2-5x faster
- **RSA operations**: 2-8x faster (depending on key size)
- **Random number generation**: Improved entropy and speed

### Without Hardware Acceleration

- All operations use software implementations
- Performance is still adequate for most use cases
- Security is not compromised (same cryptographic strength)

## Error Handling

The command has minimal error conditions:

- **Extra Arguments**: Returns an error if additional arguments are provided
- **Invalid Arguments**: Returns an error for invalid argument formats

## Implementation Notes

- The command uses OpenSSL's CPU capability detection
- Results are consistent across multiple calls
- Hardware acceleration is automatically used when available
- No manual configuration is required
- The command is designed to be lightweight and fast

## Related Commands

- `::tossl::benchmark` - Performance benchmarking of cryptographic operations
- `::tossl::sidechannel::protect` - Check side-channel attack protection
- `::tossl::fips::status` - Check FIPS compliance status

## Version Information

- **Introduced**: OpenSSL 3.x compatibility
- **Dependencies**: Requires OpenSSL 3.x or later for full feature detection
- **Platform Support**: Available on all platforms supported by OpenSSL
- **Architecture Support**: Best support on x86_64, limited on other architectures 