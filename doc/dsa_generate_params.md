# ::tossl::dsa::generate_params

Generate DSA domain parameters (PEM format).

## Overview

`::tossl::dsa::generate_params` generates DSA domain parameters of a specified bit length, suitable for DSA key generation. The output is in PEM format and can be used for further DSA operations.

## Syntax

```
tossl::dsa::generate_params ?-bits <bits>?
```

- `-bits <bits>`: (Optional) Bit length for the parameters (default: 2048). Common values: 1024, 2048, 3072.

## Example

```tcl
# Generate default (2048-bit) DSA parameters
set params [tossl::dsa::generate_params]
puts $params

# Generate 3072-bit DSA parameters
set params [tossl::dsa::generate_params -bits 3072]
puts $params
```

## Return Value

- Returns the DSA parameters in PEM format as a string.
- Returns an error if parameter generation fails or arguments are invalid.

## Error Handling

- Returns an error if the bit length is invalid (zero, negative, or non-integer).
- Returns an error if OpenSSL fails to generate parameters or write PEM output.
- Returns an error on unknown or extra arguments.

## Security Considerations

- Use at least 2048 bits for new DSA parameters; 1024 is considered legacy.
- Only use parameters generated from trusted sources.
- Handle all key material securely and clear sensitive data from memory when possible.

## Best Practices

- Always check for errors when generating parameters.
- Use strong parameter sizes (2048 bits or higher) for new deployments.
- Do not expose sensitive data in logs or outputs.

## See Also
- `tossl::dsa::validate`
- `tossl::key::generate` 