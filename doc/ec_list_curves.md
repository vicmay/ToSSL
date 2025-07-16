# ::tossl::ec::list_curves

List all supported elliptic curves.

## Overview

`::tossl::ec::list_curves` returns a list of all elliptic curves supported by the underlying OpenSSL library. Each entry is a list containing a human-readable comment and the curve's short name.

## Syntax

```
tossl::ec::list_curves
```

(No arguments.)

## Example

```tcl
set curves [tossl::ec::list_curves]
foreach curve $curves {
    set comment [lindex $curve 0]
    set name [lindex $curve 1]
    puts "$name: $comment"
}
```

## Return Value

- Returns a list of lists. Each sublist contains:
  - The curve's comment (description)
  - The curve's short name (e.g., `prime256v1`)

## Error Handling

- Returns an error if any arguments are provided.
- Returns an error if memory allocation fails (rare).

## Security Considerations

- Only use well-known, secure curves (e.g., `prime256v1`, `secp384r1`) for cryptographic operations.
- Avoid legacy or deprecated curves unless required for compatibility.

## Best Practices

- Always check that the desired curve is present in the list before use.
- Prefer curves recommended by current cryptographic standards.

## See Also
- `tossl::key::generate`
- `tossl::ec::components`
- `tossl::ec::validate` 