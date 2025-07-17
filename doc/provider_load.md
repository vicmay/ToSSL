# ::tossl::provider::load

Load an OpenSSL provider by name.

## Syntax

    tossl::provider::load <name>

- `<name>`: The name of the provider to load (e.g., `default`, `legacy`)

## Description

Loads the specified OpenSSL provider into the current process. This enables cryptographic algorithms and features associated with that provider. The command returns `ok` if the provider is loaded successfully, or an error if the provider cannot be loaded.

## Output

Returns `ok` on success.

## Examples

```tcl
set result [tossl::provider::load default]
puts $result
# Output: ok

set result [tossl::provider::load legacy]
puts $result
# Output: ok
```

## Error Handling

- If the provider cannot be loaded (e.g., invalid name), an error is returned:

```tcl
tossl::provider::load bogus
# Error: Failed to load provider
```

- If the wrong number of arguments is provided, an error is returned:

```tcl
tossl::provider::load
# Error: wrong # args: should be "tossl::provider::load name"
```

## Security Notes

- Loading a provider makes its algorithms available for cryptographic operations.
- Only load trusted providers; loading untrusted or third-party providers may introduce security risks.
- The `default` provider is required for modern OpenSSL cryptography; `legacy` is optional and may be omitted in hardened builds. 