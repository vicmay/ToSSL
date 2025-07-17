# ::tossl::provider::unload

Unload an OpenSSL provider by name.

## Syntax

    tossl::provider::unload <name>

- `<name>`: The name of the provider to unload (e.g., `default`, `legacy`)

## Description

Unloads the specified OpenSSL provider from the current process. This disables cryptographic algorithms and features associated with that provider. The command returns `ok` if the provider is unloaded successfully, or an error if the provider is not loaded or cannot be unloaded.

## Output

Returns `ok` on success.

## Examples

```tcl
set result [tossl::provider::unload default]
puts $result
# Output: ok

set result [tossl::provider::unload legacy]
puts $result
# Output: ok
```

## Error Handling

- If the provider is not loaded or cannot be unloaded, an error is returned:

```tcl
tossl::provider::unload bogus
# Error: Provider not loaded
```

- If the wrong number of arguments is provided, an error is returned:

```tcl
tossl::provider::unload
# Error: wrong # args: should be "tossl::provider::unload name"
```

## Security Notes

- Unloading a provider disables its algorithms for subsequent cryptographic operations.
- Unloading the `default` provider may break cryptographic functionality; use with caution.
- Only unload providers if you are certain they are no longer needed in the current session. 