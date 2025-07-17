# ::tossl::provider::list

List available OpenSSL providers.

## Syntax

    tossl::provider::list

- No arguments.

## Description

Returns a comma-separated list of available OpenSSL providers. By default, this includes "default" and "legacy" if both are loaded. This command is useful for checking which cryptographic providers are available for use in the current session.

## Output

Returns a string listing the available providers, e.g.:

```
default, legacy
```

## Examples

```tcl
set providers [tossl::provider::list]
puts $providers
# Output: default, legacy
```

## Error Handling

- If extra arguments are provided, an error is returned:

```tcl
tossl::provider::list foo
# Error: wrong # args: should be "tossl::provider::list "
```

## Security Notes

- The list of providers determines which cryptographic algorithms are available.
- Only the "default" provider is required for modern OpenSSL cryptography; "legacy" is optional and may be omitted in hardened builds.
- No sensitive information is exposed by this command. 