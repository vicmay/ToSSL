# ::tossl::pfs::test

## Overview

The `::tossl::pfs::test` command provides information about the Perfect Forward Secrecy (PFS) cipher suites supported and recommended by the ToSSL library. It returns a Tcl dict containing lists of PFS and non-PFS ciphers, as well as status flags indicating support and recommendation for PFS.

## Syntax

```
::tossl::pfs::test
```

No arguments are accepted. Supplying arguments will result in an error.

## Return Value

Returns a Tcl dict with the following keys:
- `pfs_ciphers`: List of supported PFS cipher suite names
- `non_pfs_ciphers`: List of non-PFS cipher suite names
- `pfs_supported`: 1 if PFS is supported, 0 otherwise
- `pfs_recommended`: 1 if PFS is recommended, 0 otherwise

## Example

```tcl
set info [::tossl::pfs::test]
puts "PFS ciphers: [dict get $info pfs_ciphers]"
puts "Non-PFS ciphers: [dict get $info non_pfs_ciphers]"
puts "PFS supported: [dict get $info pfs_supported]"
puts "PFS recommended: [dict get $info pfs_recommended]"
```

## Error Handling

- If any arguments are supplied, the command returns an error:
  ```tcl
  % ::tossl::pfs::test extra
  wrong # args: should be "::tossl::pfs::test"
  ```
- If the library is not loaded, the command will not be available.

## Security Considerations

- PFS cipher suites are recommended for secure communications, as they provide forward secrecy in the event of key compromise.
- The command only reports available ciphers; it does not configure or enforce cipher suite selection.
- Always use PFS ciphers where possible for TLS/SSL connections.

## Best Practices

- Use this command to audit available cipher suites and ensure PFS is supported and recommended in your environment.
- Regularly update your OpenSSL library to ensure the latest secure cipher suites are available. 