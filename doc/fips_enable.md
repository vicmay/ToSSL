# ::tossl::fips::enable

Enable the OpenSSL FIPS provider and FIPS mode.

## Syntax

    tossl::fips::enable

## Description

Enables the OpenSSL FIPS provider and FIPS mode using the OpenSSL 3.x API. Only the default provider is supported; no legacy FIPS module logic is used. If FIPS mode is already enabled, this command is idempotent.

**Note:** Enabling FIPS mode requires the OpenSSL FIPS provider to be installed and configured on your system. If the provider is not available, this command will return an error ("Failed to enable FIPS mode"). This is expected on systems without the FIPS provider.

## Output

Returns the string:

    FIPS mode enabled

Returns an error if enabling FIPS mode fails.

## Examples

```tcl
set result [tossl::fips::enable]
puts $result
set status [tossl::fips::status]
puts $status
```

## Error Handling

- Returns an error if FIPS mode cannot be enabled.
- Returns an error if extra arguments are provided.

## Security Notes

- Only OpenSSL 3.x default provider FIPS support is enabled.
- No legacy/old-style FIPS module is supported. 