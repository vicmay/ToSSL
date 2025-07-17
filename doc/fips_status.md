# ::tossl::fips::status

Report the status of the OpenSSL FIPS provider and FIPS mode.

## Syntax

    tossl::fips::status

## Description

Reports whether the OpenSSL FIPS provider is available and whether FIPS mode is enabled. This command checks the OpenSSL 3.x provider status and does not use any legacy FIPS module logic. Only the default provider is supported.

## Output

Returns a string of the form:

    FIPS provider available: yes|no, FIPS mode: enabled|disabled

## Examples

```tcl
set status [tossl::fips::status]
puts "FIPS status: $status"
```

## Error Handling

- Returns an error if the status cannot be determined.
- Returns an error if extra arguments are provided.

## Security Notes

- Only OpenSSL 3.x default provider FIPS support is checked.
- No legacy/old-style FIPS module is supported. 