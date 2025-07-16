# ::tossl::cryptolog

**Manage or query the cryptographic event log.**

## Syntax

```tcl
::tossl::cryptolog status
::tossl::cryptolog clear
::tossl::cryptolog enable
::tossl::cryptolog disable
```

- `status`: Show current cryptolog status
- `clear`: Clear the cryptolog
- `enable`: Enable cryptolog
- `disable`: Disable cryptolog

## Returns
Status string or confirmation message.

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if cryptolog is not supported in this build.

## Security Considerations

- Cryptolog may contain sensitive information; clear or protect as needed.

## See Also
- [benchmark](benchmark.md) 