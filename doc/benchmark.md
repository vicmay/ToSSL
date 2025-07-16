# ::tossl::benchmark

**Run or query cryptographic performance benchmarks.**

## Syntax

```tcl
::tossl::benchmark status
::tossl::benchmark run
```

- `status`: Show current benchmark status or results
- `run`: Run cryptographic benchmarks

## Returns
Status string or benchmark results.

## Examples

_TODO: Add usage examples._

## Error Handling

- Throws error if parameters are missing or invalid.
- Throws error if benchmark is not supported in this build.

## Security Considerations

- Benchmarking may impact system performance during execution.

## See Also
- [cryptolog](cryptolog.md) 