# ::tossl::json::parse

Parse a JSON string into a Tcl dict, list, or value.

## Syntax

    tossl::json::parse <json_string>

- `<json_string>`: The JSON string to parse (object, array, string, number, or boolean)

## Description

Converts a JSON string into the corresponding Tcl object using the json-c library. JSON objects become Tcl dicts, arrays become Tcl lists, and values are converted to their Tcl equivalents (string, number, boolean). Nested structures are supported.

## Output

Returns a Tcl object representing the parsed JSON input.

## Examples

```tcl
set json {"foo":"bar","baz":42}
set dict [tossl::json::parse $json]
puts $dict
# Output: foo bar baz 42

set json {[1,2,3]}
set list [tossl::json::parse $json]
puts $list
# Output: 1 2 3

set val [tossl::json::parse true]
puts $val
# Output: 1

set val [tossl::json::parse {"hello"}]
puts $val
# Output: hello
```

## Error Handling

- Returns an error if the input is not valid JSON.
- Returns an error if the wrong number of arguments is provided.

## Security Notes

- Only valid JSON is accepted; invalid input will result in an error.
- Input is not validated as safe for all Tcl consumers; ensure you trust the input source. 