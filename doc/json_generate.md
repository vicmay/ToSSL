# ::tossl::json::generate

Generate a JSON string from a Tcl dict, list, or value.

## Syntax

    tossl::json::generate <tcl_dict|list|value>

- `<tcl_dict|list|value>`: The Tcl object to convert to JSON (dict, list, string, number, or boolean)

## Description

Converts a Tcl dict, list, string, number, or boolean to a JSON string using the json-c library. Nested structures are supported. Dicts become JSON objects, lists become JSON arrays, and values are converted to their JSON equivalents.

## Output

Returns a JSON string representing the input Tcl object.

## Examples

```tcl
set dict {foo bar baz 42}
set json [tossl::json::generate $dict]
puts $json
# Output: {"foo":"bar","baz":42}

set list {1 2 3}
set json [tossl::json::generate $list]
puts $json
# Output: [1,2,3]

set json [tossl::json::generate true]
puts $json
# Output: true

set json [tossl::json::generate "hello"]
puts $json
# Output: "hello"
```

## Error Handling

- Returns an error if the input cannot be converted to JSON.
- Returns an error if the wrong number of arguments is provided.

## Security Notes

- Only supported Tcl types (dict, list, string, number, boolean) are converted.
- Input is not validated as safe for all JSON consumers; ensure you trust the input source. 