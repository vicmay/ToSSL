# ::tossl::oauth2::validate_state

Validate an OAuth2 state parameter against the expected value.

## Syntax

    tossl::oauth2::validate_state <state> <expected_state>

- `<state>`: The state value to validate
- `<expected_state>`: The expected state value

## Description

Compares the provided state value to the expected value and returns a boolean result (1 for match, 0 for mismatch). Used to prevent CSRF attacks in OAuth2 flows by ensuring the state parameter returned by the authorization server matches the one originally sent.

## Output

Returns 1 if the states match, 0 otherwise.

## Examples

```tcl
set state [tossl::oauth2::generate_state]
set valid [tossl::oauth2::validate_state $state $state]
puts $valid
# Output: 1

set valid [tossl::oauth2::validate_state $state "other_state"]
puts $valid
# Output: 0
```

## Error Handling

- If the wrong number of arguments is provided, an error is returned:

```tcl
tossl::oauth2::validate_state foo
# Error: wrong # args: should be "tossl::oauth2::validate_state <state> <expected_state>"
```

## Security Notes

- Always validate the state parameter in OAuth2 flows to prevent CSRF attacks. 