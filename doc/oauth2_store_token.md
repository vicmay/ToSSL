# ::tossl::oauth2::store_token

Securely store an OAuth2 token using simple encryption.

## Syntax

    tossl::oauth2::store_token -token_data <json> -encryption_key <key>

- `-token_data <json>`: The token data as a JSON string
- `-encryption_key <key>`: The encryption key to use (must not be empty)

## Description

Encrypts and stores the provided OAuth2 token data using a simple XOR-based scheme (for demonstration only; not secure for production). The result can be loaded and decrypted using `tossl::oauth2::load_token`.

## Output

Returns the encrypted token data as a hex string.

## Examples

```tcl
set token_data "{\"access_token\":\"abc123\",\"expires_in\":3600}"
set key "testkey"
set encrypted [tossl::oauth2::store_token -token_data $token_data -encryption_key $key]
puts $encrypted
# Output: (hex string)

set decrypted [tossl::oauth2::load_token -encrypted_data $encrypted -encryption_key $key]
puts $decrypted
# Output: {"access_token":"abc123","expires_in":3600}
```

## Error Handling

- If the encryption key is empty, an error is returned:

```tcl
tossl::oauth2::store_token -token_data $token_data -encryption_key ""
# Error: Empty encryption key
```

- If required arguments are missing, an error is returned:

```tcl
tossl::oauth2::store_token -token_data $token_data
# Error: wrong # args: should be "tossl::oauth2::store_token -token_data <dict> -encryption_key <key>"
```

## Security Notes

- The encryption used is for demonstration only and is NOT secure for production use. Use a proper cryptographic library for real applications. 