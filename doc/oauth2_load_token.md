# ::tossl::oauth2::load_token

Load and decrypt an OAuth2 token from encrypted storage.

## Syntax

    tossl::oauth2::load_token -encrypted_data <data> -encryption_key <key>

- `-encrypted_data <data>`: The encrypted token data (as produced by `tossl::oauth2::store_token`)
- `-encryption_key <key>`: The encryption key used to decrypt the token

## Description

Decrypts and loads an OAuth2 token that was previously stored using `tossl::oauth2::store_token`. The decrypted token is returned as a JSON string, which can be parsed or used as needed.

## Output

Returns the decrypted token JSON string on success.

## Examples

```tcl
set token_data [dict create access_token "test_access_token" refresh_token "test_refresh_token" expires_in 3600 token_type "Bearer"]
set token_json [tossl::json::generate $token_data]
set encryption_key "test_key_12345"
set encrypted_data [tossl::oauth2::store_token -token_data $token_json -encryption_key $encryption_key]
set decrypted_data [tossl::oauth2::load_token -encrypted_data $encrypted_data -encryption_key $encryption_key]
puts $decrypted_data
# Output: {"access_token":"test_access_token",...}
```

## Error Handling

- If the wrong number of arguments is provided, an error is returned:

```tcl
tossl::oauth2::load_token
# Error: wrong # args: should be "tossl::oauth2::load_token -encrypted_data <data> -encryption_key <key>"
```

- If the decryption fails (e.g., wrong key or corrupted data), an error is returned.

## Security Notes

- The encryption used is a simple XOR and hex encoding for demonstration; it is **not secure** for production use.
- Use a strong, random encryption key and a secure storage mechanism for real-world applications.
- Do not expose the encryption key or decrypted token data to untrusted code or users. 