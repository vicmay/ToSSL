# ToSSL TODO: OpenSSL Function Coverage and Implementation Steps

**Status:** All major features implemented. Codebase is fully OpenSSL 3.x compliant and warning-free. EVP_PKEY/EVP_PKEY_CTX APIs are used everywhere. Deprecated OpenSSL APIs are eliminated.

This TODO lists the major areas and functions of OpenSSL that can be exposed to Tcl via the ToSSL extension. For each area, implementation steps are outlined. Some functions can be grouped under a single Tcl command for usability.

## 1. Message Digests (Hash Functions)
- **Functions:**
  - EVP_DigestInit, EVP_DigestUpdate, EVP_DigestFinal, EVP_sha256, EVP_sha512, EVP_md5, etc.
- **Tcl Commands:**
  - `tossl::digest -alg <name> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Fully OpenSSL 3.x compliant. All deprecated APIs removed.
  - Implemented as `tossl::digest -alg <name> <data>`, supporting all OpenSSL digest algorithms (e.g., sha256, sha512, md5).
  - Usage example:
    ```tcl
    set hash [tossl::digest -alg sha256 "hello world"]
    puts "SHA256: $hash"
    ```

## 2. Symmetric Encryption/Decryption
- **Functions:**
  - EVP_EncryptInit, EVP_EncryptUpdate, EVP_EncryptFinal, EVP_DecryptInit, EVP_DecryptUpdate, EVP_DecryptFinal, EVP_aes_128_cbc, EVP_aes_256_gcm, etc.
- **Tcl Commands:**
  - `tossl::encrypt -alg <name> -key <key> -iv <iv> <data>`
  - `tossl::decrypt -alg <name> -key <key> -iv <iv> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as `tossl::encrypt` and `tossl::decrypt` using the OpenSSL EVP interface.
  - Supports any cipher available in your OpenSSL build (e.g., aes-128-cbc, aes-256-cbc).
  - Usage example:
    ```tcl
    set key [binary format H* 00112233445566778899aabbccddeeff]
    set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
    set plaintext "Secret message!"
    set ciphertext [tossl::encrypt -alg aes-128-cbc -key $key -iv $iv $plaintext]
    set decrypted [tossl::decrypt -alg aes-128-cbc -key $key -iv $iv $ciphertext]
    puts "Decrypted: $decrypted"
    ```

## 3. Public Key Cryptography
- **Functions:**
  - All RSA, DSA, and EC key operations now use EVP_PKEY and EVP_PKEY_CTX exclusively. All deprecated APIs (RSA_new, DSA_new, EC_KEY_new, etc.) are eliminated.
- **Tcl Commands:**
  - `tossl::rsa::generate`, `tossl::rsa::encrypt`, `tossl::rsa::decrypt`, `tossl::rsa::sign`, `tossl::rsa::verify`
- **Status:** ✅ **Completed (Key generation, encrypt, decrypt, sign, verify)**
- **Notes:**
  - RSA, DSA, and EC key generation, parsing, and writing are fully supported using OpenSSL 3.x-compliant EVP_PKEY APIs.
  - EC key parsing and writing are now supported.
  - Usage example:
    ```tcl
    set keys [tossl::rsa::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    set ciphertext [tossl::rsa::encrypt -pubkey $pub "Hello, RSA!"]
    set decrypted [tossl::rsa::decrypt -privkey $priv $ciphertext]
    puts "Decrypted: $decrypted"
    ```
  - See README for more usage examples.

## 4. Random Number Generation
- **Functions:**
  - RAND_bytes, RAND_pseudo_bytes
- **Tcl Commands:**
  - `tossl::randbytes <n>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as `tossl::randbytes <n>`, returns a Tcl byte array of length `<n>`.

## 5. X.509 Certificates
- **Functions:**
  - X.509 certificate parsing, creation, and verification are fully supported and compliant with OpenSSL 3.x best practices.
- **Tcl Commands:**
  - `tossl::x509::parse`, `tossl::x509::create`, `tossl::x509::verify`
- **Status:** ✅ **Completed (Parsing, Creation, Verification)**
- **Notes:**
  - Parsing, creation, and verification of PEM X.509 certificates are implemented and tested.
  - See README for usage examples.
- **TODO:**
  - Add support for more X.509 fields and extensions (e.g., subjectAltName, keyUsage, etc).


## 6. Key Generation and Management
- **Functions:**
  - EVP_PKEY_new, EVP_PKEY_assign_RSA, EVP_PKEY_assign_DSA, EVP_PKEY_assign_EC_KEY, PEM_write_bio_PrivateKey, PEM_read_bio_PrivateKey, etc.
- **Tcl Commands:**
  - `tossl::key::generate`, `tossl::key::parse`, `tossl::key::write`
- **Status:** ✅ **Key generation (RSA, DSA, EC) completed**
- **Notes:**
  - Implemented `tossl::key::generate` for RSA, DSA, and EC keys (default: RSA 2048 bits, DSA 2048 bits, EC prime256v1).
  - Supports both PEM and DER formats for key parsing and writing.
  - Usage example (RSA):
    ```tcl
    set keys [tossl::key::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (DSA):
    ```tcl
    set keys [tossl::key::generate -type dsa -bits 2048]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (EC):
    ```tcl
    set keys [tossl::key::generate -type ec -curve prime256v1]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (DER parse):
    ```tcl
    set info [tossl::key::parse $der_bytes]
    ```

### DSA/EC Signing and Verification
- **Status:** ✅ **Completed**
- **Notes:**
  - Tcl commands for DSA and EC signing and verification are implemented:
    - `tossl::dsa::sign`, `tossl::dsa::verify`
    - `tossl::ec::sign`, `tossl::ec::verify`
  - Usage example (DSA):
    ```tcl
    set sig [tossl::dsa::sign -privkey $priv -alg sha256 $data]
    set ok [tossl::dsa::verify -pubkey $pub -alg sha256 $data $sig]
    ```
  - Usage example (EC):
    ```tcl
    set sig [tossl::ec::sign -privkey $priv -alg sha256 $data]
    set ok [tossl::ec::verify -pubkey $pub -alg sha256 $data $sig]
    ```


## 7. HMAC
- **Functions:**
  - HMAC, HMAC_Init_ex, HMAC_Update, HMAC_Final, EVP_MAC, EVP_MAC_CTX, EVP_MAC_init, etc.
- **Tcl Commands:**
  - `tossl::hmac -alg <name> -key <key> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as `tossl::hmac -alg <name> -key <key> <data>` using OpenSSL 3.x EVP_MAC APIs.
  - Supports all OpenSSL digest algorithms (e.g., sha256, sha512, md5).
  - Returns HMAC as a hex string (for consistency with digest).
  - Usage example:
    ```tcl
    set key [binary format H* 00112233445566778899aabbccddeeff]
    set data "hello world"
    set mac [tossl::hmac -alg sha256 -key $key $data]
    puts "HMAC: $mac"
    ```

---

## 8. Base64/Hex Encoding/Decoding
- **Functions:**
  - EVP_EncodeBlock, EVP_DecodeBlock
- **Tcl Commands:**
  - `tossl::base64::encode`, `tossl::base64::decode`, `tossl::hex::encode`, `tossl::hex::decode`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as four Tcl commands using OpenSSL APIs.
  - Usage example (Base64 encode):
    ```tcl
    set b64 [tossl::base64::encode $data]
    puts "Base64: $b64"
    ```
  - Usage example (Base64 decode):
    ```tcl
    set bin [tossl::base64::decode $b64]
    puts "Decoded: $bin"
    ```
  - Usage example (Hex encode):
    ```tcl
    set hex [tossl::hex::encode $data]
    puts "Hex: $hex"
    ```
  - Usage example (Hex decode):
    ```tcl
    set bin [tossl::hex::decode $hex]
    puts "Decoded: $bin"
    ```

## 9. PKCS#12
- **Functions:**
  - PKCS12_create, PKCS12_parse
- **Tcl Commands:**
  - `tossl::pkcs12::parse <data>`
  - `tossl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>`
- **Status:** ✅ **Completed**
- **Notes:**
  - PKCS#12 parsing and creation are fully supported.
  - `tossl::pkcs12::parse <data>` parses a PKCS#12 bundle and returns a dict with PEM-encoded cert, key, and ca.
  - `tossl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>` creates a PKCS#12 bundle from PEM cert, key, ca, and password.
  - Usage examples:
    ```tcl
    # Parse PKCS#12
    set f [open "bundle.p12" rb]
    set p12 [read $f]
    close $f
    set info [tossl::pkcs12::parse $p12]
    puts "Certificate: [dict get $info cert]"
    puts "Private key: [dict get $info key]"
    puts "CA chain: [dict get $info ca]"
    # Create PKCS#12
    set cert ... ;# PEM certificate
    set key ...  ;# PEM private key
    set ca ...   ;# PEM CA chain (optional, may be "")
    set p12 [tossl::pkcs12::create -cert $cert -key $key -ca $ca -password "secret"]
    set f [open "bundle.p12" wb]
    puts -nonewline $f $p12
    close $f
    ```

## 10. PKCS#7, S/MIME
- **Functions:**
  - PKCS7_sign, PKCS7_verify, PKCS7_encrypt, PKCS7_decrypt, S/MIME APIs
- **Tcl Commands:**
  - `tossl::pkcs7::sign -cert <cert> -key <key> <data>`
  - `tossl::pkcs7::verify -ca <ca> <pkcs7> <data>`
  - `tossl::pkcs7::encrypt -cert <cert> <data>`
  - `tossl::pkcs7::decrypt -key <key> -cert <cert> <pkcs7>`
- **Status:** ✅ **Complete**
- **Notes:**
  - PKCS#7/S-MIME sign, verify, encrypt, and decrypt commands are implemented and documented.
  - Multi-recipient encryption and cipher selection are implemented and documented.
  - Usage examples and API documentation are available in the README.
  - Next steps (optional): diagnostics/info command for PKCS#7, test/demo scripts for PKCS#7/S-MIME workflows.

## 11. SSL/TLS Context/Session (Advanced)
- **Functions:**
  - SSL_new, SSL_CTX_new, SSL_connect, SSL_accept, SSL_SESSION, i2d_SSL_SESSION, d2i_SSL_SESSION, BIO, etc.
- **Tcl Commands:**
  - `tossl::ssl::context create ...` — Create an SSL/TLS context with options for protocols, ciphers, certificates, etc.
  - `tossl::ssl::socket <ctx> <sock> ?-session <sessionhandle>?` — Wrap a Tcl socket with SSL, optionally resuming a session.
  - `tossl::ssl::session export <sslsock>` — Export the current session as a base64 string (for resumption).
  - `tossl::ssl::session import <ctx> <base64blob>` — Import a session from a base64 string, returning a session handle.
  - `tossl::ssl::session info <sslsock>` — Get session/cipher/peer info as a Tcl dict.
  - `tossl::ssl::connect <sslsock>` — Perform SSL/TLS handshake as client.
  - `tossl::ssl::accept <sslsock>` — Perform SSL/TLS handshake as server.
  - `tossl::ssl::read <sslsock> ?nbytes?` — Read from SSL connection.
  - `tossl::ssl::write <sslsock> <data>` — Write to SSL connection.
  - `tossl::ssl::close <sslsock>` — Close SSL connection and free resources.
- **Status:** ✅ **Completed (Session resumption, export/import, custom verification, robust error handling, and documentation)**
- **Notes:**
  - Session resumption is supported via export/import commands and the `-session` option to `tossl::ssl::socket`.
  - Custom certificate verification and context options are available.
  - All commands include robust error handling and clear error messages.
  - Comprehensive documentation and usage examples are provided in the README.
  - Usage example (session export/import):
    ```tcl
    # Create context and wrap socket
    set ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3}]
    set sslsock [tossl::ssl::socket $ctx $sock]
    # Perform handshake
    tossl::ssl::connect $sslsock
    # Export session
    set sess [tossl::ssl::session export $sslsock]
    # Later, import session for resumption
    set sesshandle [tossl::ssl::session import $ctx $sess]
    set sslsock2 [tossl::ssl::socket $ctx $sock2 -session $sesshandle]
    tossl::ssl::connect $sslsock2
    ```
  - See README for further details and advanced usage.
