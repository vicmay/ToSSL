# OpenTSSL TODO: OpenSSL Function Coverage and Implementation Steps

**Status:** All major features implemented. Codebase is fully OpenSSL 3.x compliant and warning-free. EVP_PKEY/EVP_PKEY_CTX APIs are used everywhere. Deprecated OpenSSL APIs are eliminated.

This TODO lists the major areas and functions of OpenSSL that can be exposed to Tcl via the OpenTSSL extension. For each area, implementation steps are outlined. Some functions can be grouped under a single Tcl command for usability.

## 1. Message Digests (Hash Functions)
- **Functions:**
  - EVP_DigestInit, EVP_DigestUpdate, EVP_DigestFinal, EVP_sha256, EVP_sha512, EVP_md5, etc.
- **Tcl Commands:**
  - `opentssl::digest -alg <name> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Fully OpenSSL 3.x compliant. All deprecated APIs removed.
  - Implemented as `opentssl::digest -alg <name> <data>`, supporting all OpenSSL digest algorithms (e.g., sha256, sha512, md5).
  - Usage example:
    ```tcl
    set hash [opentssl::digest -alg sha256 "hello world"]
    puts "SHA256: $hash"
    ```

## 2. Symmetric Encryption/Decryption
- **Functions:**
  - EVP_EncryptInit, EVP_EncryptUpdate, EVP_EncryptFinal, EVP_DecryptInit, EVP_DecryptUpdate, EVP_DecryptFinal, EVP_aes_128_cbc, EVP_aes_256_gcm, etc.
- **Tcl Commands:**
  - `opentssl::encrypt -alg <name> -key <key> -iv <iv> <data>`
  - `opentssl::decrypt -alg <name> -key <key> -iv <iv> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as `opentssl::encrypt` and `opentssl::decrypt` using the OpenSSL EVP interface.
  - Supports any cipher available in your OpenSSL build (e.g., aes-128-cbc, aes-256-cbc).
  - Usage example:
    ```tcl
    set key [binary format H* 00112233445566778899aabbccddeeff]
    set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
    set plaintext "Secret message!"
    set ciphertext [opentssl::encrypt -alg aes-128-cbc -key $key -iv $iv $plaintext]
    set decrypted [opentssl::decrypt -alg aes-128-cbc -key $key -iv $iv $ciphertext]
    puts "Decrypted: $decrypted"
    ```

## 3. Public Key Cryptography
- **Functions:**
  - All RSA, DSA, and EC key operations now use EVP_PKEY and EVP_PKEY_CTX exclusively. All deprecated APIs (RSA_new, DSA_new, EC_KEY_new, etc.) are eliminated.
- **Tcl Commands:**
  - `opentssl::rsa::generate`, `opentssl::rsa::encrypt`, `opentssl::rsa::decrypt`, `opentssl::rsa::sign`, `opentssl::rsa::verify`
- **Status:** ✅ **Completed (Key generation, encrypt, decrypt, sign, verify)**
- **Notes:**
  - RSA, DSA, and EC key generation, parsing, and writing are fully supported using OpenSSL 3.x-compliant EVP_PKEY APIs.
  - EC key parsing and writing are now supported.
  - Usage example:
    ```tcl
    set keys [opentssl::rsa::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    set ciphertext [opentssl::rsa::encrypt -pubkey $pub "Hello, RSA!"]
    set decrypted [opentssl::rsa::decrypt -privkey $priv $ciphertext]
    puts "Decrypted: $decrypted"
    ```
  - See README for more usage examples.

## 4. Random Number Generation
- **Functions:**
  - RAND_bytes, RAND_pseudo_bytes
- **Tcl Commands:**
  - `opentssl::randbytes <n>`
- **Status:** ✅ **Completed**
- **Notes:**
  - Implemented as `opentssl::randbytes <n>`, returns a Tcl byte array of length `<n>`.

## 5. X.509 Certificates
- **Functions:**
  - X.509 certificate parsing, creation, and verification are fully supported and compliant with OpenSSL 3.x best practices.
- **Tcl Commands:**
  - `opentssl::x509::parse`, `opentssl::x509::create`, `opentssl::x509::verify`
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
  - `opentssl::key::generate`, `opentssl::key::parse`, `opentssl::key::write`
- **Status:** ✅ **Key generation (RSA, DSA, EC) completed**
- **Notes:**
  - Implemented `opentssl::key::generate` for RSA, DSA, and EC keys (default: RSA 2048 bits, DSA 2048 bits, EC prime256v1).
  - Supports both PEM and DER formats for key parsing and writing.
  - Usage example (RSA):
    ```tcl
    set keys [opentssl::key::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (DSA):
    ```tcl
    set keys [opentssl::key::generate -type dsa -bits 2048]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (EC):
    ```tcl
    set keys [opentssl::key::generate -type ec -curve prime256v1]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
  - Usage example (DER parse):
    ```tcl
    set info [opentssl::key::parse $der_bytes]
    ```

### DSA/EC Signing and Verification
- **Status:** ✅ **Completed**
- **Notes:**
  - Tcl commands for DSA and EC signing and verification are implemented:
    - `opentssl::dsa::sign`, `opentssl::dsa::verify`
    - `opentssl::ec::sign`, `opentssl::ec::verify`
  - Usage example (DSA):
    ```tcl
    set sig [opentssl::dsa::sign -privkey $priv -alg sha256 $data]
    set ok [opentssl::dsa::verify -pubkey $pub -alg sha256 $data $sig]
    ```
  - Usage example (EC):
    ```tcl
    set sig [opentssl::ec::sign -privkey $priv -alg sha256 $data]
    set ok [opentssl::ec::verify -pubkey $pub -alg sha256 $data $sig]
    ```


## 7. HMAC
- **Functions:**
  - HMAC, HMAC_Init_ex, HMAC_Update, HMAC_Final
- **Tcl Commands:**
  - `opentssl::hmac -alg <name> -key <key> <data>`
- **Steps:**
  1. Implement HMAC command supporting all OpenSSL digests.

---

## 8. Base64/Hex Encoding/Decoding
- **Functions:**
  - EVP_EncodeBlock, EVP_DecodeBlock
- **Tcl Commands:**
  - `opentssl::base64::encode`, `opentssl::base64::decode`, `opentssl::hex::encode`, `opentssl::hex::decode`
- **Steps:**
  1. Implement encoding/decoding commands.

## 9. PKCS#12, PKCS#7, S/MIME
- **Functions:**
  - PKCS12_create, PKCS12_parse, PKCS7_sign, PKCS7_verify, etc.
- **Tcl Commands:**
  - `opentssl::pkcs12::parse`, `opentssl::pkcs12::create`, etc.
- **Steps:**
  1. Implement as needed for certificate/key management.

## 10. SSL/TLS Context/Session (Advanced)
- **Functions:**
  - SSL_new, SSL_CTX_new, SSL_connect, SSL_accept, etc.
- **Tcl Commands:**
  - (Usually handled by the `tls` package, but can be exposed for advanced use.)
- **Steps:**
  1. Consider only if needed beyond existing Tcl `tls` package.

---

# General Implementation Steps
1. For each command, define the Tcl command signature and expected arguments.
2. Implement the command in C using the relevant OpenSSL APIs.
3. Add proper error handling and memory management.
4. Write tests and example Tcl scripts for each command.
5. Update documentation and pkgIndex.tcl as new commands are added.

---

# Notes
- Some OpenSSL features are very advanced or rarely used; prioritize based on user needs.
- For full coverage, consult the OpenSSL documentation: https://www.openssl.org/docs/manmaster/man3/
