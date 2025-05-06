# OpenTSSL TODO: OpenSSL Function Coverage and Implementation Steps

This TODO lists the major areas and functions of OpenSSL that can be exposed to Tcl via the OpenTSSL extension. For each area, implementation steps are outlined. Some functions can be grouped under a single Tcl command for usability.

## 1. Message Digests (Hash Functions)
- **Functions:**
  - EVP_DigestInit, EVP_DigestUpdate, EVP_DigestFinal, EVP_sha256, EVP_sha512, EVP_md5, etc.
- **Tcl Commands:**
  - `opentssl::digest -alg <name> <data>`
- **Status:** ✅ **Completed**
- **Notes:**
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
  - RSA_new, RSA_generate_key_ex, RSA_public_encrypt, RSA_private_decrypt, RSA_sign, RSA_verify, PEM_read_bio_RSAPrivateKey, etc.
  - EVP_PKEY, EVP_PKEY_new, EVP_PKEY_assign_RSA, etc.
- **Tcl Commands:**
  - `opentssl::rsa::generate`, `opentssl::rsa::encrypt`, `opentssl::rsa::decrypt`, `opentssl::rsa::sign`, `opentssl::rsa::verify`
- **Status:** ✅ **Completed (Key generation, encrypt, decrypt)**
- **Notes:**
  - Implemented `opentssl::rsa::generate` for RSA key pair generation (default 2048 bits, PEM output).
  - Implemented `opentssl::rsa::encrypt` and `opentssl::rsa::decrypt` for public key encryption and private key decryption (PKCS#1 OAEP padding, PEM input).
  - Usage example:
    ```tcl
    set keys [opentssl::rsa::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    set ciphertext [opentssl::rsa::encrypt -pubkey $pub "Hello, RSA!"]
    set decrypted [opentssl::rsa::decrypt -privkey $priv $ciphertext]
    puts "Decrypted: $decrypted"
    ```
- **Status:** ✅ **Sign/Verify Completed**
- **Notes:**
  - Implemented `opentssl::rsa::sign -privkey <pem> -alg <digest> <data>` and `opentssl::rsa::verify -pubkey <pem> -alg <digest> <data> <signature>`.
  - See README for usage examples.
- **TODO:**
  - Add support for loading keys from files/strings (beyond PEM in-memory).

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
  - X509_new, X509_free, X509_sign, X509_verify, PEM_read_bio_X509, PEM_write_bio_X509, etc.
- **Tcl Commands:**
  - `opentssl::x509::parse`, `opentssl::x509::create`, `opentssl::x509::sign`, `opentssl::x509::verify`
- **Status:** ✅ **Completed (Parsing)**
- **Notes:**
  - Implemented `opentssl::x509::parse <pem>` to extract subject, issuer, serial, notBefore, notAfter from a PEM X.509 certificate as a Tcl dict.
  - Usage example:
    ```tcl
    set info [opentssl::x509::parse $cert_pem]
    puts "Subject:   [dict get $info subject]"
    puts "Issuer:    [dict get $info issuer]"
    puts "Serial:    [dict get $info serial]"
    puts "Valid From: [dict get $info notBefore]"
    puts "Valid To:   [dict get $info notAfter]"
    ```
- **Status:** ✅ **Creation Completed**
- **Notes:**
  - Implemented `opentssl::x509::create -subject <dn> -issuer <dn> -pubkey <pem> -privkey <pem> -days <n>` for self-signed and CA-signed certificates.
  - See README for usage.
- **Status:** ✅ **Verification Completed**
- **Notes:**
  - Implemented `opentssl::x509::verify -cert <pem> -ca <pem>` to verify certificate signatures.
  - See README for usage.
- **TODO:**
  - Add support for more X.509 fields and extensions (e.g., subjectAltName, keyUsage, etc).

## 6. Key Generation and Management
- **Functions:**
  - EVP_PKEY_new, EVP_PKEY_assign_RSA, EVP_PKEY_assign_DSA, EVP_PKEY_assign_EC_KEY, PEM_write_bio_PrivateKey, PEM_read_bio_PrivateKey, etc.
- **Tcl Commands:**
  - `opentssl::key::generate`, `opentssl::key::parse`, `opentssl::key::write`
- **Status:** ✅ **Key generation (RSA) completed**
- **Notes:**
  - Implemented `opentssl::key::generate` for RSA keys (default 2048 bits, PEM output for public/private).
  - Only RSA is supported for now; DSA/EC planned for future.
  - Usage example:
    ```tcl
    set keys [opentssl::key::generate]
    set pub [dict get $keys public]
    set priv [dict get $keys private]
    ```
- **Status:** ✅ **Key parse/write (RSA/PEM) completed**
- **Notes:**
  - Implemented `opentssl::key::parse` for parsing RSA PEM keys (public/private, returns dict with type/kind/bits).
  - Implemented `opentssl::key::write` for serializing RSA PEM keys from a dict to PEM format.
  - Only RSA keys in PEM format are supported for now; DER and DSA/EC planned for future.
- **Status:** ✅ **EC key generation, parse, and write completed**
- **Notes:**
  - Implemented `opentssl::key::generate -type ec -curve <name>` for EC keypair generation (PEM output, curve name required, e.g., prime256v1).
  - RSA, DSA, and EC key parsing and writing in PEM format are all supported.
  - DER support for all key types is the next milestone.
- **TODO:**
  - Add support for DER format for all key types (RSA, DSA, EC).
  - Extend key parsing/writing to handle additional key metadata and types.

## 7. HMAC
- **Functions:**
  - HMAC, HMAC_Init_ex, HMAC_Update, HMAC_Final
- **Tcl Commands:**
  - `opentssl::hmac -alg <name> -key <key> <data>`
- **Steps:**
  1. Implement HMAC command supporting all OpenSSL digests.

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
