# OpenTSSL: Tcl OpenSSL Extension

OpenTSSL is a Tcl extension that provides access to OpenSSL cryptographic functions from Tcl scripts. The goal is to mirror the capabilities of the OpenSSL library and command-line tool, making them available as Tcl commands.

---

## Features
- Message digests (hash functions) for any OpenSSL-supported algorithm
- Cryptographically secure random bytes
- Symmetric encryption/decryption (all OpenSSL ciphers supported)
- Public key cryptography (RSA, DSA, EC): key generation, parsing, writing, encryption, decryption, signing, verifying (PEM and DER supported)
- X.509 certificate parsing, creation, and verification
- (Planned) HMAC, encoding, and more

---

## OpenSSL 3.x Compliance

OpenTSSL is fully compatible with OpenSSL 3.x. All deprecated API usage has been eliminated. All cryptographic operations use the modern EVP_PKEY and EVP_PKEY_CTX APIs for key generation, parsing, and PEM serialization. The code compiles warning-free with `-Wall -Wextra -Werror` and OpenSSL 3.x.

## Installation

1. Build the extension:
   ```sh
   make
   ```
2. Add the build directory to your Tcl `auto_path`:
   ```tcl
   lappend auto_path /path/to/OPENTSSL
   package require opentssl
   ```

---

## Usage

### X.509 Certificate Verification
Verify that a certificate is signed by a CA:
```tcl
set cert ... ;# PEM certificate
set ca ...   ;# PEM CA certificate or public key
set ok [opentssl::x509::verify -cert $cert -ca $ca]
puts "Valid? $ok"
```

---

### X.509 Certificate Creation
Create and sign a self-signed X.509 certificate:
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [opentssl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365]
puts $cert
```

Add Subject Alternative Names (SAN):
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [opentssl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -san {example.com www.example.com 192.168.1.1}]
puts $cert
```

Add Key Usage extension:
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [opentssl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -keyusage {digitalSignature keyEncipherment}]
puts $cert
```

Allowed keyUsage values:
- digitalSignature
- nonRepudiation
- keyEncipherment
- dataEncipherment
- keyAgreement
- keyCertSign
- cRLSign
- encipherOnly
- decipherOnly

---

### RSA Signing and Verification
Sign and verify data using RSA keys and a digest algorithm:
```tcl
set keys [opentssl::rsa::generate]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "important message"
set sig [opentssl::rsa::sign -privkey $priv -alg sha256 $data]
set ok [opentssl::rsa::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

### DSA Signing and Verification
Sign and verify data using DSA keys:
```tcl
set keys [opentssl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set sig [opentssl::dsa::sign -privkey $priv -alg sha256 $data]
set ok [opentssl::dsa::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

### EC Signing and Verification
Sign and verify data using EC keys:
```tcl
set keys [opentssl::key::generate -type ec -curve prime256v1]
set priv [dict get $keys private]
set pub [dict get $keys public]
set sig [opentssl::ec::sign -privkey $priv -alg sha256 $data]
set ok [opentssl::ec::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

---

### X.509 Certificate Parsing
Parse a PEM-encoded X.509 certificate and extract its fields:
```tcl
set cert_pem {-----BEGIN CERTIFICATE-----
...your certificate here...
-----END CERTIFICATE-----}
set info [opentssl::x509::parse $cert_pem]
puts "Subject:   [dict get $info subject]"
puts "Issuer:    [dict get $info issuer]"
puts "Serial:    [dict get $info serial]"
puts "Valid From: [dict get $info notBefore]"
puts "Valid To:   [dict get $info notAfter]"
```

---

### Generic Key Generation
Generate an RSA, DSA, or EC key pair:
```tcl
# Generate RSA key pair (default 2048 bits)
set keys [opentssl::key::generate]
# Or specify bit length
set keys [opentssl::key::generate -type rsa -bits 3072]
# Generate DSA key pair (default 2048 bits)
set keys [opentssl::key::generate -type dsa -bits 2048]
# Generate EC key pair (default: prime256v1)
set keys [opentssl::key::generate -type ec -curve prime256v1]
set pub [dict get $keys public]
set priv [dict get $keys private]
```

### RSA Key Generation, Encryption, and Decryption
Generate an RSA key pair, encrypt with the public key, and decrypt with the private key:
```tcl
# Generate RSA key pair (default 2048 bits)
set keys [opentssl::key::generate]
set pub [dict get $keys public]
set priv [dict get $keys private]

#### `opentssl::key::generate`
Creates a new RSA, DSA, or EC key pair.

**Usage (RSA, default):**
```
set keys [opentssl::key::generate]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
**Usage (DSA):**
```
set keys [opentssl::key::generate -type dsa -bits 2048]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
**Usage (EC):**
```
set keys [opentssl::key::generate -type ec -curve prime256v1]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
- The returned dictionary includes `type` ("rsa", "dsa", or "ec"), `bits`, `public`, and `private` PEM strings. EC keys also include a `curve` field.
- Only PEM output is supported for now.
- EC support includes key generation, parsing, and writing.

#### `opentssl::key::parse`
Parses a PEM- or DER-encoded RSA, DSA, or EC key (public or private) and returns a dictionary describing the key.

**Usage (RSA):**
```
set info [opentssl::key::parse $priv]
# $info = {type rsa kind private bits 2048}
```
**Usage (DSA):**
```
set info [opentssl::key::parse $priv]
# $info = {type dsa kind private bits 2048}
```
**Usage (EC):**
```
set info [opentssl::key::parse $priv]
# $info = {type ec kind private curve prime256v1 bits 256}
```
**Usage (DER):**
```
set info [opentssl::key::parse $der_bytes]
# $info = {type ...}
```

#### `opentssl::key::write`
Serializes a key dictionary (as returned by generate or parse, with a 'pem' field) to PEM format.

**Usage:**
```
set pem [opentssl::key::write -key $dict -format pem]
```

**Notes:**
- RSA, DSA, and EC keys in PEM and DER formats are supported for generate/parse/write.
- The key dictionary must contain at least the fields: `type`, `kind`, and `pem`.
- DER support is now available for all key types.

# Encrypt with public key
set plaintext "Hello, RSA!"
set ciphertext [opentssl::rsa::encrypt -pubkey $pub $plaintext]

# Decrypt with private key
set decrypted [opentssl::rsa::decrypt -privkey $priv $ciphertext]
puts "Decrypted: $decrypted"
```

---

### Message Digests (Hash Functions)
Compute a hash using any OpenSSL-supported algorithm:
```tcl
set hash [opentssl::digest -alg sha256 "hello world"]
puts "SHA256: $hash"

set md5 [opentssl::digest -alg md5 "test"]
puts "MD5: $md5"
```

### Symmetric Encryption/Decryption
Encrypt and decrypt data using OpenSSL ciphers (e.g., aes-128-cbc, aes-256-cbc):
```tcl
# Encrypt
set key [binary format H* 00112233445566778899aabbccddeeff]  ;# 16 bytes for AES-128
set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]  ;# 16 bytes
set plaintext "Secret message!"
set ciphertext [opentssl::encrypt -alg aes-128-cbc -key $key -iv $iv $plaintext]

# Decrypt
set decrypted [opentssl::decrypt -alg aes-128-cbc -key $key -iv $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### Random Bytes
Generate cryptographically secure random bytes:
```tcl
set bytes [opentssl::randbytes 16]
puts "Random bytes (hex): [binary encode hex $bytes]"
```

---

## API Reference

### `opentssl::x509::verify -cert <pem> -ca <pem>`
Verifies that the certificate is signed by the provided CA certificate or public key. Returns 1 if valid, 0 otherwise.

### `opentssl::x509::create -subject <dn> -issuer <dn> -pubkey <pem> -privkey <pem> -days <n>`
Creates and signs a new X.509 certificate. Returns the certificate in PEM format.
- `-subject <dn>`: Subject common name (CN)
- `-issuer <dn>`: Issuer common name (CN)
- `-pubkey <pem>`: Public key PEM
- `-privkey <pem>`: Issuer's private key PEM
- `-days <n>`: Validity period in days

### `opentssl::rsa::sign -privkey <pem> -alg <digest> <data>`
Signs the given data with the provided PEM private key and digest algorithm (e.g., sha256). Returns the signature as a Tcl byte array.

### `opentssl::rsa::verify -pubkey <pem> -alg <digest> <data> <signature>`
Verifies the signature using the PEM public key and digest algorithm. Returns 1 if valid, 0 otherwise.

### `opentssl::x509::parse <pem>`
Parses a PEM-encoded X.509 certificate and returns a Tcl dict with the following fields:
- `subject`: Distinguished Name of the subject
- `issuer`: Distinguished Name of the issuer
- `serial`: Serial number (hex)
- `notBefore`: Certificate validity start (human-readable)
- `notAfter`: Certificate validity end (human-readable)

### `opentssl::key::generate ?-bits <n>?`
Generates an RSA key pair. Default is 2048 bits.
- Returns: Tcl dict with keys `public` and `private` (both PEM-encoded strings).

### `opentssl::key::parse <pem>`
Parses a PEM-encoded RSA key (public or private) and returns a dictionary describing the key.

### `opentssl::key::write -key <dict> -format <format>`
Serializes a key dictionary (as returned by generate or parse, with a 'pem' field) to the specified format.

### `opentssl::rsa::encrypt -pubkey <pem> <data>`
Encrypts `<data>` using the provided PEM public key (PKCS#1 OAEP padding).
- Returns: Ciphertext as a Tcl byte array.

### `opentssl::rsa::decrypt -privkey <pem> <ciphertext>`
Decrypts `<ciphertext>` using the provided PEM private key (PKCS#1 OAEP padding).
- Returns: Decrypted plaintext as a Tcl byte array.

### `opentssl::digest -alg <name> <data>`
Computes the hash of `<data>` using the specified algorithm (e.g., sha256, sha512, md5).
- Returns: Hex-encoded string of the digest.

### `opentssl::encrypt -alg <name> -key <key> -iv <iv> <data>`
Encrypts `<data>` using the specified cipher, key, and IV.
- `<name>`: Cipher name (e.g., aes-128-cbc, aes-256-cbc)
- `<key>`: Byte array key (must match cipher requirements)
- `<iv>`: Byte array IV (must match cipher requirements)
- `<data>`: Data to encrypt (byte array or string)
- Returns: Ciphertext as a Tcl byte array.

### `opentssl::decrypt -alg <name> -key <key> -iv <iv> <data>`
Decrypts `<data>` using the specified cipher, key, and IV.
- Parameters as above.
- Returns: Decrypted plaintext as a Tcl byte array.

### `opentssl::randbytes <n>`
Generates `<n>` random bytes (as a Tcl byte array).
- Returns: Byte array of length `<n>`.

---

**Note:** Supported ciphers and parameter lengths depend on your OpenSSL build. Common options include `aes-128-cbc`, `aes-256-cbc`, etc. Key and IV must be the correct length for the chosen cipher.

---

## Development Roadmap
See [TODO.md](TODO.md) for a list of planned features and implementation steps.

- As new commands are added, they will be documented here.

---

## License
MIT or similar open-source license (to be specified).
