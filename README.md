# OpenTSSL: Tcl OpenSSL Extension

OpenTSSL is a Tcl extension that provides access to OpenSSL cryptographic functions from Tcl scripts. The goal is to mirror the capabilities of the OpenSSL library and command-line tool, making them available as Tcl commands.

---

## Features (in progress)
- Message digests (hash functions) for any OpenSSL-supported algorithm
- Cryptographically secure random bytes
- (Planned) Symmetric encryption/decryption
- (Planned) Public key cryptography (RSA, etc.)
- (Planned) X.509 certificate parsing and creation
- (Planned) HMAC, encoding, and more

---

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

### RSA Key Generation, Encryption, and Decryption
Generate an RSA key pair, encrypt with the public key, and decrypt with the private key:
```tcl
# Generate RSA key pair (default 2048 bits)
set keys [opentssl::rsa::generate]
set pub [dict get $keys public]
set priv [dict get $keys private]

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

### `opentssl::rsa::generate ?-bits <n>?`
Generates an RSA key pair. Default is 2048 bits.
- Returns: Tcl dict with keys `public` and `private` (both PEM-encoded strings).

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
