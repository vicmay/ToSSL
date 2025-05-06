# OpenTSSL: Tcl OpenSSL Extension

OpenTSSL is a Tcl extension that provides access to OpenSSL cryptographic functions from Tcl scripts. The goal is to mirror the capabilities of the OpenSSL library and command-line tool, making them available as Tcl commands.

---

## Features
- Message digests (hash functions) for any OpenSSL-supported algorithm
- Cryptographically secure random bytes
- Symmetric encryption/decryption (all OpenSSL ciphers supported)
- Public key cryptography (RSA, DSA, EC): key generation, parsing, writing, encryption, decryption, signing, verifying (PEM and DER supported)
- X.509 certificate parsing, creation, and verification
- HMAC (all OpenSSL digests supported)
- Base64 and hex encoding/decoding
- PKCS#12 parsing and creation (import/export certificates and keys)
- (Planned) PKCS#7, S/MIME, and more

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

### `opentssl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?`
Signs data using PKCS#7 format (S/MIME/CMS) with the provided certificate and private key.
- `-cert <cert>`: PEM certificate (string)
- `-key <key>`: PEM private key (string)
- `<data>`: Data to sign (byte array or string)
- `-detached 0|1`: 1 for detached signature (default), 0 for attached
- `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- Returns: PKCS#7 signature (PEM string or DER byte array)

### `opentssl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?`
Verifies a PKCS#7 signature (detached or attached) using the provided CA certificate.
- `-ca <ca>`: PEM CA certificate (string)
- `<pkcs7>`: PKCS#7 signature (PEM string or DER byte array)
- `<data>`: Data to verify (byte array or string)
- `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- Returns: 1 if signature is valid, 0 otherwise

### `opentssl::pkcs7::encrypt -cert <cert1> ?-cert <cert2> ...? ?-cipher <cipher>? <data> ?-pem 0|1?`
Encrypts data to one or more recipients using PKCS#7 enveloped data (S/MIME/CMS).
- `-cert <cert>`: PEM certificate for a recipient (may be specified multiple times)
- `-cipher <cipher>`: Symmetric cipher to use (default: aes-256-cbc; e.g. aes-128-cbc, des-ede3-cbc)
- `<data>`: Data to encrypt (byte array or string)
- `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- Returns: PKCS#7 envelope (PEM string or DER byte array)

### `opentssl::pkcs7::decrypt -key <key> -cert <cert> <pkcs7> ?-pem 0|1?`
Decrypts PKCS#7 enveloped data (S/MIME/CMS) using the provided private key and certificate.
- `-key <key>`: PEM private key (string)
- `-cert <cert>`: PEM certificate (string)
- `<pkcs7>`: PKCS#7 envelope (PEM string or DER byte array)
- `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- Returns: Decrypted data (byte array)

### `opentssl::pkcs7::info <pkcs7> ?-pem 0|1?`
Returns a Tcl dict describing the PKCS#7 structure (type, signers, recipients, cipher).
- `<pkcs7>`: PKCS#7 envelope or signature (PEM string or DER byte array)
- `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- Returns: Tcl dict with keys:
  - `type`: PKCS#7 type (e.g., signed, enveloped)
  - `signers`: list of {issuer serial} for signed data
  - `recipients`: list of {issuer serial} for enveloped data
  - `cipher`: encryption algorithm for enveloped data

#### Usage Example
```tcl
set info [opentssl::pkcs7::info $pkcs7]
puts "Type: [dict get $info type]"
if {[dict exists $info signers]} {
    puts "Signers: [dict get $info signers]"
}
if {[dict exists $info recipients]} {
    puts "Recipients: [dict get $info recipients]"
    puts "Cipher: [dict get $info cipher]"
}
```
- For signed data, `signers` is a list of dicts with `issuer` and `serial`.
- For enveloped data, `recipients` is a list of dicts with `issuer` and `serial`, and `cipher` is the encryption algorithm.

### `opentssl::digest -alg <name> <data>`
Computes the hash of `<data>` using the specified digest algorithm (e.g., sha256, sha512, md5).
- Returns: Hex-encoded string of the digest.

### `opentssl::encrypt -alg <name> -key <key> -iv <iv> <data>`
Encrypts `<data>` using the specified cipher, key, and IV.
- `-alg <name>`: Cipher name (e.g., aes-128-cbc, aes-256-cbc)
- `-key <key>`: Byte array key (must match cipher requirements)
- `-iv <iv>`: Byte array IV (must match cipher requirements)
- `<data>`: Data to encrypt (byte array or string)
- Returns: Ciphertext as a Tcl byte array.

### `opentssl::decrypt -alg <name> -key <key> -iv <iv> <data>`
Decrypts `<data>` using the specified cipher, key, and IV.
- Parameters as above.
- Returns: Decrypted plaintext as a Tcl byte array.

### `opentssl::randbytes <n>`
Generates `<n>` random bytes (as a Tcl byte array).
- Returns: Byte array of length `<n>`.

### `opentssl::base64::encode <data>`
Encodes binary or string data to Base64.
- Returns: Base64-encoded string.

### `opentssl::base64::decode <b64>`
Decodes a Base64 string to binary data.
- Returns: Tcl byte array.

### `opentssl::hex::encode <data>`
Encodes binary data to a hex string.
- Returns: Hex-encoded string.

### `opentssl::hex::decode <hex>`
Decodes a hex string to binary data.
- Returns: Tcl byte array.

### `opentssl::hmac -alg <name> -key <key> <data>`
Computes the HMAC of `<data>` using the specified digest algorithm and key.
- `-alg <name>`: Digest algorithm (e.g., sha256, sha512, md5)
- `-key <key>`: Key as a Tcl byte array
- `<data>`: Data to HMAC (byte array or string)
- Returns: HMAC as a hex string.

### `opentssl::pkcs12::parse <data>`
Parses a PKCS#12 (PFX) bundle and returns a Tcl dict with PEM-encoded certificate, private key, and CA chain.
- `<data>`: PKCS#12 binary data (Tcl byte array)
- Returns: Tcl dict with keys `cert`, `key`, and `ca` (list of PEM CA certs, if present).

### `opentssl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>`
Creates a PKCS#12 (PFX) bundle from PEM certificate, private key, optional CA chain, and password.
- `-cert <cert>`: PEM certificate (string)
- `-key <key>`: PEM private key (string)
- `-ca <ca>`: PEM CA chain (string, concatenated PEMs; optional)
- `-password <pw>`: password for the PKCS#12 bundle (string)
- Returns: PKCS#12 binary data as a Tcl byte array.


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

### `opentssl::hmac -alg <name> -key <key> <data>`
Computes the HMAC of `<data>` using the specified digest algorithm and key.
- `-alg <name>`: Digest algorithm (e.g., sha256, sha512, md5)
- `-key <key>`: Key as a Tcl byte array
- `<data>`: Data to HMAC (byte array or string)
- Returns: HMAC as a hex string
- Usage example:
```tcl
set key [binary format H* 00112233445566778899aabbccddeeff]
set data "hello world"
set mac [opentssl::hmac -alg sha256 -key $key $data]
puts "HMAC: $mac"
```

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

## Encoding and Decoding

### Base64 Encoding
Encode binary or string data to Base64:
```tcl
set b64 [opentssl::base64::encode $data]
puts "Base64: $b64"
```

### Base64 Decoding
Decode Base64 string to binary data:
```tcl
set bin [opentssl::base64::decode $b64]
puts "Decoded: $bin"
```

### Hex Encoding
Encode binary data to hex string:
```tcl
set hex [opentssl::hex::encode $data]
puts "Hex: $hex"
```

### Hex Decoding
Decode hex string to binary data:
```tcl
set bin [opentssl::hex::decode $hex]
puts "Decoded: $bin"
```

---

## PKCS#12: Import/Export Certificates and Keys

### Parse PKCS#12 Bundle
Parse a PKCS#12 (PFX) bundle and extract certificate, private key, and CA chain:
```tcl
set f [open "bundle.p12" rb]
set p12 [read $f]
close $f
set info [opentssl::pkcs12::parse $p12]
puts "Certificate: [dict get $info cert]"
puts "Private key: [dict get $info key]"
puts "CA chain: [dict get $info ca]"
```
- **Arguments:**
  - `<data>`: PKCS#12 binary data (Tcl byte array)
- **Returns:** Tcl dict with keys:
  - `cert`: PEM certificate (string)
  - `key`: PEM private key (string)
  - `ca`: List of PEM CA certificates (if present)

### Create PKCS#12 Bundle
Create a PKCS#12 (PFX) bundle from PEM certificate, private key, optional CA chain, and password:
```tcl
set cert ... ;# PEM certificate
set key ...  ;# PEM private key
set ca ...   ;# PEM CA chain (optional, may be "")
set p12 [opentssl::pkcs12::create -cert $cert -key $key -ca $ca -password "secret"]
set f [open "bundle.p12" wb]
puts -nonewline $f $p12
close $f
```
- **Arguments:**
  - `-cert <cert>`: PEM certificate (string)
  - `-key <key>`: PEM private key (string)
  - `-ca <ca>`: PEM CA chain (string, concatenated PEMs; optional)
  - `-password <pw>`: password for the PKCS#12 bundle (string)
- **Returns:** PKCS#12 binary data as a Tcl byte array

---

## PKCS#7: Signing and Verification (Detached/Attached)

### Sign Data (PKCS#7 Signature)
Create a PKCS#7 signature (detached or attached) in PEM or DER format:

#### Detached signature (PEM output, default):
```tcl
set sig [opentssl::pkcs7::sign -cert $cert -key $key $data]
set f [open "sig.p7s" w]
puts -nonewline $f $sig
close $f
```
#### Attached signature (DER output):
```tcl
set sig [opentssl::pkcs7::sign -cert $cert -key $key -detached 0 -pem 0 $data]
set f [open "sig.p7m" wb]
puts -nonewline $f $sig
close $f
```
- **Arguments:**
  - `-cert <cert>`: PEM certificate (string)
  - `-key <key>`: PEM private key (string)
  - `<data>`: Data to sign (byte array or string)
  - `-detached 0|1`: 1 for detached signature (default), 0 for attached
  - `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- **Returns:** PKCS#7 signature (PEM string or DER byte array)

### Verify PKCS#7 Signature
Verify a PKCS#7 signature (detached or attached, PEM or DER input):

#### Detached signature (PEM input, default):
```tcl
set ok [opentssl::pkcs7::verify -ca $ca $sig $data]
puts "Valid? $ok"
```
#### Attached signature (DER input):
```tcl
set ok [opentssl::pkcs7::verify -ca $ca -pem 0 $sig $data]
puts "Valid? $ok"
```
- **Arguments:**
  - `-ca <ca>`: PEM CA certificate (string)
  - `<sig>`: PKCS#7 signature (PEM string or DER byte array)
  - `<data>`: Data to verify (byte array or string)
  - `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- **Returns:** 1 if signature is valid, 0 otherwise

### Encrypt Data (PKCS#7 Envelope)
Encrypt data for one or more recipients using PKCS#7 (S/MIME enveloped data):

#### Single recipient, PEM output (default):
```tcl
set env [opentssl::pkcs7::encrypt -cert $cert $data]
set f [open "env.p7m" w]
puts -nonewline $f $env
close $f
```
#### Multiple recipients, custom cipher, DER output:
```tcl
set env [opentssl::pkcs7::encrypt -cert $cert1 -cert $cert2 -cipher aes-128-cbc -pem 0 $data]
set f [open "env.p7m" wb]
puts -nonewline $f $env
close $f
```
- **Arguments:**
  - `-cert <cert>`: PEM certificate for a recipient (may be specified multiple times)
  - `-cipher <cipher>`: Symmetric cipher (default: aes-256-cbc)
  - `<data>`: Data to encrypt (byte array or string)
  - `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- **Returns:** PKCS#7 envelope (PEM string or DER byte array)

### Decrypt PKCS#7 Envelope
Decrypt PKCS#7 enveloped data using your private key and certificate:

#### PEM input (default):
```tcl
set plain [opentssl::pkcs7::decrypt -key $key -cert $cert $env]
puts "Decrypted: $plain"
```
#### DER input:
```tcl
set plain [opentssl::pkcs7::decrypt -key $key -cert $cert -pem 0 $env]
puts "Decrypted: $plain"
```
- **Arguments:**
  - `-key <key>`: PEM private key (string)
  - `-cert <cert>`: PEM certificate (string)
  - `<env>`: PKCS#7 envelope (PEM string or DER byte array)
  - `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- **Returns:** Decrypted data (byte array)

---

## Development Roadmap
See [TODO.md](TODO.md) for a list of planned features and implementation steps.

- As new commands are added, they will be documented here.

---

## License
MIT or similar open-source license (to be specified).
