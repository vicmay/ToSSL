# TOSSL: Tcl OpenSSL Extension

TOSSL is a Tcl extension for Linux that provides access to OpenSSL cryptographic functions from Tcl scripts. The goal is to mirror the capabilities of the OpenSSL library and command-line tool, making them available as Tcl commands.

---

## Features
- **Message digests (hash functions)** for any OpenSSL-supported algorithm including SHA-1, SHA-2, SHA-3, BLAKE2, SM3, RIPEMD-160, Whirlpool, MD5, MD4
- **Hash streaming** for large file hashing with `tossl::digest::stream`
- **Hash comparison** with `tossl::digest::compare`
- **Cryptographically secure random bytes** and random key/IV generation
- **Symmetric encryption/decryption** (all OpenSSL ciphers supported) with enhanced cipher information and listing
- **Public key cryptography** (RSA, DSA, EC): key generation, parsing, writing, encryption, decryption, signing, verifying (PEM and DER supported)
- **X.509 certificate operations**: parsing, creation, verification, fingerprinting, and chain validation
- **Certificate Authority (CA) operations**: CA certificate generation and certificate signing
- **Certificate Signing Requests (CSR)**: creation, parsing, validation, fingerprinting, and extension modification
- **Certificate Revocation Lists (CRL)**: creation and parsing
- **Key derivation functions**: PBKDF2, Scrypt, and Argon2 (if supported)
- **HMAC** (all OpenSSL digests supported)
- **Base64 and hex encoding/decoding**
- **PKCS#12 parsing and creation** (import/export certificates and keys)
- **Advanced SSL/TLS support:**
  - SSL/TLS context creation and management with secure defaults
  - SSL/TLS socket wrapping and session resumption (export/import)
  - Custom certificate verification and context options
  - Enhanced session management with caching and tickets
  - Protocol version management and configuration
  - Detailed session/cipher/peer info retrieval
  - Robust error handling for all SSL/TLS commands
- **ACME protocol support:**
  - ACME v2 protocol with full RFC 8555 compliance
  - DNS-01 challenge support for domain validation
  - HTTP/HTTPS client functionality using libcurl
  - JSON parsing and generation using json-c
  - Multiple DNS provider support (Cloudflare, Route53, generic)
  - Certificate lifecycle management (issuance, renewal, revocation)

---

## ACME Protocol Support

TOSSL provides comprehensive ACME (Automated Certificate Management Environment) protocol support for automated SSL/TLS certificate issuance and management using Let's Encrypt and other ACME-compliant certificate authorities.

### ACME Commands

#### `tossl::acme::directory directory_url`
Fetches and parses the ACME directory from the specified URL.

```tcl
set directory [tossl::acme::directory "https://acme-staging-v02.api.letsencrypt.org/directory"]
puts "New account URL: [dict get $directory newAccount]"
puts "New order URL: [dict get $directory newOrder]"
```

#### `tossl::acme::create_account directory_url account_key email ?contact?`
Creates a new ACME account with the specified email address.

```tcl
set account_key [tossl::key::generate -type rsa -bits 2048]
set result [tossl::acme::create_account \
    "https://acme-staging-v02.api.letsencrypt.org/directory" \
    [dict get $account_key private] \
    "admin@example.com"]
```

#### `tossl::acme::create_order directory_url account_key domains`
Creates a new certificate order for the specified domains.

```tcl
set result [tossl::acme::create_order \
    "https://acme-staging-v02.api.letsencrypt.org/directory" \
    $account_key \
    "example.com www.example.com"]
```

#### `tossl::acme::dns01_challenge domain token account_key provider api_key ?zone_id?`
Prepares a DNS-01 challenge by creating the required DNS TXT record.

```tcl
set challenge [tossl::acme::dns01_challenge \
    "example.com" \
    "challenge-token-12345" \
    $account_key \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]

puts "DNS record name: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"
```

#### `tossl::acme::cleanup_dns domain record_name provider api_key ?zone_id?`
Removes the DNS TXT record created for the challenge.

```tcl
set result [tossl::acme::cleanup_dns \
    "example.com" \
    "_acme-challenge.example.com" \
    "cloudflare" \
    "your-cloudflare-api-key" \
    "your-zone-id"]
```

### HTTP/HTTPS Client Support

TOSSL provides a comprehensive HTTP client with both basic and enhanced features for API integration and OAuth2 support.

#### Basic HTTP Commands

##### `tossl::http::get url`
Performs a basic HTTP GET request and returns a dict with status_code, body, and headers.

```tcl
set response [tossl::http::get "https://api.example.com/data"]
puts "Status: [dict get $response status_code]"
puts "Body: [dict get $response body]"
```

##### `tossl::http::post url data`
Performs a basic HTTP POST request with the specified data.

```tcl
set response [tossl::http::post "https://api.example.com/submit" "key=value"]
puts "Status: [dict get $response status_code]"
```

#### Enhanced HTTP Commands (OAuth2-Ready)

##### `tossl::http::get_enhanced url ?options?`
Performs an enhanced HTTP GET request with full control over headers, timeouts, authentication, and SSL options.

```tcl
# OAuth2 Bearer token authentication
set response [tossl::http::get_enhanced "https://api.example.com/users" \
    -headers "Authorization: Bearer $access_token\nAccept: application/json" \
    -timeout 30 \
    -return_details true]

puts "Status: [dict get $response status_code]"
puts "Request time: [dict get $response request_time] ms"
puts "Response size: [dict get $response response_size] bytes"
```

**Available options:**
- `-headers {header1 value1}`: Custom HTTP headers
- `-timeout seconds`: Request timeout in seconds
- `-user_agent string`: Custom user agent string
- `-follow_redirects boolean`: Whether to follow redirects (default: true)
- `-verify_ssl boolean`: Whether to verify SSL certificates (default: true)
- `-proxy url`: Proxy server URL
- `-auth {username:password}`: Basic authentication
- `-return_details boolean`: Include detailed response info (timing, size, etc.)

##### `tossl::http::post_enhanced url data ?options?`
Performs an enhanced HTTP POST request with full control over content-type, headers, and other options.

```tcl
# JSON API call with OAuth2 authentication
set json_data "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}"
set response [tossl::http::post_enhanced "https://api.example.com/users" $json_data \
    -headers "Authorization: Bearer $access_token\nContent-Type: application/json" \
    -content_type "application/json" \
    -timeout 30 \
    -return_details true]
```

**Available options:** Same as `get_enhanced` plus:
- `-content_type type`: Content-Type header value

##### `tossl::http::request -method METHOD -url url ?options?`
Universal HTTP request command supporting all HTTP methods (GET, POST, PUT, DELETE, PATCH).

```tcl
# OAuth2 API calls with different methods
set access_token "your-access-token"

# GET request
set response [tossl::http::request \
    -method GET \
    -url "https://api.example.com/users" \
    -headers "Authorization: Bearer $access_token" \
    -return_details true]

# PUT request
set response [tossl::http::request \
    -method PUT \
    -url "https://api.example.com/users/123" \
    -data "{\"status\": \"active\"}" \
    -headers "Authorization: Bearer $access_token\nContent-Type: application/json" \
    -content_type "application/json"]

# DELETE request
set response [tossl::http::request \
    -method DELETE \
    -url "https://api.example.com/users/123" \
    -headers "Authorization: Bearer $access_token"]
```

#### Session Management

##### `tossl::http::session::create session_id ?options?`
Creates a persistent HTTP session for connection reuse and better performance.

```tcl
set session_id [tossl::http::session::create "api_session" \
    -timeout 30 \
    -user_agent "MyApp/1.0"]
```

##### `tossl::http::session::get session_id url ?-headers {header1 value1}?`
Performs a GET request using a session.

```tcl
set response [tossl::http::session::get $session_id "https://api.example.com/users" \
    -headers "Authorization: Bearer $access_token"]
```

##### `tossl::http::session::post session_id url data ?-headers {header1 value1}? ?-content_type type?`
Performs a POST request using a session.

```tcl
set response [tossl::http::session::post $session_id "https://api.example.com/users" $json_data \
    -headers "Authorization: Bearer $access_token" \
    -content_type "application/json"]
```

##### `tossl::http::session::destroy session_id`
Destroys a session and frees resources.

```tcl
tossl::http::session::destroy $session_id
```

#### File Upload

##### `tossl::http::upload url file_path ?options?`
Uploads a file using multipart form data.

```tcl
set response [tossl::http::upload "https://api.example.com/upload" "/path/to/file.txt" \
    -field_name "file" \
    -additional_fields "description: My file\ncategory: documents" \
    -headers "Authorization: Bearer $access_token"]
```

#### Debug and Metrics

##### `tossl::http::debug enable|disable ?-level verbose|info|warning|error?`
Enables or disables debug logging.

```tcl
tossl::http::debug enable -level info
# Make requests...
tossl::http::debug disable
```

##### `tossl::http::metrics`
Returns performance metrics for all HTTP requests.

```tcl
set metrics [tossl::http::metrics]
puts "Total requests: [dict get $metrics total_requests]"
puts "Average response time: [dict get $metrics avg_response_time] ms"
puts "Total request time: [dict get $metrics total_request_time] ms"
```

### JSON Support

#### `tossl::json::parse json_string`
Parses a JSON string and returns a Tcl dict.

```tcl
set json '{"name": "test", "value": 123, "active": true}'
set data [tossl::json::parse $json]
puts "Name: [dict get $data name]"
puts "Value: [dict get $data value]"
puts "Active: [dict get $data active]"
```

#### `tossl::json::generate tcl_dict`
Generates a JSON string from a Tcl dict.

```tcl
set data [dict create name "test" value 123 active true]
set json [tossl::json::generate $data]
puts "JSON: $json"
```

### Complete Certificate Issuance Example

```tcl
#!/usr/bin/env tclsh

# Load TOSSL
if {[catch {package require tossl}]} {
    load ./libtossl.so
}

# Configuration
set acme_server "https://acme-staging-v02.api.letsencrypt.org/directory"
set domain "example.com"
set email "admin@example.com"
set dns_provider "cloudflare"
set dns_api_key "your-cloudflare-api-key"
set dns_zone_id "your-zone-id"

# Step 1: Generate account key
puts "Generating account key..."
set account_keys [tossl::key::generate -type rsa -bits 2048]
set account_private [dict get $account_keys private]

# Step 2: Create ACME account
puts "Creating ACME account..."
set account_result [tossl::acme::create_account $acme_server $account_private $email]
puts "Account creation: $account_result"

# Step 3: Create certificate order
puts "Creating certificate order..."
set order_result [tossl::acme::create_order $acme_server $account_private $domain]
puts "Order creation: $order_result"

# Step 4: Prepare DNS-01 challenge
puts "Preparing DNS-01 challenge..."
set token "challenge-token-12345"
set challenge [tossl::acme::dns01_challenge \
    $domain $token $account_private $dns_provider $dns_api_key $dns_zone_id]

puts "DNS record name: [dict get $challenge dns_record_name]"
puts "DNS record value: [dict get $challenge dns_record_value]"

# Step 5: Wait for DNS propagation (in real usage)
puts "Waiting for DNS propagation..."
after 30000  ; # Wait 30 seconds

# Step 6: Clean up DNS record
puts "Cleaning up DNS record..."
set cleanup_result [tossl::acme::cleanup_dns \
    $domain \
    [dict get $challenge dns_record_name] \
    $dns_provider \
    $dns_api_key \
    $dns_zone_id]
puts "Cleanup: $cleanup_result"

puts "Certificate issuance process completed!"
```

For detailed ACME documentation, see [ACME-README.md](ACME-README.md).

---

## OpenSSL 3.x Compliance

TOSSL is fully compatible with OpenSSL 3.x. All deprecated API usage has been eliminated. All cryptographic operations use the modern EVP_PKEY and EVP_PKEY_CTX APIs for key generation, parsing, and PEM serialization. The code compiles warning-free with `-Wall -Wextra -Werror` and OpenSSL 3.x.

## Installation

1. Build the extension:
   ```sh
   make
   ```
2. Add the build directory to your Tcl `auto_path`:
   ```tcl
   lappend auto_path /path/to/TOSSL
   package require tossl
   ```

---

## Usage

### Advanced SSL/TLS: Context, Socket, and Session Resumption

#### Create an SSL/TLS Context
```tcl
set ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3} -ciphers "ECDHE+AESGCM" -cert $cert -key $key -cafile $ca -verify 1 -alpn {h2 http/1.1}]
```
- `-protocols`: List of allowed protocol versions (e.g., {TLSv1.2 TLSv1.3})
- `-ciphers`: Cipher string (OpenSSL syntax)
- `-cert`, `-key`: PEM certificate/private key (optional)
- `-cafile`: PEM CA file (optional)
- `-verify`: 1 to require peer cert, 0 to skip (default 0)
- `-alpn`: List of ALPN protocol names to advertise (for HTTP/2, etc). Example: `{h2 http/1.1}`

**ALPN (Application-Layer Protocol Negotiation):**
- Use `-alpn` to advertise supported application protocols (e.g., HTTP/2 and HTTP/1.1) to clients.
- This enables negotiation of HTTP/2 (`h2`) or fallback to HTTP/1.1 as required by modern browsers and HTTP/2 clients.
- If ALPN negotiation fails or is not supported by the peer, the connection may fall back to another protocol or fail, depending on the client/server configuration.

**Example (HTTP/2-ready context):**
```tcl
set ctx [tossl::ssl::context create \
    -protocols {TLSv1.2 TLSv1.3} \
    -ciphers "ECDHE+AESGCM" \
    -cert mycert.pem -key mykey.pem \
    -cafile ca.pem -verify 1 \
    -alpn {h2 http/1.1}]
```
This context will negotiate HTTP/2 if the client supports it, otherwise HTTP/1.1.
- **Returns:** SSL context handle (e.g., sslctx1)

#### Wrap a Tcl Socket in SSL/TLS (with optional session resumption)
```tcl
set sslsock [tossl::ssl::socket $ctx $sock]
# To resume a session:
set sslsock2 [tossl::ssl::socket $ctx $sock2 -session $sesshandle]
```
- `-session <sessionhandle>`: Resume a previously exported session
- **Returns:** SSL socket handle (e.g., sslsock1)

#### Perform SSL/TLS Handshake
```tcl
tossl::ssl::connect $sslsock  ;# Client mode
tossl::ssl::accept $sslsock   ;# Server mode
```

#### Export/Import SSL Session (for resumption)
```tcl
# Export session after handshake
set sess [tossl::ssl::session export $sslsock]
# Import session blob for resumption
set sesshandle [tossl::ssl::session import $ctx $sess]
```
- **Export:** Returns base64 string representing the SSL session
- **Import:** Returns a session handle (for use with -session)

#### Retrieve Session and Peer Info
```tcl
set info [tossl::ssl::session info $sslsock]
# info is a dict with keys: protocol, cipher, session_id, peer_subject, etc.
```

#### Read/Write and Close SSL Socket
```tcl
set data [tossl::ssl::read $sslsock 4096]
tossl::ssl::write $sslsock $data
otossl::ssl::close $sslsock
```

#### Example: Full Session Resumption Workflow
```tcl
# Initial connection
set ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3}]
set sslsock [tossl::ssl::socket $ctx $sock]
tossl::ssl::connect $sslsock
set sess [tossl::ssl::session export $sslsock]
# Later, resume session
set sesshandle [tossl::ssl::session import $ctx $sess]
set sslsock2 [tossl::ssl::socket $ctx $sock2 -session $sesshandle]
tossl::ssl::connect $sslsock2
```

#### Custom Certificate Verification
- Use `-verify 1` with `tossl::ssl::context create` to require peer certificate verification.
- The context can be configured with custom CA files or options.
- Error messages are descriptive if verification fails.

---

### X.509 Certificate Verification
Verify that a certificate is signed by a CA:
```tcl
set cert ... ;# PEM certificate
set ca ...   ;# PEM CA certificate or public key
set ok [tossl::x509::verify -cert $cert -ca $ca]
puts "Valid? $ok"
```

---

### X.509 Certificate Creation
Create and sign a self-signed X.509 certificate:
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365]
puts $cert
```

Add Subject Alternative Names (SAN):
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -san {example.com www.example.com 192.168.1.1}]
puts $cert
```

Add Key Usage extension:
```tcl
set pub ... ;# PEM public key
set priv ... ;# PEM private key
set cert [tossl::x509::create -subject "My CN" -issuer "My CN" -pubkey $pub -privkey $priv -days 365 -keyusage {digitalSignature keyEncipherment}]
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

### Certificate Authority (CA) Operations

#### Generate CA Certificate
Create a Certificate Authority certificate:
```tcl
set ca_key [dict get [tossl::rsa::generate -bits 2048] private]
set ca_cert [tossl::ca::generate -key $ca_key -subject "My CA" -days 3650]
puts "CA Certificate: $ca_cert"
```

#### Sign Certificates with CA
Sign a certificate using a CA private key and certificate:
```tcl
set csr ... ;# Certificate Signing Request
set ca_key ... ;# CA private key
set ca_cert ... ;# CA certificate
set signed_cert [tossl::ca::sign -ca_key $ca_key -ca_cert $ca_cert -csr $csr -days 365]
puts "Signed Certificate: $signed_cert"
```

---

### Certificate Signing Requests (CSR)

#### Create CSR
Create a Certificate Signing Request:
```tcl
set keys [tossl::rsa::generate -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set csr [tossl::csr::create -subject "CN=example.com" -pubkey $pub -privkey $priv]
puts "CSR: $csr"
```

Add Subject Alternative Names to CSR:
```tcl
set csr [tossl::csr::create -subject "CN=example.com" -pubkey $pub -privkey $priv -san {example.com www.example.com}]
```

Add Key Usage extensions to CSR:
```tcl
set csr [tossl::csr::create -subject "CN=example.com" -pubkey $pub -privkey $priv -keyusage {digitalSignature keyEncipherment}]
```

#### Parse CSR
Parse a CSR and extract information:
```tcl
set csr_info [tossl::csr::parse $csr]
puts "Subject: [dict get $csr_info subject]"
puts "Public Key: [dict get $csr_info pubkey]"
puts "Extensions: [dict get $csr_info extensions]"
```

#### Validate CSR
Validate a CSR structure and signature:
```tcl
set valid [tossl::csr::validate $csr]
puts "CSR valid? $valid"
```

#### Generate CSR Fingerprint
Generate a fingerprint of a CSR:
```tcl
set fingerprint [tossl::csr::fingerprint $csr -algorithm sha256]
puts "CSR fingerprint: $fingerprint"
```

#### Modify CSR Extensions
Add or remove extensions from a CSR:
```tcl
# Add extension
set modified_csr [tossl::csr::modify -csr $csr -add_extension "subjectAltName" "DNS:new.example.com" 0]

# Remove extension
set modified_csr [tossl::csr::modify -csr $csr -remove_extension "subjectAltName"]
```

---

### Certificate Revocation Lists (CRL)

#### Create CRL
Create a Certificate Revocation List:
```tcl
set revoked_certs [list [list 123 "keyCompromise"] [list 456 "unspecified"]]
set crl [tossl::crl::create -ca_key $ca_key -ca_cert $ca_cert -revoked $revoked_certs -days 30]
puts "CRL: $crl"
```

#### Parse CRL
Parse a CRL and extract information:
```tcl
set crl_info [tossl::crl::parse $crl]
puts "Issuer: [dict get $crl_info issuer]"
puts "This Update: [dict get $crl_info thisUpdate]"
puts "Next Update: [dict get $crl_info nextUpdate]"
puts "Revoked Certificates: [dict get $crl_info revoked]"
```

---

### Certificate Validation and Fingerprinting

#### Validate Certificate Chain
Validate a certificate against a CA certificate:
```tcl
set valid [tossl::x509::validate -cert $cert -ca $ca_cert]
puts "Certificate valid? $valid"
```

#### Generate Certificate Fingerprint
Generate a fingerprint of a certificate:
```tcl
set fingerprint [tossl::x509::fingerprint -cert $cert -alg sha256]
puts "Certificate fingerprint: $fingerprint"
```

---

### RSA Signing and Verification
Sign and verify data using RSA keys and a digest algorithm:
```tcl
set keys [tossl::rsa::generate]
set priv [dict get $keys private]
set pub [dict get $keys public]
set data "important message"
set sig [tossl::rsa::sign -privkey $priv -alg sha256 $data]
set ok [tossl::rsa::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

### DSA Signing and Verification
Sign and verify data using DSA keys:
```tcl
set keys [tossl::key::generate -type dsa -bits 2048]
set priv [dict get $keys private]
set pub [dict get $keys public]
set sig [tossl::dsa::sign -privkey $priv -alg sha256 $data]
set ok [tossl::dsa::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

### EC Signing and Verification
Sign and verify data using EC keys:
```tcl
set keys [tossl::key::generate -type ec -curve prime256v1]
set priv [dict get $keys private]
set pub [dict get $keys public]
set sig [tossl::ec::sign -privkey $priv -alg sha256 $data]
set ok [tossl::ec::verify -pubkey $pub -alg sha256 $data $sig]
puts "Signature valid? $ok"
```

---

### X.509 Certificate Parsing
Parse a PEM-encoded X.509 certificate and extract its fields:
```tcl
set cert_pem {-----BEGIN CERTIFICATE-----
...your certificate here...
-----END CERTIFICATE-----}
set info [tossl::x509::parse $cert_pem]
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
set keys [tossl::key::generate]
# Or specify bit length
set keys [tossl::key::generate -type rsa -bits 3072]
# Generate DSA key pair (default 2048 bits)
set keys [tossl::key::generate -type dsa -bits 2048]
# Generate EC key pair (default: prime256v1)
set keys [tossl::key::generate -type ec -curve prime256v1]
set pub [dict get $keys public]
set priv [dict get $keys private]
```

### RSA Key Generation, Encryption, and Decryption
Generate an RSA key pair, encrypt with the public key, and decrypt with the private key:
```tcl
# Generate RSA key pair (default 2048 bits)
set keys [tossl::key::generate]
set pub [dict get $keys public]
set priv [dict get $keys private]

#### `tossl::key::generate`
Creates a new RSA, DSA, or EC key pair.

**Usage (RSA, default):**
```
set keys [tossl::key::generate]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
**Usage (DSA):**
```
set keys [tossl::key::generate -type dsa -bits 2048]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
**Usage (EC):**
```
set keys [tossl::key::generate -type ec -curve prime256v1]
set pub [dict get $keys public]
set priv [dict get $keys private]
```
- The returned dictionary includes `type` ("rsa", "dsa", or "ec"), `bits`, `public`, and `private` PEM strings. EC keys also include a `curve` field.
- Only PEM output is supported for now.
- EC support includes key generation, parsing, and writing.

#### `tossl::key::parse`
Parses a PEM- or DER-encoded RSA, DSA, or EC key (public or private) and returns a dictionary describing the key.

**Usage (RSA):**
```
set info [tossl::key::parse $priv]
# $info = {type rsa kind private bits 2048}
```
**Usage (DSA):**
```
set info [tossl::key::parse $priv]
# $info = {type dsa kind private bits 2048}
```
**Usage (EC):**
```
set info [tossl::key::parse $priv]
# $info = {type ec kind private curve prime256v1 bits 256}
```
**Usage (DER):**
```
set info [tossl::key::parse $der_bytes]
# $info = {type ...}
```

#### `tossl::key::write`
Serializes a key dictionary (as returned by generate or parse, with a 'pem' field) to PEM format.

**Usage:**
```
set pem [tossl::key::write -key $dict -format pem]
```

#### `tossl::key::getpub <private_key_data>`
Extracts the public key from a given private key (PEM or DER format).
- `<private_key_data>`: The private key content as a string or byte array.
- Returns: The corresponding public key in PEM format.

**Usage:**
```tcl
set private_key_pem {-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----}
set public_key_pem [tossl::key::getpub $private_key_pem]
puts "Public Key: $public_key_pem"
```

**Notes:**
- RSA, DSA, and EC keys in PEM and DER formats are supported for generate/parse/write.
- The key dictionary must contain at least the fields: `type`, `kind`, and `pem`.
- DER support is now available for all key types.

# Encrypt with public key
set plaintext "Hello, RSA!"
set ciphertext [tossl::rsa::encrypt -pubkey $pub $plaintext]

# Decrypt with private key
set decrypted [tossl::rsa::decrypt -privkey $priv $ciphertext]
puts "Decrypted: $decrypted"
```

---

### Message Digests (Hash Functions)
Compute a hash using any OpenSSL-supported algorithm:
```tcl
set hash [tossl::digest -alg sha256 "hello world"]
puts "SHA256: $hash"

set md5 [tossl::digest -alg md5 "test"]
puts "MD5: $md5"

# New algorithms: BLAKE2, SM3
set blake2 [tossl::digest -alg blake2b512 "hello world"]
puts "BLAKE2b-512: $blake2"

set sm3 [tossl::digest -alg sm3 "hello world"]
puts "SM3: $sm3"
```

### Hash Streaming for Large Files
Compute hash of large files without loading them entirely into memory:
```tcl
set file_hash [tossl::digest::stream -alg sha256 -file "large_file.dat"]
puts "File SHA256: $file_hash"
```

### Hash Comparison
Compare two hash values securely:
```tcl
set hash1 [tossl::digest -alg sha256 "Hello"]
set hash2 [tossl::digest -alg sha256 "Hello"]
set hash3 [tossl::digest -alg sha256 "World"]

puts "Identical: [tossl::digest::compare $hash1 $hash2]"  ;# Returns 1
puts "Different: [tossl::digest::compare $hash1 $hash3]"  ;# Returns 0
```

### List Available Algorithms
Get a list of all supported hash algorithms:
```tcl
set algorithms [tossl::digest::list]
puts "Available algorithms: $algorithms"
```

### Symmetric Encryption/Decryption
Encrypt and decrypt data using OpenSSL ciphers (e.g., aes-128-cbc, aes-256-cbc):
```tcl
# Encrypt
set key [binary format H* 00112233445566778899aabbccddeeff]  ;# 16 bytes for AES-128
set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]  ;# 16 bytes
set plaintext "Secret message!"
set ciphertext [tossl::encrypt -alg aes-128-cbc -key $key -iv $iv $plaintext]

# Decrypt
set decrypted [tossl::decrypt -alg aes-128-cbc -key $key -iv $iv $ciphertext]
puts "Decrypted: $decrypted"
```

### Enhanced Encryption with Random Keys/IVs
Use the new random key/IV generation for secure encryption:
```tcl
# Generate random key and IV
set key [tossl::rand::key -alg aes-256-cbc]
set iv [tossl::rand::iv -alg aes-256-cbc]

# Encrypt with GCM mode (returns dict with ciphertext and tag)
set encrypted [tossl::encrypt -alg aes-128-gcm -key $key -iv $iv $plaintext]
set ciphertext [dict get $encrypted ciphertext]
set tag [dict get $encrypted tag]

# Decrypt GCM mode
set decrypted [tossl::decrypt -alg aes-128-gcm -key $key -iv $iv $ciphertext -tag $tag]
puts "Decrypted: $decrypted"
```

### Cipher Information and Listing
Get information about available ciphers:
```tcl
# Get cipher information
set info [tossl::cipher::info aes-256-cbc]
puts "Block size: [dict get $info block_size]"
puts "Key length: [dict get $info key_length]"
puts "Mode: [dict get $info mode]"

# List all available ciphers
set ciphers [tossl::cipher::list]
puts "Available ciphers: [llength $ciphers]"

# List ciphers by mode
set cbc_ciphers [tossl::cipher::list -type cbc]
puts "CBC ciphers: [llength $cbc_ciphers]"
```

### Random Bytes and Key/IV Generation
Generate cryptographically secure random bytes:
```tcl
set bytes [tossl::randbytes 16]
puts "Random bytes (hex): [binary encode hex $bytes]"
```

Generate random keys and IVs for specific ciphers:
```tcl
# Generate random key for AES-256-CBC
set key [tossl::rand::key -alg aes-256-cbc]
puts "AES-256 key length: [string length $key] bytes"

# Generate random IV for AES-256-CBC
set iv [tossl::rand::iv -alg aes-256-cbc]
puts "AES-256 IV length: [string length $iv] bytes"
```

---

### Key Derivation Functions

#### PBKDF2 (Password-Based Key Derivation Function 2)
Derive a key from a password using PBKDF2:
```tcl
set password "my_password"
set salt [tossl::randbytes 16]
set key [tossl::kdf::pbkdf2 -password $password -salt $salt -iterations 10000 -keylen 32 -digest sha256]
puts "Derived key length: [string length $key] bytes"
```

#### Scrypt
Derive a key using the Scrypt algorithm:
```tcl
set password "my_password"
set salt [tossl::randbytes 16]
set key [tossl::kdf::scrypt -password $password -salt $salt -n 16384 -r 8 -p 1 -keylen 32]
puts "Scrypt derived key length: [string length $key] bytes"
```

#### Argon2
Derive a key using the Argon2 algorithm (if supported by your OpenSSL build):
```tcl
set password "my_password"
set salt [tossl::randbytes 16]
set key [tossl::kdf::argon2 -password $password -salt $salt -time 3 -memory 65536 -parallel 4 -keylen 32]
puts "Argon2 derived key length: [string length $key] bytes"
```

---

## API Reference

### `tossl::pkcs7::sign -cert <cert> -key <key> <data> ?-detached 0|1? ?-pem 0|1?`
Signs data using PKCS#7 format (S/MIME/CMS) with the provided certificate and private key.
- `-cert <cert>`: PEM certificate (string)
- `-key <key>`: PEM private key (string)
- `<data>`: Data to sign (byte array or string)
- `-detached 0|1`: 1 for detached signature (default), 0 for attached
- `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- Returns: PKCS#7 signature (PEM string or DER byte array)

### `tossl::pkcs7::verify -ca <ca> <pkcs7> <data> ?-pem 0|1?`
Verifies a PKCS#7 signature (detached or attached) using the provided CA certificate.
- `-ca <ca>`: PEM CA certificate (string)
- `<pkcs7>`: PKCS#7 signature (PEM string or DER byte array)
- `<data>`: Data to verify (byte array or string)
- `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- Returns: 1 if signature is valid, 0 otherwise

### `tossl::pkcs7::encrypt -cert <cert1> ?-cert <cert2> ...? ?-cipher <cipher>? <data> ?-pem 0|1?`
Encrypts data to one or more recipients using PKCS#7 enveloped data (S/MIME/CMS).
- `-cert <cert>`: PEM certificate for a recipient (may be specified multiple times)
- `-cipher <cipher>`: Symmetric cipher to use (default: aes-256-cbc; e.g. aes-128-cbc, des-ede3-cbc)
- `<data>`: Data to encrypt (byte array or string)
- `-pem 0|1`: 1 for PEM output (default), 0 for DER (binary)
- Returns: PKCS#7 envelope (PEM string or DER byte array)

### `tossl::pkcs7::decrypt -key <key> -cert <cert> <pkcs7> ?-pem 0|1?`
Decrypts PKCS#7 enveloped data (S/MIME/CMS) using the provided private key and certificate.
- `-key <key>`: PEM private key (string)
- `-cert <cert>`: PEM certificate (string)
- `<pkcs7>`: PKCS#7 envelope (PEM string or DER byte array)
- `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- Returns: Decrypted data (byte array)

### `tossl::pkcs7::info <pkcs7> ?-pem 0|1?`
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
set info [tossl::pkcs7::info $pkcs7]
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

### `tossl::digest -alg <name> <data>`
Computes the hash of `<data>` using the specified digest algorithm (e.g., sha256, sha512, md5, blake2b512, sm3).
- Returns: Hex-encoded string of the digest.

### `tossl::digest::stream -alg <name> -file <filename>`
Computes the hash of a file using streaming (memory-efficient for large files).
- `-alg <name>`: Digest algorithm name
- `-file <filename>`: Path to the file to hash
- Returns: Hex-encoded string of the digest.

### `tossl::digest::compare <hash1> <hash2>`
Compares two hash values securely.
- `<hash1>`, `<hash2>`: Hex-encoded hash strings to compare
- Returns: 1 if hashes are identical, 0 otherwise.

### `tossl::digest::list`
Returns a list of all supported hash algorithms.
- Returns: List of algorithm names.

### `tossl::encrypt -alg <name> -key <key> -iv <iv> <data>`
Encrypts `<data>` using the specified cipher, key, and IV.
- `-alg <name>`: Cipher name (e.g., aes-128-cbc, aes-256-cbc)
- `-key <key>`: Byte array key (must match cipher requirements)
- `-iv <iv>`: Byte array IV (must match cipher requirements)
- `<data>`: Data to encrypt (byte array or string)
- Returns: Ciphertext as a Tcl byte array.

### `tossl::decrypt -alg <name> -key <key> -iv <iv> <data>`
Decrypts `<data>` using the specified cipher, key, and IV.
- Parameters as above.
- Returns: Decrypted plaintext as a Tcl byte array.

### `tossl::randbytes <n>`
Generates `<n>` random bytes (as a Tcl byte array).
- Returns: Byte array of length `<n>`.

### `tossl::base64::encode <data>`
Encodes binary or string data to Base64.
- Returns: Base64-encoded string.

### `tossl::base64::decode <b64>`
Decodes a Base64 string to binary data.
- Returns: Tcl byte array.

### `tossl::hex::encode <data>`
Encodes binary data to a hex string.
- Returns: Hex-encoded string.

### `tossl::hex::decode <hex>`
Decodes a hex string to binary data.
- Returns: Tcl byte array.

### `tossl::hmac -alg <name> -key <key> <data>`
Computes the HMAC of `<data>` using the specified digest algorithm and key.
- `-alg <name>`: Digest algorithm (e.g., sha256, sha512, md5)
- `-key <key>`: Key as a Tcl byte array
- `<data>`: Data to HMAC (byte array or string)
- Returns: HMAC as a hex string.

### `tossl::http::get url`
Performs an HTTP GET request to the specified URL.
- `<url>`: The URL to request
- Returns: Dict with keys `status_code`, `body`, and `headers`

### `tossl::http::post url data`
Performs an HTTP POST request to the specified URL with the given data.
- `<url>`: The URL to request
- `<data>`: The data to post
- Returns: Dict with keys `status_code`, `body`, and `headers`

### `tossl::json::parse json_string`
Parses a JSON string and returns a Tcl dict.
- `<json_string>`: JSON string to parse
- Returns: Tcl dict representation of the JSON data

### `tossl::json::generate tcl_dict`
Generates a JSON string from a Tcl dict.
- `<tcl_dict>`: Tcl dict to convert
- Returns: JSON string representation of the dict

### `tossl::acme::directory directory_url`
Fetches and parses the ACME directory from the specified URL.
- `<directory_url>`: ACME server directory URL
- Returns: Tcl dict containing ACME endpoints

### `tossl::acme::create_account directory_url account_key email ?contact?`
Creates a new ACME account with the specified email address.
- `<directory_url>`: ACME server directory URL
- `<account_key>`: PEM-encoded private key for account
- `<email>`: Email address for account
- `<contact>`: Additional contact information (optional)
- Returns: Account creation status

### `tossl::acme::create_order directory_url account_key domains`
Creates a new certificate order for the specified domains.
- `<directory_url>`: ACME server directory URL
- `<account_key>`: PEM-encoded private key for account
- `<domains>`: Space-separated list of domain names
- Returns: Order creation status

### `tossl::acme::dns01_challenge domain token account_key provider api_key ?zone_id?`
Prepares a DNS-01 challenge by creating the required DNS TXT record.
- `<domain>`: Domain name for certificate
- `<token>`: ACME challenge token
- `<account_key>`: PEM-encoded private key for account
- `<provider>`: DNS provider ("cloudflare", "route53", "generic")
- `<api_key>`: DNS provider API key
- `<zone_id>`: DNS zone ID (required for Cloudflare)
- Returns: Challenge information dict

### `tossl::acme::cleanup_dns domain record_name provider api_key ?zone_id?`
Removes the DNS TXT record created for the challenge.
- `<domain>`: Domain name
- `<record_name>`: DNS record name to delete
- `<provider>`: DNS provider
- `<api_key>`: DNS provider API key
- `<zone_id>`: DNS zone ID (required for Cloudflare)
- Returns: Cleanup status

### `tossl::pkcs12::parse <data>`
Parses a PKCS#12 (PFX) bundle and returns a Tcl dict with PEM-encoded certificate, private key, and CA chain.
- `<data>`: PKCS#12 binary data (Tcl byte array)
- Returns: Tcl dict with keys `cert`, `key`, and `ca` (list of PEM CA certs, if present).

### `tossl::pkcs12::create -cert <cert> -key <key> -ca <ca> -password <pw>`
Creates a PKCS#12 (PFX) bundle from PEM certificate, private key, optional CA chain, and password.
- `-cert <cert>`: PEM certificate (string)
- `-key <key>`: PEM private key (string)
- `-ca <ca>`: PEM CA chain (string, concatenated PEMs; optional)
- `-password <pw>`: password for the PKCS#12 bundle (string)
- Returns: PKCS#12 binary data as a Tcl byte array.


### `tossl::x509::verify -cert <pem> -ca <pem>`
Verifies that the certificate is signed by the provided CA certificate or public key. Returns 1 if valid, 0 otherwise.

### `tossl::x509::create -subject <dn> -issuer <dn> -pubkey <pem> -privkey <pem> -days <n>`
Creates and signs a new X.509 certificate. Returns the certificate in PEM format.
- `-subject <dn>`: Subject common name (CN)
- `-issuer <dn>`: Issuer common name (CN)
- `-pubkey <pem>`: Public key PEM
- `-privkey <pem>`: Issuer's private key PEM
- `-days <n>`: Validity period in days

### `tossl::rsa::sign -privkey <pem> -alg <digest> <data>`
Signs the given data with the provided PEM private key and digest algorithm (e.g., sha256). Returns the signature as a Tcl byte array.

### `tossl::rsa::verify -pubkey <pem> -alg <digest> <data> <signature>`
Verifies the signature using the PEM public key and digest algorithm. Returns 1 if valid, 0 otherwise.

### `tossl::x509::parse <pem>`
Parses a PEM-encoded X.509 certificate and returns a Tcl dict with the following fields:
- `subject`: Distinguished Name of the subject
- `issuer`: Distinguished Name of the issuer
- `serial`: Serial number (hex)
- `notBefore`: Certificate validity start (human-readable)
- `notAfter`: Certificate validity end (human-readable)

### `tossl::x509::validate -cert <pem> -ca <pem>`
Validates a certificate against a CA certificate.
- `-cert <pem>`: PEM certificate to validate
- `-ca <pem>`: PEM CA certificate
- Returns: 1 if valid, 0 otherwise

### `tossl::x509::fingerprint -cert <pem> -alg <algorithm>`
Generates a fingerprint of a certificate.
- `-cert <pem>`: PEM certificate
- `-alg <algorithm>`: Hash algorithm (e.g., sha1, sha256, sha512)
- Returns: Hex-encoded fingerprint

### `tossl::ca::generate -key <pem> -subject <subject> -days <days> ?-extensions <extensions>?`
Generates a CA certificate.
- `-key <pem>`: PEM private key
- `-subject <subject>`: Subject distinguished name
- `-days <days>`: Validity period in days
- `-extensions <extensions>`: Optional extensions
- Returns: PEM CA certificate

### `tossl::ca::sign -ca_key <pem> -ca_cert <pem> -csr <pem> -days <days> ?-extensions <extensions>?`
Signs a certificate using a CA.
- `-ca_key <pem>`: CA private key
- `-ca_cert <pem>`: CA certificate
- `-csr <pem>`: Certificate signing request
- `-days <days>`: Validity period in days
- `-extensions <extensions>`: Optional extensions
- Returns: PEM signed certificate

### `tossl::csr::create -subject <dn> -pubkey <pem> -privkey <pem> ?-san {dns1 dns2 ...}? ?-keyusage {usage1 usage2 ...}?`
Creates a certificate signing request.
- `-subject <dn>`: Subject distinguished name
- `-pubkey <pem>`: Public key PEM
- `-privkey <pem>`: Private key PEM
- `-san {dns1 dns2 ...}`: Optional subject alternative names
- `-keyusage {usage1 usage2 ...}`: Optional key usage extensions
- Returns: PEM CSR

### `tossl::csr::parse <pem>`
Parses a CSR and returns information.
- `<pem>`: PEM CSR
- Returns: Dictionary with CSR information

### `tossl::csr::validate <pem>`
Validates a CSR structure and signature.
- `<pem>`: PEM CSR
- Returns: 1 if valid, 0 otherwise

### `tossl::csr::fingerprint <pem> ?-algorithm sha1|sha256|sha512?`
Generates a fingerprint of a CSR.
- `<pem>`: PEM CSR
- `-algorithm`: Hash algorithm (default: sha256)
- Returns: Hex-encoded fingerprint

### `tossl::csr::modify -csr <pem> -add_extension <oid> <value> <critical> ?-remove_extension <oid>?`
Modifies CSR extensions.
- `-csr <pem>`: PEM CSR
- `-add_extension <oid> <value> <critical>`: Add extension
- `-remove_extension <oid>`: Remove extension
- Returns: Modified PEM CSR

### `tossl::crl::create -ca_key <pem> -ca_cert <pem> -revoked <list> -days <days>`
Creates a certificate revocation list.
- `-ca_key <pem>`: CA private key
- `-ca_cert <pem>`: CA certificate
- `-revoked <list>`: List of revoked certificates with serial numbers and reasons
- `-days <days>`: Validity period in days
- Returns: PEM CRL

### `tossl::crl::parse <pem>`
Parses a CRL and returns information.
- `<pem>`: PEM CRL
- Returns: Dictionary with CRL information

### `tossl::kdf::pbkdf2 -password <password> -salt <salt> -iterations <n> -keylen <length> -digest <algorithm>`
Derives a key using PBKDF2.
- `-password <password>`: Password string
- `-salt <salt>`: Salt bytes
- `-iterations <n>`: Number of iterations
- `-keylen <length>`: Output key length
- `-digest <algorithm>`: Hash algorithm (e.g., sha256)
- Returns: Derived key bytes

### `tossl::kdf::scrypt -password <password> -salt <salt> -n <n> -r <r> -p <p> -keylen <length>`
Derives a key using Scrypt.
- `-password <password>`: Password string
- `-salt <salt>`: Salt bytes
- `-n <n>`: CPU/memory cost parameter
- `-r <r>`: Block size parameter
- `-p <p>`: Parallelization parameter
- `-keylen <length>`: Output key length
- Returns: Derived key bytes

### `tossl::kdf::argon2 -password <password> -salt <salt> -time <time> -memory <memory> -parallel <parallel> -keylen <length>`
Derives a key using Argon2 (if supported).
- `-password <password>`: Password string
- `-salt <salt>`: Salt bytes
- `-time <time>`: Time cost parameter
- `-memory <memory>`: Memory cost parameter (in KB)
- `-parallel <parallel>`: Parallelization parameter
- `-keylen <length>`: Output key length
- Returns: Derived key bytes

### `tossl::key::generate ?-bits <n>?`
Generates an RSA key pair. Default is 2048 bits.
- Returns: Tcl dict with keys `public` and `private` (both PEM-encoded strings).

### `tossl::key::parse <pem>`
Parses a PEM-encoded RSA key (public or private) and returns a dictionary describing the key.

### `tossl::key::write -key <dict> -format <format>`
Serializes a key dictionary (as returned by generate or parse, with a 'pem' field) to the specified format.

### `tossl::rsa::encrypt -pubkey <pem> <data>`
Encrypts `<data>` using the provided PEM public key (PKCS#1 OAEP padding).
- Returns: Ciphertext as a Tcl byte array.

### `tossl::rsa::decrypt -privkey <pem> <ciphertext>`
Decrypts `<ciphertext>` using the provided PEM private key (PKCS#1 OAEP padding).
- Returns: Decrypted plaintext as a Tcl byte array.

### `tossl::hmac -alg <name> -key <key> <data>`
Computes the HMAC of `<data>` using the specified digest algorithm and key.
- `-alg <name>`: Digest algorithm (e.g., sha256, sha512, md5)
- `-key <key>`: Key as a Tcl byte array
- `<data>`: Data to HMAC (byte array or string)
- Returns: HMAC as a hex string
- Usage example:
```tcl
set key [binary format H* 00112233445566778899aabbccddeeff]
set data "hello world"
set mac [tossl::hmac -alg sha256 -key $key $data]
puts "HMAC: $mac"
```

- `<name>`: Cipher name (e.g., aes-128-cbc, aes-256-cbc)
- `<key>`: Byte array key (must match cipher requirements)
- `<iv>`: Byte array IV (must match cipher requirements)
- `<data>`: Data to encrypt (byte array or string)
- Returns: Ciphertext as a Tcl byte array.

### `tossl::decrypt -alg <name> -key <key> -iv <iv> <data>`
Decrypts `<data>` using the specified cipher, key, and IV.
- Parameters as above.
- Returns: Decrypted plaintext as a Tcl byte array.

### `tossl::randbytes <n>`
Generates `<n>` random bytes (as a Tcl byte array).
- Returns: Byte array of length `<n>`.

### `tossl::rand::key -alg <name>`
Generates a random key for the specified cipher algorithm.
- `-alg <name>`: Cipher algorithm name (e.g., aes-256-cbc, chacha20)
- Returns: Byte array of the appropriate key length for the cipher.

### `tossl::rand::iv -alg <name>`
Generates a random IV for the specified cipher algorithm.
- `-alg <name>`: Cipher algorithm name (e.g., aes-256-cbc, aes-128-gcm)
- Returns: Byte array of the appropriate IV length for the cipher.

### `tossl::cipher::info <algorithm>`
Returns information about a cipher algorithm.
- `<algorithm>`: Cipher algorithm name
- Returns: Dictionary with keys: `name`, `block_size`, `key_length`, `iv_length`, `mode`, `flags`

### `tossl::cipher::list ?-type type?`
Returns a list of available cipher algorithms.
- `-type type`: Optional filter by cipher mode (e.g., cbc, gcm, ecb)
- Returns: List of cipher algorithm names.

---

**Note:** Supported ciphers and parameter lengths depend on your OpenSSL build. Common options include `aes-128-cbc`, `aes-256-cbc`, etc. Key and IV must be the correct length for the chosen cipher.

---

## Encoding and Decoding

### Base64 Encoding
Encode binary or string data to Base64:
```tcl
set b64 [tossl::base64::encode $data]
puts "Base64: $b64"
```

### Base64 Decoding
Decode Base64 string to binary data:
```tcl
set bin [tossl::base64::decode $b64]
puts "Decoded: $bin"
```

### Hex Encoding
Encode binary data to hex string:
```tcl
set hex [tossl::hex::encode $data]
puts "Hex: $hex"
```

### Hex Decoding
Decode hex string to binary data:
```tcl
set bin [tossl::hex::decode $hex]
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
set info [tossl::pkcs12::parse $p12]
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
set p12 [tossl::pkcs12::create -cert $cert -key $key -ca $ca -password "secret"]
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
set sig [tossl::pkcs7::sign -cert $cert -key $key $data]
set f [open "sig.p7s" w]
puts -nonewline $f $sig
close $f
```
#### Attached signature (DER output):
```tcl
set sig [tossl::pkcs7::sign -cert $cert -key $key -detached 0 -pem 0 $data]
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
set ok [tossl::pkcs7::verify -ca $ca $sig $data]
puts "Valid? $ok"
```
#### Attached signature (DER input):
```tcl
set ok [tossl::pkcs7::verify -ca $ca -pem 0 $sig $data]
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
set env [tossl::pkcs7::encrypt -cert $cert $data]
set f [open "env.p7m" w]
puts -nonewline $f $env
close $f
```
#### Multiple recipients, custom cipher, DER output:
```tcl
set env [tossl::pkcs7::encrypt -cert $cert1 -cert $cert2 -cipher aes-128-cbc -pem 0 $data]
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
set plain [tossl::pkcs7::decrypt -key $key -cert $cert $env]
puts "Decrypted: $plain"
```
#### DER input:
```tcl
set plain [tossl::pkcs7::decrypt -key $key -cert $cert -pem 0 $env]
puts "Decrypted: $plain"
```
- **Arguments:**
  - `-key <key>`: PEM private key (string)
  - `-cert <cert>`: PEM certificate (string)
  - `<env>`: PKCS#7 envelope (PEM string or DER byte array)
  - `-pem 0|1`: 1 for PEM input (default), 0 for DER (binary)
- **Returns:** Decrypted data (byte array)

---

## SSL/TLS API Reference

### `tossl::ssl::context create ?options?`
Creates a new SSL/TLS context with customizable options.
- Options: `-protocols`, `-ciphers`, `-cert`, `-key`, `-cafile`, `-verify`
- Returns: context handle (e.g., sslctx1)

### `tossl::ssl::context_free <ctx_handle>`
Frees the specified SSL context and its associated resources.
- `<ctx_handle>`: The handle of the SSL context to free (e.g., sslctx1).
- Call this when a context is no longer needed to prevent resource leaks.

### `tossl::ssl::protocol_version -ctx <ctx_handle>`
Retrieves the current protocol version settings for an SSL context.
- `<ctx_handle>`: The handle of the SSL context (e.g., sslctx1).
- Returns: Dictionary with current protocol version information.

### `tossl::ssl::set_protocol_version -ctx <ctx_handle> -min <version> -max <version>`
Sets the minimum and maximum protocol versions for an SSL context.
- `<ctx_handle>`: The handle of the SSL context (e.g., sslctx1).
- `-min <version>`: Minimum protocol version (e.g., TLSv1.2, TLSv1.3).
- `-max <version>`: Maximum protocol version (e.g., TLSv1.2, TLSv1.3).
- Returns: 1 on success, 0 on failure.

### `tossl::ssl::socket <ctx> <sock> ?-session <sessionhandle>?`
Wraps a Tcl socket in SSL/TLS, optionally resuming a session.
- Returns: SSL socket handle (e.g., sslsock1)

### `tossl::ssl::session export <sslsock>`
Exports the current SSL session as a base64 string for future resumption.

### `tossl::ssl::session import <ctx> <base64blob>`
Imports a session from a base64 string, returning a session handle for use with `-session`.

### `tossl::ssl::session info <sslsock>`
Returns a dict with protocol, cipher, session id, peer subject, etc.

### `tossl::ssl::peer_cert <sslsock_handle>`
Retrieves the PEM-encoded certificate of the peer from an established SSL/TLS connection.
- `<sslsock_handle>`: The handle of the SSL socket (e.g., sslsock1).
- Returns: The peer's certificate as a PEM-formatted string if available, otherwise an error or empty string.
- Useful for inspecting the certificate presented by the other side after a successful handshake.

**Usage:**
```tcl
# After a successful tossl::ssl::connect or tossl::ssl::accept
set peer_cert_pem [tossl::ssl::peer_cert $sslsock]
if {[string length $peer_cert_pem] > 0} {
    puts "Peer certificate:"
    puts $peer_cert_pem
    # You can then parse it using tossl::x509::parse
    set cert_info [tossl::x509::parse $peer_cert_pem]
    puts "Peer subject: [dict get $cert_info subject]"
} else {
    puts "No peer certificate presented or error retrieving it."
}
```

### `tossl::ssl::connect <sslsock>`
Performs SSL/TLS handshake as a client.

### `tossl::ssl::accept <sslsock>`
Performs SSL/TLS handshake as a server.

### `tossl::ssl::read <sslsock> ?nbytes?`
Reads up to nbytes (default 4096) from the SSL connection.

### `tossl::ssl::write <sslsock> <data>`
Writes data to the SSL connection.

### `tossl::ssl::close <sslsock>`
Closes the SSL connection and frees resources.

---

## SSL/TLS Usage Examples

### Example: Creating an SSL Server
```tcl
# Generate or load server certificate and key (PEM format)
set cert [read [open "server-cert.pem"]]
set key  [read [open "server-key.pem"]]

# Create SSL context for the server
set ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3} -cert $cert -key $key -verify 0]

# Listen on a TCP socket
set srv [socket -server accept_cb 4433]

# Accept callback: wrap accepted socket in SSL and perform handshake
proc accept_cb {sock addr port} {
    global ctx
    set sslsock [tossl::ssl::socket $ctx $sock]
    if {[catch {tossl::ssl::accept $sslsock} err]} {
        puts "Handshake failed: $err"
        close $sock
        return
    }
    # Now you can read/write encrypted data:
    set data [tossl::ssl::read $sslsock 4096]
    puts "Received: $data"
    tossl::ssl::write $sslsock "Hello from SSL server!"
    tossl::ssl::close $sslsock
    close $sock
}

vwait forever  ;# Keep the server running
```

### Example: Creating an SSL Client
```tcl
# Optionally load CA certificate for verification
set ca [read [open "ca-cert.pem"]]

# Create SSL context for the client
set ctx [tossl::ssl::context create -protocols {TLSv1.2 TLSv1.3} -cafile $ca -verify 1]

# Open a TCP connection to the server
set sock [socket localhost 4433]

# Wrap socket in SSL
set sslsock [tossl::ssl::socket $ctx $sock]

# Perform SSL handshake as client
if {[catch {tossl::ssl::connect $sslsock} err]} {
    puts "Handshake failed: $err"
    close $sock
    return
}

# Send and receive encrypted data
tossl::ssl::write $sslsock "Hello from SSL client!"
set response [tossl::ssl::read $sslsock 4096]
puts "Received: $response"
tossl::ssl::close $sslsock
close $sock
```

**Notes:**
- You can use Tcl's event loop and fileevent for asynchronous I/O with SSL sockets.
- Always close both the SSL socket and the underlying Tcl socket when done.
- For mutual authentication, supply `-cert` and `-key` for both client and server contexts and set `-verify 1`.

## Error Handling
- All SSL/TLS commands provide detailed error messages on failure (e.g., handshake errors, verification failures).
- Resources are automatically freed on error or close.
- Invalid handles or arguments result in descriptive Tcl errors.

---

## Development Roadmap
See [TODO.md](TODO.md) for a list of planned features and implementation steps.

- As new commands are added, they will be documented here.

---

## License

This project is licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
You may obtain a copy of the License at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0

---

## Attribution

This project incorporates OpenSSL, developed by Eric Young and Tim Hudson, and acknowledges their significant contributions to the cryptographic community.

For license details, see the [OpenSSL License](https://www.openssl.org/source/license.html).
