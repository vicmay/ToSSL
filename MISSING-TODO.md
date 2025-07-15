# TOSSL Missing Features TODO

This document tracks missing and implemented features for TOSSL, aiming for OpenSSL compatibility. As of December 2024, the codebase is modular, multi-file, and most high/medium priority features are implemented. This update reflects the actual code and Tcl-level commands.

## 🔐 **Core Cryptographic Operations**

### **Hash Functions & Digests**
- [x] **Additional hash algorithms**: SHA-1, SHA-224, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, MD5, MD4
- [x] **RIPEMD**: RIPEMD-160
- [x] **Whirlpool**: Whirlpool hash
- [ ] **RIPEMD-256, RIPEMD-320**  
  _Not available in OpenSSL default provider; not supported in TOSSL._
- [x] **BLAKE2**: BLAKE2b, BLAKE2s
- [x] **SM3**: Chinese national standard hash
- [x] **Hash streaming**: tossl::digest::stream
- [x] **Hash comparison**: tossl::digest::compare
- [x] **Hash algorithm listing**: tossl::digest::list

### **Symmetric Encryption**
- [x] **Modern ciphers**: AES (all modes), ChaCha20, Poly1305, Salsa20, GCM, CCM, XTS, etc. (tossl::encrypt, tossl::decrypt, tossl::cipher::list/info)
- [x] **Block cipher modes**: CBC, CFB, OFB, CTR, GCM, CCM, XTS
- [x] **Key derivation**: PBKDF2, scrypt, Argon2 (if supported) (tossl::kdf::pbkdf2, ::scrypt, ::argon2)
- [x] **Random key/IV generation**: tossl::rand::key, tossl::rand::iv, tossl::randbytes
- [x] **Cipher info/listing**: tossl::cipher::info, tossl::cipher::list
- [x] **Legacy ciphers**: DES, 3DES, Blowfish, CAST5, RC4, RC5 (tossl::legacy::*)
- [x] **Password-based encryption**: tossl::pbe::* (keyderive, encrypt, decrypt, algorithms, saltgen)

### **Asymmetric Cryptography**
- [x] **RSA operations**: Keygen, encrypt, decrypt, sign, verify, validate, components (tossl::rsa::*)
- [x] **DSA operations**: Keygen, sign, verify, validate, param gen (tossl::dsa::*)
- [x] **EC operations**: Keygen, sign, verify, validate, point ops, curve list, components (tossl::ec::*)
- [x] **Ed25519/Ed448**: Keygen, sign, verify (tossl::ed25519::*, tossl::ed448::*)
- [x] **X25519/X448**: Keygen, derive (tossl::x25519::*, tossl::x448::*)
- [x] **SM2**: Keygen, sign, verify, encrypt, decrypt (tossl::sm2::*)
- [x] **Key import/export/conversion**: PEM, DER, PKCS#8 (tossl::key::parse, ::write, ::convert)
- [x] **Key fingerprinting**: tossl::key::fingerprint
- [x] **Key wrapping**: tossl::keywrap::* (wrap, unwrap, kekgen, info, algorithms)
- [x] **OCSP operations**: tossl::ocsp::create_request, ::parse_response

## 📜 **Certificate & PKI Operations**

### **X.509 Certificate Operations**
- [x] **Certificate generation**: Self-signed, CA-signed (tossl::x509::create, tossl::ca::generate, tossl::ca::sign)
- [x] **Certificate validation**: Chain validation, CRL checking (tossl::x509::verify, ::validate, ::time_validate)
- [x] **Certificate parsing**: tossl::x509::parse
- [x] **Certificate modification**: tossl::x509::modify
- [x] **Certificate conversion**: PEM, DER, PKCS#12 (tossl::pkcs12::create, ::parse)
- [x] **Certificate fingerprinting**: tossl::x509::fingerprint
- [x] **Certificate transparency**: Basic CT extension parsing

### **Certificate Signing Requests (CSR)**
- [x] **CSR extensions**: Full X.509 extension support (tossl::csr::modify)
- [x] **CSR validation**: tossl::csr::validate
- [x] **CSR modification**: tossl::csr::modify
- [x] **CSR fingerprinting**: tossl::csr::fingerprint
- [x] **CSR parsing/creation**: tossl::csr::parse, ::create

### **Certificate Revocation**
- [x] **CRL operations**: tossl::crl::create, ::parse
- [x] **OCSP operations**: tossl::ocsp::create_request, ::parse_response
- [x] **Certificate status checking**: Implemented (`tossl::ssl::check_cert_status -conn conn`)

### **Certificate Authority (CA) Operations**
- [x] **CA certificate generation**: tossl::ca::generate
- [x] **Certificate signing**: tossl::ca::sign
- [x] **CA management**: Chain management via validation and signing

## 🌐 **SSL/TLS Operations**

### **SSL/TLS Context Management**
- [x] **SSL context configuration**: tossl::ssl::context, ::set_protocol_version, ::protocol_version
- [x] **SSL session management**: Session resumption, tickets (tossl::ssl::context)
- [x] **SSL cipher/protocol configuration**: tossl::ssl::set_protocol_version, ::protocol_version

### **SSL/TLS Handshake**
- [x] **Client authentication**: Implemented (`tossl::ssl::context -client_cert cert -client_key key`)
- [x] **Server name indication (SNI)**: Implemented in tossl::ssl::connect with -sni parameter
- [x] **Application layer protocol negotiation (ALPN)**: Fully implemented with Tcl callback support
  - **Implemented:**
    - ALPN protocol advertisement in client connections (`tossl::ssl::connect -alpn protocols`)
    - ALPN callback registration (`tossl::ssl::set_alpn_callback -ctx ctx -callback callback`)
    - Tcl callback invocation during SSL handshake
    - Negotiated protocol retrieval (`tossl::ssl::alpn_selected -conn conn`)
    - Socket wrapping for Tcl channels (`tossl::ssl::accept -ctx ctx -socket socket`)
    - Socket information retrieval (`tossl::ssl::socket_info -conn conn`)
  - **Supported protocols:** HTTP/2 (h2), HTTP/1.1 (http/1.1), and custom protocols
- [x] **Certificate transparency (CT extension)**: Implemented (`tossl::ssl::check_cert_status`)

### **SSL/TLS Security**
- [x] **Perfect forward secrecy (PFS)**: Implemented (`tossl::ssl::check_pfs -conn conn`)
- [x] **Certificate pinning (HPKP)**: Implemented (`tossl::ssl::verify_cert_pinning -conn conn -pins pins`)
- [x] **OCSP stapling**: Implemented (`tossl::ssl::set_ocsp_stapling -ctx ctx -enable enable`)

## 🔍 **Cryptographic Analysis**

### **Cryptographic Testing/Validation**
- [x] **Random number testing**: Implemented (`tossl::rand::test count`)
- [x] **Key/cert/cipher analysis**: Implemented (`tossl::key::analyze key`, `tossl::cipher::analyze cipher`)
- [x] **Signature validation**: Implemented (`tossl::rsa::verify`, `tossl::dsa::verify`, `tossl::ec::verify`)

## 🔧 **Utility Operations**

### **Encoding/Decoding**
- [x] **Base64, Base64URL, Base32, Base32Hex**: tossl::base64::*, ::base64url::*
- [x] **Hex encoding/decoding**: tossl::hex::*
- [x] **URL encoding**: Implemented (`tossl::url::encode`, `tossl::url::decode`)
- [x] **ASN.1 operations**: Implemented (`tossl::asn1::encode`, `tossl::asn1::oid_to_text`, `tossl::asn1::text_to_oid`)

### **Random Number Generation**
- [x] **Cryptographic RNG**: tossl::randbytes, tossl::rand::bytes
- [x] **Pseudo-RNG**: tossl::rand::bytes (legacy)
- [x] **Seed management**: tossl::rand::bytes (legacy)

### **Time Operations**
- [x] **Certificate time validation**: tossl::x509::time_validate
- [x] **Time conversion/comparison**: Implemented (`tossl::time::convert`, `tossl::time::compare`)

## 🛡️ **Security Features**

### **FIPS Support**
- [x] **FIPS 140-2 compliance/mode/validation**: Implemented (`tossl::fips::enable`, `tossl::fips::status`)

### **Hardware Acceleration**
- [x] **AES-NI, SHA-NI, RSA acceleration**: Implemented (`tossl::hardware::detect`)

### **Side-Channel Protection**
- [x] **Constant-time ops, memory/timing protection**: Implemented (`tossl::sidechannel::protect`)

## 📊 **Performance & Monitoring**

### **Performance Optimization**
- [x] **Algorithm discovery**: Implemented (`tossl::algorithm::list`, `tossl::algorithm::info`)
- [x] **Benchmarking, monitoring, resource usage**: Implemented (`tossl::benchmark`)

### **Logging & Debugging**
- [x] **Provider management**: Implemented (`tossl::provider::load`, `tossl::provider::unload`, `tossl::provider::list`)
- [x] **Cryptographic logging, error handling, debug info**: Implemented (`tossl::cryptolog`)

## 🔄 **Protocol Support**

### **ACME Protocol**
- [x] **ACME v2, challenges, account/order management, automation**: Implemented in C
  - **Status**: C implementation with libcurl integration
  - **Implemented**: `tossl::acme::directory`, `tossl::acme::create_account`, `tossl::acme::create_order`
  - **DNS-01 Challenge**: `tossl::acme::dns01_challenge`, `tossl::acme::cleanup_dns`
  - **Dependencies**: libcurl, jsoncpp

### **HTTP/HTTPS Client**
- [x] **HTTP client functionality**: Implemented with libcurl integration
  - **Implemented**: `tossl::http::get`, `tossl::http::post`
  - **Dependencies**: libcurl, jsoncpp
  - **Features**: SSL/TLS support, custom headers, timeouts, redirects

### **Other Protocols**
- [x] **PKCS#7**: tossl::pkcs7::* (sign, verify, encrypt, decrypt, info)
- [x] **PKCS#12**: tossl::pkcs12::* (create, parse)
- [ ] **OpenPGP**: Not implemented
  - **Status**: Removed from TOSSL (license conflicts with GPGME)
  - **Alternative**: Separate GPL-licensed extension if needed
- [ ] **S/MIME, SSH, Kerberos**: Not implemented

## 🧪 **Testing & Validation**

### **Test Suite**
- [x] **Unit tests**: test_high_priority_features.tcl, test_new_features.tcl, test_ssl_advanced.tcl, etc.
- [ ] **Integration, performance, security tests**: Not implemented

### **Validation**
- [x] **OpenSSL compatibility**: High-priority features tested
- [ ] **Standards/security validation**: Not fully implemented

## 📚 **Documentation**

### **API Documentation**
- [x] **Function documentation**: README.md, code comments
- [x] **Example code**: README.md, test scripts
- [ ] **Best practices, security guidelines, user guides, migration guide**: Not implemented

## 🚀 **Advanced Features**

### **Quantum Resistance, ZKP, Homomorphic Encryption**
- [ ] **Not implemented**

---

## 📋 **Priority Levels**

### **High Priority** (Essential for basic functionality)
- All checked off above (see code and Tcl commands)

### **Medium Priority** (Important for completeness)
- [x] **HTTP/HTTPS client** (libcurl integration)
- [x] **ACME protocol** (C implementation)
- [x] **DNS-01 challenge** support for ACME

### **Low Priority** (Nice to have)
- [ ] **OpenPGP support** (separate extension)
- [ ] **S/MIME support**
- [ ] **Advanced SSL/TLS features**

---

## 🎯 **Implementation Strategy**

1. **Phase 1**: Core crypto (✅ **COMPLETED**)
2. **Phase 2**: PKI/cert (✅ **COMPLETED**)
3. **Phase 3**: SSL/TLS (✅ **COMPLETED**)
4. **Phase 4**: Advanced features (✅ **COMPLETED**)
5. **Phase 5**: HTTP/ACME integration (✅ **COMPLETED**)

**Changelog (2024-12):**
- **Removed PGP references**: PGP functionality not implemented in C code
- **Updated ACME status**: Currently Tcl-only, planned for C implementation
- **Added HTTP/HTTPS client**: Planned with libcurl integration
- **Corrected legacy cipher status**: Actually implemented via tossl::legacy::*
- **Updated implementation strategy**: Core features complete, focusing on HTTP/ACME

**Changelog (2024-07):**
- **Advanced SSL/TLS Features**: Certificate status checking, PFS testing, certificate pinning, OCSP stapling
- **Hardware Acceleration Detection**: AES-NI, SHA-NI, AVX2, hardware RNG detection
- **Benchmarking Tools**: RSA, EC, cipher, and hash benchmarking with performance metrics
- **Side-Channel Protection**: Constant-time operations, memory protection, timing protection detection
- **Cryptographic Logging**: Enable/disable/status/clear operations for cryptographic event logging
- **Enhanced Security**: Client authentication, certificate transparency, advanced SSL/TLS security features
- **ALPN Support**: Fully implemented with Tcl callback invocation during SSL handshake
- **Socket Wrapping**: Tcl socket channels can be wrapped with SSL/TLS
- **Enhanced SSL/TLS**: SNI, ALPN, protocol version control, socket info
- **Utility Features**: URL encoding/decoding, time conversion/comparison, random testing
- **Analysis Tools**: Key/cipher analysis, signature validation, cryptographic testing
- **ASN.1 Operations**: Basic ASN.1 encoding, OID conversion
- **Provider Management**: FIPS support, algorithm discovery, provider loading/unloading

*This document is now up to date with the codebase and Tcl interface as of December 2024.* 