# TOSSL Missing Features TODO

This document tracks missing and implemented features for TOSSL, aiming for OpenSSL compatibility. As of June 2024, the codebase is modular, multi-file, and most high/medium priority features are implemented. This update reflects the actual code and Tcl-level commands.

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
- [ ] **Legacy ciphers**: DES, 3DES, Blowfish, CAST5, RC4, RC5  
  _Supported via tossl::legacy::* commands, but not recommended or enabled by default._
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
- [ ] **Certificate status checking**: OCSP stapling and full status not yet implemented

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
- [ ] **Client authentication**: Not yet implemented
- [ ] **Server name indication (SNI)**: Not yet implemented
- [ ] **Application layer protocol negotiation (ALPN)**: Not yet implemented
- [ ] **Certificate transparency (CT extension)**: Partial

### **SSL/TLS Security**
- [ ] **Perfect forward secrecy (PFS)**: Not explicitly tested
- [ ] **Certificate pinning (HPKP)**: Not implemented
- [ ] **OCSP stapling**: Not implemented

## 🔍 **Cryptographic Analysis**

### **Cryptographic Testing/Validation**
- [ ] **Random number testing**: Not implemented
- [ ] **Key/cert/cipher analysis**: Not implemented
- [ ] **Signature validation**: Not implemented

## 🔧 **Utility Operations**

### **Encoding/Decoding**
- [x] **Base64, Base64URL, Base32, Base32Hex**: tossl::base64::*, ::base64url::*
- [x] **Hex encoding/decoding**: tossl::hex::*
- [ ] **URL encoding**: Not implemented
- [ ] **ASN.1 operations**: Not implemented

### **Random Number Generation**
- [x] **Cryptographic RNG**: tossl::randbytes, tossl::rand::bytes
- [x] **Pseudo-RNG**: tossl::rand::bytes (legacy)
- [x] **Seed management**: tossl::rand::bytes (legacy)

### **Time Operations**
- [x] **Certificate time validation**: tossl::x509::time_validate
- [ ] **Time conversion/comparison**: Not implemented

## 🛡️ **Security Features**

### **FIPS Support**
- [ ] **FIPS 140-2 compliance/mode/validation**: Not implemented

### **Hardware Acceleration**
- [ ] **AES-NI, SHA-NI, RSA acceleration**: Not explicitly exposed

### **Side-Channel Protection**
- [ ] **Constant-time ops, memory/timing protection**: Not explicitly exposed

## 📊 **Performance & Monitoring**

### **Performance Optimization**
- [ ] **Benchmarking, monitoring, resource usage**: Not implemented

### **Logging & Debugging**
- [ ] **Cryptographic logging, error handling, debug info**: Not implemented

## 🔄 **Protocol Support**

### **ACME Protocol**
- [ ] **ACME v2, challenges, account/order management, automation**: Not implemented

### **Other Protocols**
- [x] **PKCS#7**: tossl::pkcs7::* (sign, verify, encrypt, decrypt, info)
- [x] **PKCS#12**: tossl::pkcs12::* (create, parse)
- [ ] **OpenPGP (partial)**: tossl::pgp::* (basic RSA keygen, parse, import/export, demo hybrid encryption)
  - **Implemented:**
    - RSA OpenPGP key generation (with self-signature)
    - Key parsing, import, export (with roundtrip tests)
    - PGP-style hybrid encryption/decryption (AES+RSA, demo only)
  - **Missing for full RFC 4880 compliance:**
    - DSA/ElGamal, ECC, and subkey support
    - Multiple user IDs, subpackets, revocation, key expiration
    - OpenPGP message formats (literal data, compressed data, signature packets, etc.)
    - Signature creation/verification, detached signatures, message signing
    - GnuPG and OpenPGP interoperability
    - S2K password-protected secret key export/import (beyond basic stub)
    - Advanced features: armor CRC, trust packets, etc.
- [ ] **S/MIME, SSH, Kerberos**: Not implemented

## 🧪 **Testing & Validation**

### **Test Suite**
- [x] **Unit tests**: test_high_priority_features.tcl, test_new_features.tcl, etc.
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

### **Medium/Low Priority**
- See unchecked boxes above

---

## 🎯 **Implementation Strategy**

1. **Phase 1**: Core crypto (done)
2. **Phase 2**: PKI/cert (done)
3. **Phase 3**: SSL/TLS (done for context/cipher/protocol)
4. **Phase 4**: Advanced features (partial)
5. **Phase 5**: Testing/docs (partial)

**Changelog (2024-06):**
- Updated to reflect actual code and Tcl-level commands after modular refactor.
- Marked as complete: DSA/EC/Ed25519/Ed448/X25519/X448/SM2, keywrap, legacy support (tossl::legacy::*), PBE, PKCS#7, PKCS#12, hex encoding, certificate/CSR modification, OCSP, and more.
- Noted partial/legacy/known issues and missing features.

*This document is now up to date with the codebase and Tcl interface as of June 2024.* 