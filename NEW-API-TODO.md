# TOSSL OpenSSL 3.x API Migration Plan

This document outlines the complete migration of TOSSL from legacy OpenSSL APIs to the latest OpenSSL 3.x APIs. The goal is to eliminate all deprecation warnings and use modern, secure, and future-proof APIs.

## 🎯 **Migration Goals**

- ✅ Eliminate all deprecation warnings
- ✅ Use modern OpenSSL 3.x APIs throughout
- ✅ Improve security and performance
- ✅ Ensure future compatibility
- ✅ Support provider-based cryptography
- ✅ Maintain backward compatibility for Tcl interface

## 📋 **Current State Analysis**

### **Deprecated APIs Currently Used**
- `EVP_PKEY_get0_RSA()` → Use `EVP_PKEY` operations directly
- `EVP_PKEY_set1_RSA()` → Use `EVP_PKEY_assign()` or `EVP_PKEY_new()`
- `RSA_check_key()` → Use `EVP_PKEY_check()`
- `RSA_get0_key()` → Use `EVP_PKEY_get_bn_param()`
- `RSA_set0_key()` → Use `EVP_PKEY_set_bn_param()`
- `EVP_CIPHER_free()` → Use `EVP_CIPHER_fetch()`/`EVP_CIPHER_free()`
- `X509_CRL_get_lastUpdate()` → Use `X509_CRL_get0_lastUpdate()`

### **Files Requiring Migration**
1. `tossl_keys.c` - Key management operations
2. `tossl_rsa.c` - RSA-specific operations
3. `tossl_dsa.c` - DSA-specific operations
4. `tossl_ec.c` - EC-specific operations
5. `tossl_core.c` - Core crypto operations
6. `tossl_crl.c` - CRL operations
7. `tossl_x509.c` - Certificate operations

## 🔄 **Migration Strategy**

### **Phase 1: Core Infrastructure (Week 1)**

#### **1.1 Update Build System**
```makefile
# Add OpenSSL 3.x specific flags
CFLAGS += -DOPENSSL_API_COMPAT=0x30000000L
CFLAGS += -DOPENSSL_NO_DEPRECATED
```

#### **1.2 Create Modern API Wrappers**
Create `tossl_modern.h` with:
```c
// Modern OpenSSL 3.x API wrappers
EVP_PKEY *modern_key_new(int type);
int modern_key_set_rsa_params(EVP_PKEY *pkey, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int modern_key_get_rsa_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d);
int modern_key_check(EVP_PKEY *pkey);
```

#### **1.3 Update Initialization**
```c
// In tossl_main.c
int Tossl_Init(Tcl_Interp *interp) {
    // Initialize OpenSSL 3.x
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    
    // Load default provider
    OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        return TCL_ERROR;
    }
    
    // Load legacy provider for backward compatibility
    OSSL_PROVIDER *legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    
    // ... rest of initialization
}
```

### **Phase 2: Key Management Migration (Week 2)**

#### **2.1 Replace Key Access Functions**
**Before (Legacy):**
```c
RSA *rsa = EVP_PKEY_get0_RSA(pkey);
RSA_get0_key(rsa, &n, &e, &d);
```

**After (Modern):**
```c
BIGNUM *n = NULL, *e = NULL, *d = NULL;
EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
```

#### **2.2 Update Key Generation**
**Before:**
```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
```

**After:**
```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
OSSL_PARAM params[] = {
    OSSL_PARAM_uint("bits", &bits),
    OSSL_PARAM_END
};
EVP_PKEY_CTX_set_params(ctx, params);
```

### **Phase 3: Crypto Operations Migration (Week 3)**

#### **3.1 Update Cipher Operations**
**Before:**
```c
const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");
EVP_CIPHER_free(cipher);
```

**After:**
```c
EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "aes-256-cbc", NULL);
EVP_CIPHER_free(cipher);
```

#### **3.2 Update Digest Operations**
**Before:**
```c
const EVP_MD *md = EVP_get_digestbyname("sha256");
```

**After:**
```c
EVP_MD *md = EVP_MD_fetch(NULL, "sha256", NULL);
```

#### **3.3 Update Sign/Verify Operations**
**Before:**
```c
RSA_sign(NID_sha256, hash, hash_len, sig, &sig_len, rsa);
RSA_verify(NID_sha256, hash, hash_len, sig, sig_len, rsa);
```

**After:**
```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
EVP_PKEY_sign_init(ctx);
EVP_PKEY_sign(ctx, sig, &sig_len, hash, hash_len);

EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
EVP_PKEY_verify_init(vctx);
EVP_PKEY_verify(vctx, sig, sig_len, hash, hash_len);
```

### **Phase 4: Certificate Operations Migration (Week 4)**

#### **4.1 Update CRL Operations**
**Before:**
```c
ASN1_TIME *last_update = X509_CRL_get_lastUpdate(crl);
ASN1_TIME *next_update = X509_CRL_get_nextUpdate(crl);
```

**After:**
```c
const ASN1_TIME *last_update = X509_CRL_get0_lastUpdate(crl);
const ASN1_TIME *next_update = X509_CRL_get0_nextUpdate(crl);
```

#### **4.2 Update Certificate Validation**
**Before:**
```c
RSA_check_key(rsa);
```

**After:**
```c
EVP_PKEY_check(pkey);
```

### **Phase 5: Provider Support (Week 5)**

#### **5.1 Add Provider Management**
```c
// Provider management functions
OSSL_PROVIDER *load_provider(const char *name);
void unload_provider(OSSL_PROVIDER *provider);
int list_providers(Tcl_Interp *interp);
```

#### **5.2 Add FIPS Support**
```c
// FIPS provider support
int enable_fips_mode(Tcl_Interp *interp);
int check_fips_status(Tcl_Interp *interp);
```

#### **5.3 Add Algorithm Discovery**
```c
// Modern algorithm discovery
int list_available_algorithms(Tcl_Interp *interp, const char *type);
int get_algorithm_properties(Tcl_Interp *interp, const char *algorithm);
```

## 🧪 **Testing Strategy**

### **Unit Tests**
- Create test suite for each migrated function
- Test both legacy and modern APIs side-by-side
- Verify identical results

### **Integration Tests**
- Test all Tcl commands with new APIs
- Verify performance improvements
- Test provider switching

### **Compatibility Tests**
- Test with different OpenSSL versions
- Test with different providers
- Test FIPS mode

## 📊 **Migration Checklist**

### **Week 1: Infrastructure**
- [x] Update build system with OpenSSL 3.x flags
- [x] Create modern API wrapper functions
- [x] Update initialization code
- [x] Add provider management

### **Week 2: Key Management**
- [x] Migrate `tossl_keys.c`
- [x] Migrate `tossl_rsa.c`
- [x] Migrate `tossl_dsa.c`
- [x] Migrate `tossl_ec.c`

### **Week 3: Crypto Operations**
- [x] Migrate `tossl_core.c`
- [x] Update cipher operations
- [x] Update digest operations
- [x] Update sign/verify operations

### **Week 4: Certificate Operations**
- [x] Migrate `tossl_x509.c`
- [x] Migrate `tossl_crl.c`
- [x] Update certificate validation
- [x] Update CRL operations

### **Week 5: Advanced Features**
- [x] Add provider management commands (completed with simplified implementation)
- [x] Add FIPS support (completed)
- [x] Add algorithm discovery (completed with simplified implementation)
- [ ] Performance optimization

## 🔧 **Implementation Details**

### **New Tcl Commands to Add**
```tcl
# Provider management
tossl::provider::load name
tossl::provider::unload name
tossl::provider::list

# Algorithm discovery
tossl::algorithm::list type
tossl::algorithm::info name

# FIPS support
tossl::fips::enable
tossl::fips::status
```

### **Backward Compatibility**
- Keep existing Tcl command interface unchanged
- Maintain same parameter names and return values
- Add new commands for modern features
- Provide migration guide for users

### **Performance Considerations**
- Use `EVP_CIPHER_fetch()` instead of `EVP_get_cipherbyname()`
- Cache frequently used algorithms
- Use provider-specific optimizations
- Minimize memory allocations

## 🚀 **Benefits After Migration**

### **Immediate Benefits**
- ✅ No more deprecation warnings
- ✅ Better performance with modern APIs
- ✅ Improved security with provider model
- ✅ Future-proof codebase

### **Long-term Benefits**
- ✅ Support for new OpenSSL features
- ✅ Better FIPS compliance
- ✅ Hardware acceleration support
- ✅ Provider-based cryptography

## 📚 **Resources**

### **OpenSSL 3.x Documentation**
- [OpenSSL 3.0 Migration Guide](https://www.openssl.org/docs/man3.0/man7/migration_guide.html)
- [OpenSSL 3.0 Provider Documentation](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [OpenSSL 3.0 EVP Documentation](https://www.openssl.org/docs/man3.0/man7/evp.html)

### **Migration Examples**
- [OpenSSL 3.0 Migration Examples](https://github.com/openssl/openssl/tree/master/demos)
- [Provider Examples](https://github.com/openssl/openssl/tree/master/demos/provider)

## ⚠️ **Risks and Mitigation**

### **Risks**
- Breaking changes in API behavior
- Performance regressions
- Compatibility issues with existing code

### **Mitigation**
- Comprehensive testing at each phase
- Gradual migration with fallback options
- Performance benchmarking
- Backward compatibility layer

---

## 📅 **Timeline Summary**

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Infrastructure | Build system, wrappers, initialization |
| 2 | Key Management | RSA, DSA, EC operations |
| 3 | Crypto Operations | Ciphers, digests, signing |
| 4 | Certificate Operations | X.509, CRL operations |
| 5 | Advanced Features | Providers, FIPS, discovery |

**Total Estimated Time: 5 weeks**

---

**Progress Notes:**
- ✅ Project builds and loads successfully with OpenSSL 3.x (no critical deprecation errors)
- ✅ Infrastructure, RSA, CRL, core crypto, DSA, EC, and X.509 modules migrated
- ✅ All sign/verify and digest operations are now modernized
- ✅ Advanced features (provider management, FIPS, algorithm discovery) implemented with working Tcl commands
- 🔄 Provider enumeration uses simplified implementation due to OpenSSL callback issues
- 🧪 Performance optimization and advanced provider enumeration are next steps

*This migration plan ensures TOSSL uses the latest OpenSSL 3.x APIs while maintaining backward compatibility and improving security and performance.* 