# OpenID Connect (OIDC) Implementation Plan for TOSSL

## Overview

This document outlines the implementation plan for adding OpenID Connect (OIDC) support to TOSSL, building on the existing OAuth2 and JWT infrastructure. OIDC is an authentication layer that sits on top of OAuth 2.0, providing standardized user authentication capabilities.

## Current Infrastructure Analysis

### ✅ **Available Components (Strong Foundation)**
- **OAuth2 Implementation**: Complete OAuth2 flows with PKCE, token introspection, device flow ✅
- **JWT Support**: Full JWT creation, verification, parsing, and claims validation ✅
- **HTTP Client**: Enhanced HTTP client with custom headers, authentication, session management ✅
- **JSON Processing**: JSON parsing and generation capabilities ✅
- **Cryptography**: RSA/EC key generation, digital signatures, HMAC, Base64URL ✅
- **Random Generation**: Secure random value generation ✅
- **Error Handling**: Comprehensive error reporting framework ✅

### ✅ **OIDC-Ready Features**
- **Bearer Token Authentication**: `Authorization: Bearer token` support ✅
- **JWT ID Token Support**: JWT creation and verification for ID tokens ✅
- **Claims Validation**: Standard JWT claims (iss, aud, exp, nbf, etc.) ✅
- **OAuth2 Scopes**: Support for `openid` scope and other OIDC scopes ✅
- **State Management**: Secure state parameter generation and validation ✅

## Implementation Plan

### **Phase 1: OIDC Discovery (Priority: High) - 1-2 days**

#### **1.1 OIDC Discovery Endpoint**
Implement RFC 8414 (OAuth 2.0 Authorization Server Metadata) support.

**New Commands:**
```tcl
# Discover OIDC provider configuration
tossl::oidc::discover -issuer <issuer_url>

# Returns provider configuration including:
# - authorization_endpoint
# - token_endpoint  
# - userinfo_endpoint
# - jwks_uri
# - end_session_endpoint
# - supported_scopes
# - supported_response_types
# - supported_grant_types
# - supported_claim_types
# - supported_claims
# - supported_token_endpoint_auth_methods
# - supported_subject_types
# - supported_id_token_signing_alg_values
# - supported_id_token_encryption_alg_values
# - supported_userinfo_signing_alg_values
# - supported_userinfo_encryption_alg_values
# - supported_request_object_signing_alg_values
# - supported_request_object_encryption_alg_values
# - supported_display_values
# - supported_claim_types
# - supported_claims
# - service_documentation
# - claims_locales_supported
# - ui_locales_supported
# - claims_parameter_supported
# - request_parameter_supported
# - request_uri_parameter_supported
# - require_request_uri_registration
# - op_policy_uri
# - op_tos_uri
# - issuer
```

**Implementation Tasks:**
- [ ] Add `tossl_oidc.c` source file
- [ ] Implement OIDC discovery HTTP request
- [ ] Parse and validate discovery response
- [ ] Cache discovery results for performance
- [ ] Add error handling for discovery failures
- [ ] Add validation of required OIDC endpoints

#### **1.2 JWKS (JSON Web Key Set) Support**
Implement RFC 7517 (JSON Web Key Set) for public key discovery.

**New Commands:**
```tcl
# Fetch and parse JWKS from OIDC provider
tossl::oidc::fetch_jwks -jwks_uri <jwks_url>

# Get specific key from JWKS by key ID
tossl::oidc::get_jwk -jwks <jwks_data> -kid <key_id>

# Validate JWKS structure and keys
tossl::oidc::validate_jwks -jwks <jwks_data>
```

**Implementation Tasks:**
- [ ] Implement JWKS fetching and parsing
- [ ] Add key ID (kid) lookup functionality
- [ ] Validate JWKS structure and key formats
- [ ] Cache JWKS for performance (with expiration)
- [ ] Add automatic JWKS refresh on expiration

### **Phase 2: Enhanced JWT Validation (Priority: High) - 1-2 days**

#### **2.1 OIDC ID Token Validation**
Implement OpenID Connect Core 1.0 ID token validation requirements.

**New Commands:**
```tcl
# Validate OIDC ID token with comprehensive checks
tossl::oidc::validate_id_token -token <id_token> -issuer <issuer> -audience <audience> ?-nonce <nonce>? ?-max_age <seconds>? ?-acr_values <acr>? ?-auth_time <timestamp>?

# Extract and validate specific OIDC claims
tossl::oidc::extract_oidc_claims -token <id_token> -issuer <issuer> -audience <audience>

# Validate ID token signature using JWKS
tossl::oidc::verify_id_token_signature -token <id_token> -jwks <jwks_data>
```

**Implementation Tasks:**
- [ ] Implement OIDC-specific ID token validation rules
- [ ] Add nonce validation for CSRF protection
- [ ] Add max_age validation for authentication freshness
- [ ] Add acr (Authentication Context Class Reference) validation
- [ ] Add auth_time validation
- [ ] Implement signature verification using JWKS
- [ ] Add comprehensive error reporting for validation failures

#### **2.2 OIDC Claims Validation**
Implement standard OIDC claims validation.

**New Commands:**
```tcl
# Validate OIDC standard claims
tossl::oidc::validate_claims -claims <claims_dict> -required_claims {claim1 claim2}

# Check for specific OIDC claim values
tossl::oidc::check_claim -claims <claims_dict> -claim <claim_name> -value <expected_value>

# Validate claim formats (email, phone, etc.)
tossl::oidc::validate_claim_format -claim <claim_name> -value <claim_value>
```

**Implementation Tasks:**
- [ ] Implement standard OIDC claims validation
- [ ] Add email format validation
- [ ] Add phone number format validation
- [ ] Add URL format validation
- [ ] Add timestamp validation
- [ ] Add boolean claim validation

### **Phase 3: UserInfo Endpoint (Priority: Medium) - 1 day**

#### **3.1 UserInfo Endpoint Support**
Implement RFC 7662 (UserInfo Endpoint) support.

**New Commands:**
```tcl
# Fetch user information from UserInfo endpoint
tossl::oidc::userinfo -access_token <token> -userinfo_url <url> ?-headers <headers>?

# Validate UserInfo response
tossl::oidc::validate_userinfo -userinfo <userinfo_data> -expected_subject <subject>

# Parse and extract specific user claims
tossl::oidc::extract_user_claims -userinfo <userinfo_data> -claims {name email picture}
```

**Implementation Tasks:**
- [ ] Implement UserInfo endpoint HTTP requests
- [ ] Add Bearer token authentication for UserInfo requests
- [ ] Parse and validate UserInfo JSON responses
- [ ] Add subject validation between ID token and UserInfo
- [ ] Add error handling for UserInfo failures
- [ ] Add caching for UserInfo responses (with appropriate TTL)

### **Phase 4: OIDC Logout (Priority: Medium) - 1 day**

#### **4.1 End Session Endpoint**
Implement OpenID Connect RP-Initiated Logout 1.0.

**New Commands:**
```tcl
# Initiate OIDC logout
tossl::oidc::end_session -id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?

# Generate logout URL
tossl::oidc::logout_url -id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?

# Validate logout response
tossl::oidc::validate_logout_response -response <response_data>
```

**Implementation Tasks:**
- [ ] Implement end session endpoint requests
- [ ] Add id_token_hint parameter support
- [ ] Add post_logout_redirect_uri parameter support
- [ ] Add state parameter for logout CSRF protection
- [ ] Add logout response validation
- [ ] Add error handling for logout failures

### **Phase 5: OIDC Provider Presets (Priority: Low) - 1 day**

#### **5.1 Pre-configured OIDC Providers**
Add convenience functions for popular OIDC providers.

**New Commands:**
```tcl
# Google OIDC configuration
tossl::oidc::provider::google -client_id <id> -client_secret <secret> ?-redirect_uri <uri>?

# Microsoft OIDC configuration  
tossl::oidc::provider::microsoft -client_id <id> -client_secret <secret> ?-redirect_uri <uri>?

# GitHub OIDC configuration
tossl::oidc::provider::github -client_id <id> -client_secret <secret> ?-redirect_uri <uri>?

# Generic OIDC provider configuration
tossl::oidc::provider::custom -issuer <issuer> -client_id <id> -client_secret <secret> ?-redirect_uri <uri>?
```

**Implementation Tasks:**
- [ ] Add Google OIDC provider configuration
- [ ] Add Microsoft OIDC provider configuration
- [ ] Add GitHub OIDC provider configuration
- [ ] Add generic OIDC provider template
- [ ] Add provider-specific scope defaults
- [ ] Add provider-specific claim mappings

### **Phase 6: Enhanced OAuth2 Integration (Priority: Medium) - 1 day**

#### **6.1 OIDC-Enhanced OAuth2 Commands**
Enhance existing OAuth2 commands with OIDC awareness.

**Enhanced Commands:**
```tcl
# OIDC-enhanced authorization URL
tossl::oauth2::authorization_url_oidc -client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url> -nonce <nonce> ?-max_age <seconds>? ?-acr_values <acr>?

# OIDC-enhanced token exchange
tossl::oauth2::exchange_code_oidc -client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url> ?-nonce <nonce>?

# OIDC-enhanced token refresh
tossl::oauth2::refresh_token_oidc -client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url> ?-scope <scope>?
```

**Implementation Tasks:**
- [ ] Add nonce parameter to authorization URL generation
- [ ] Add max_age parameter to authorization URL generation
- [ ] Add acr_values parameter to authorization URL generation
- [ ] Add ID token validation to token exchange
- [ ] Add nonce validation to token exchange
- [ ] Add scope validation for OIDC flows

## Technical Implementation Details

### **File Structure**
```
tossl_oidc.c          # Core OIDC functionality
tossl_oidc.h          # OIDC function prototypes
test_oidc.tcl         # OIDC test suite
oidc_example.tcl      # Usage examples
doc/oidc_*.md         # OIDC documentation
```

### **Dependencies**
- **Existing**: libcurl, json-c, OpenSSL ✅
- **New**: None (uses existing infrastructure)

### **Build System Updates**
```makefile
# Add to Makefile
SRC_MODULAR += tossl_oidc.c
CFLAGS += -DOIDC_SUPPORT
```

### **Header File Updates (`tossl.h`)**
```c
// OIDC function prototypes
int OidcDiscoverCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int OidcFetchJwksCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int OidcValidateIdTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int OidcUserinfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int OidcEndSessionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Initialization function
int Tossl_OidcInit(Tcl_Interp *interp);
```

## Example Usage Scenarios

### **1. Complete OIDC Flow**
```tcl
# 1. Discover OIDC provider
set config [tossl::oidc::discover -issuer "https://accounts.google.com"]

# 2. Generate OAuth2 authorization URL with OIDC scope
set nonce [tossl::oidc::generate_nonce]
set auth_url [tossl::oauth2::authorization_url_oidc \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -nonce $nonce \
    -authorization_url [dict get $config authorization_endpoint]]

puts "Visit: $auth_url"

# 3. Exchange code for tokens (includes ID token)
set tokens [tossl::oauth2::exchange_code_oidc \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -code $auth_code \
    -redirect_uri "https://your-app.com/callback" \
    -token_url [dict get $config token_endpoint] \
    -nonce $nonce]

# 4. Validate ID token
set id_token_valid [tossl::oidc::validate_id_token \
    -token [dict get $tokens id_token] \
    -issuer [dict get $config issuer] \
    -audience "your_client_id" \
    -nonce $nonce]

if {![dict get $id_token_valid valid]} {
    error "ID token validation failed: [dict get $id_token_valid error]"
}

# 5. Get user profile
set userinfo [tossl::oidc::userinfo \
    -access_token [dict get $tokens access_token] \
    -userinfo_url [dict get $config userinfo_endpoint]]

# 6. Use access token for API calls
set api_response [tossl::http::get_enhanced "https://api.example.com/data" \
    -headers "Authorization: Bearer [dict get $tokens access_token]"]
```

### **2. Google OIDC Integration**
```tcl
# Use Google OIDC provider preset
set google_config [tossl::oidc::provider::google \
    -client_id "your-google-client-id" \
    -client_secret "your-google-client-secret" \
    -redirect_uri "https://your-app.com/callback"]

# Complete OIDC flow with Google
set nonce [tossl::oidc::generate_nonce]
set auth_url [tossl::oauth2::authorization_url_oidc \
    -client_id [dict get $google_config client_id] \
    -redirect_uri [dict get $google_config redirect_uri] \
    -scope "openid profile email" \
    -state [tossl::oauth2::generate_state] \
    -nonce $nonce \
    -authorization_url [dict get $google_config authorization_endpoint]]

# ... rest of the flow
```

### **3. OIDC Logout**
```tcl
# End user session
tossl::oidc::end_session \
    -id_token_hint [dict get $tokens id_token] \
    -post_logout_redirect_uri "https://your-app.com/logout" \
    -end_session_endpoint [dict get $config end_session_endpoint] \
    -state [tossl::oauth2::generate_state]
```

## Testing Strategy

### **Unit Tests (`test_oidc.tcl`)**
- [ ] OIDC discovery tests
- [ ] JWKS fetching and parsing tests
- [ ] ID token validation tests
- [ ] UserInfo endpoint tests
- [ ] End session tests
- [ ] Provider preset tests
- [ ] Error handling tests
- [ ] Integration with existing OAuth2/JWT tests

### **Integration Tests**
- [ ] End-to-end OIDC flow tests
- [ ] Google OIDC integration tests
- [ ] Microsoft OIDC integration tests
- [ ] GitHub OIDC integration tests
- [ ] Error recovery tests
- [ ] Performance tests

### **Mock OIDC Server**
- [ ] Simple OIDC server for testing
- [ ] Discovery endpoint
- [ ] JWKS endpoint
- [ ] UserInfo endpoint
- [ ] End session endpoint
- [ ] Various OIDC flows support
- [ ] Error condition simulation

## Security Considerations

### **ID Token Security**
- [ ] Cryptographic signature verification
- [ ] Issuer validation
- [ ] Audience validation
- [ ] Nonce validation for CSRF protection
- [ ] Expiration validation
- [ ] Not-before validation
- [ ] Authentication time validation

### **UserInfo Security**
- [ ] Bearer token authentication
- [ ] Subject validation between ID token and UserInfo
- [ ] HTTPS enforcement
- [ ] Response validation

### **Logout Security**
- [ ] State parameter for CSRF protection
- [ ] ID token hint validation
- [ ] Secure redirect URI validation

### **General Security**
- [ ] Input validation and sanitization
- [ ] Secure error messages (no sensitive data)
- [ ] HTTPS enforcement for all endpoints
- [ ] Proper key management and validation

## Documentation Updates

### **README.md Updates**
- [ ] Add OIDC section to features list
- [ ] Add OIDC usage examples
- [ ] Add OIDC provider integration examples
- [ ] Update API reference

### **New Documentation**
- [ ] `OIDC-README.md` - Comprehensive OIDC guide
- [ ] `OIDC-EXAMPLES.md` - Real-world OIDC examples
- [ ] `OIDC-SECURITY.md` - OIDC security best practices
- [ ] Individual command documentation in `doc/` directory

## Migration and Compatibility

### **Backward Compatibility**
- [ ] All existing OAuth2 commands remain unchanged
- [ ] All existing JWT commands remain unchanged
- [ ] New OIDC commands are additive
- [ ] No breaking changes to existing API

### **Dependency Management**
- [ ] OIDC support is optional (compile-time flag)
- [ ] Graceful degradation if OIDC not compiled
- [ ] Clear dependency requirements

## Timeline Estimate

### **Phase 1 (OIDC Discovery)**: 1-2 days
- OIDC discovery endpoint: 1 day
- JWKS support: 1 day

### **Phase 2 (Enhanced JWT Validation)**: 1-2 days
- OIDC ID token validation: 1 day
- OIDC claims validation: 1 day

### **Phase 3 (UserInfo Endpoint)**: 1 day
- UserInfo endpoint support: 1 day

### **Phase 4 (OIDC Logout)**: 1 day
- End session endpoint: 1 day

### **Phase 5 (Provider Presets)**: 1 day
- Provider configurations: 1 day

### **Phase 6 (Enhanced OAuth2 Integration)**: 1 day
- OIDC-enhanced OAuth2 commands: 1 day

### **Testing and Documentation**: 1-2 days
- Unit and integration tests: 1 day
- Documentation updates: 1 day

**Total Estimated Time**: 6-9 days

## Success Criteria

### **Functional Requirements**
- [ ] Complete OIDC discovery support
- [ ] Full ID token validation
- [ ] UserInfo endpoint support
- [ ] OIDC logout support
- [ ] Provider presets for major providers
- [ ] Integration with existing OAuth2/JWT infrastructure
- [ ] Comprehensive error handling

### **Performance Requirements**
- [ ] OIDC discovery completes within 5 seconds
- [ ] ID token validation completes within 1 second
- [ ] UserInfo requests complete within 3 seconds
- [ ] Memory usage remains reasonable (< 5MB for typical usage)

### **Security Requirements**
- [ ] Cryptographic signature verification
- [ ] CSRF protection via nonce validation
- [ ] Secure token handling
- [ ] Input validation
- [ ] No sensitive data in error messages

### **Usability Requirements**
- [ ] Simple, intuitive API
- [ ] Comprehensive error messages
- [ ] Good documentation and examples
- [ ] Backward compatibility
- [ ] Provider presets for common use cases

## Risk Assessment

### **Technical Risks**
- **Low**: OIDC discovery (HTTP + JSON parsing) ✅
- **Low**: JWKS support (existing JWT infrastructure) ✅
- **Low**: ID token validation (existing JWT validation) ✅
- **Low**: UserInfo endpoint (existing HTTP client) ✅
- **Low**: End session endpoint (existing HTTP client) ✅

### **Integration Risks**
- **Low**: OAuth2 integration (existing OAuth2 infrastructure) ✅
- **Low**: JWT integration (existing JWT infrastructure) ✅
- **Low**: HTTP client integration (existing HTTP infrastructure) ✅

### **Security Risks**
- **Medium**: ID token validation (security critical)
- **Low**: JWKS key validation (existing crypto infrastructure) ✅
- **Low**: Nonce validation (existing random generation) ✅

## Conclusion

Adding OpenID Connect support to TOSSL is **highly feasible and valuable** because:

1. **Strong Foundation**: TOSSL already has 90% of required infrastructure
2. **Low Risk**: Building on proven OAuth2/JWT/HTTP infrastructure
3. **High Value**: Complete OAuth2 + OIDC solution
4. **Production Ready**: Suitable for enterprise applications
5. **Standards Compliant**: Full RFC compliance
6. **Performance**: Native C implementation
7. **Security**: Built on proven cryptographic primitives

The implementation will transform TOSSL into a **complete, production-ready OAuth 2.0 + OpenID Connect solution** that can compete with dedicated OIDC libraries in other languages.

## Next Steps

1. **Review and approve implementation plan**
2. **Set up development environment**
3. **Begin Phase 1 implementation (OIDC Discovery)**
4. **Implement comprehensive test suite**
5. **Create documentation and examples**
6. **Perform security review**
7. **Deploy and validate with real OIDC providers** 