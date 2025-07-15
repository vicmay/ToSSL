# OAuth2 Implementation Plan for TOSSL

## Overview

This document outlines the implementation plan for adding OAuth2 support to TOSSL, leveraging the existing HTTP client, JSON processing, and cryptographic infrastructure.

## Current Infrastructure Analysis

### ✅ **Available Components**
- **HTTP Client**: `tossl::http::get` and `tossl::http::post` with HTTPS support
- **JSON Processing**: `tossl::json::parse` and `tossl::json::generate`
- **Cryptography**: RSA/EC key generation, HMAC, Base64 encoding/decoding
- **Random Generation**: `tossl::randbytes` for secure random values
- **Error Handling**: Comprehensive error reporting framework

### 🔧 **Required Enhancements**
- **JWT Support**: JSON Web Token creation, verification, and parsing
- **Enhanced HTTP Client**: Custom headers, content-type support
- **OAuth2 State Management**: Secure state parameter generation and validation
- **Token Storage**: Secure token caching and refresh mechanisms

## Implementation Phases

### Phase 1: Core OAuth2 Infrastructure (Priority: High)

#### **1.1 Enhanced HTTP Client (`tossl_http.c`)**
- [ ] Add custom headers support to `tossl::http::get`
- [ ] Add custom headers support to `tossl::http::post`
- [ ] Add content-type specification for POST requests
- [ ] Add user-agent customization
- [ ] Add timeout configuration
- [ ] Add redirect handling configuration

**New Commands:**
```tcl
tossl::http::get url ?-headers {header1 value1 header2 value2}? ?-timeout seconds?
tossl::http::post url data ?-headers {header1 value1}? ?-content_type type? ?-timeout seconds?
```

#### **1.2 JWT Support (`tossl_jwt.c`)**
- [ ] JWT header creation and validation
- [ ] JWT payload encoding/decoding
- [ ] JWT signature creation (RS256, ES256, HS256)
- [ ] JWT signature verification
- [ ] JWT token parsing without verification
- [ ] JWT expiration validation

**New Commands:**
```tcl
tossl::jwt::create -header <header_dict> -payload <payload_dict> -key <key> -alg <algorithm>
tossl::jwt::verify -token <jwt_string> -key <key> -alg <algorithm>
tossl::jwt::decode -token <jwt_string>
tossl::jwt::validate -token <jwt_string> -audience <aud> -issuer <iss>
```

#### **1.3 OAuth2 Core Module (`tossl_oauth2.c`)**
- [ ] Authorization URL generation
- [ ] Authorization code exchange
- [ ] Token refresh
- [ ] Client credentials flow
- [ ] Token response parsing
- [ ] State parameter generation and validation

**New Commands:**
```tcl
tossl::oauth2::authorization_url -client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url>
tossl::oauth2::exchange_code -client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url>
tossl::oauth2::refresh_token -client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url>
tossl::oauth2::client_credentials -client_id <id> -client_secret <secret> -token_url <url> -scope <scope>
tossl::oauth2::parse_token <token_response>
tossl::oauth2::generate_state
tossl::oauth2::validate_state <state> <expected_state>
```

### Phase 2: Advanced OAuth2 Features (Priority: Medium)

#### **2.1 PKCE Support (RFC 7636)**
- [ ] Code verifier generation
- [ ] Code challenge creation (S256 method)
- [ ] PKCE-enhanced authorization URL
- [ ] PKCE-enhanced token exchange

**New Commands:**
```tcl
tossl::oauth2::generate_code_verifier ?-length 128?
tossl::oauth2::create_code_challenge -verifier <code_verifier>
tossl::oauth2::authorization_url_pkce -client_id <id> -redirect_uri <uri> -code_challenge <challenge> -code_challenge_method S256
tossl::oauth2::exchange_code_pkce -client_id <id> -code_verifier <verifier> -code <code> -redirect_uri <uri> -token_url <url>
```

#### **2.2 Token Introspection (RFC 7662)**
- [ ] Token introspection endpoint support
- [ ] Introspection response parsing
- [ ] Token validation using introspection

**New Commands:**
```tcl
tossl::oauth2::introspect_token -token <access_token> -introspection_url <url> -client_id <id> -client_secret <secret>
tossl::oauth2::validate_introspection -introspection_result <result> -required_scopes {scope1 scope2}
```

#### **2.3 Device Authorization Flow (RFC 8628)**
- [ ] Device authorization request
- [ ] Device code polling
- [ ] Device authorization completion

**New Commands:**
```tcl
tossl::oauth2::device_authorization -client_id <id> -device_authorization_url <url> -scope <scope>
tossl::oauth2::poll_device_token -device_code <code> -token_url <url> -client_id <id> -client_secret <secret>
```

### Phase 3: Security and Validation (Priority: High)

#### **3.1 Token Security**
- [ ] Secure token storage (encrypted)
- [ ] Token expiration checking
- [ ] Automatic token refresh
- [ ] Token rotation support

**New Commands:**
```tcl
tossl::oauth2::store_token -token_data <dict> -encryption_key <key>
tossl::oauth2::load_token -encryption_key <key>
tossl::oauth2::is_token_expired -token <access_token>
tossl::oauth2::auto_refresh -token_data <dict> -client_id <id> -client_secret <secret> -token_url <url>
```

#### **3.2 Input Validation**
- [ ] URL validation
- [ ] Client ID/secret validation
- [ ] Scope validation
- [ ] Redirect URI validation
- [ ] State parameter validation

**New Commands:**
```tcl
tossl::oauth2::validate_url -url <url>
tossl::oauth2::validate_client_id -client_id <id>
tossl::oauth2::validate_scope -scope <scope> -allowed_scopes {scope1 scope2}
tossl::oauth2::validate_redirect_uri -redirect_uri <uri> -allowed_uris {uri1 uri2}
```

### Phase 4: Integration and Utilities (Priority: Medium)

#### **4.1 HTTP Client Integration**
- [ ] OAuth2-aware HTTP client
- [ ] Automatic token injection
- [ ] Automatic token refresh on 401 responses

**New Commands:**
```tcl
tossl::http::get_oauth2 -url <url> -access_token <token> ?-refresh_token <refresh> -client_id <id> -client_secret <secret> -token_url <url>?
tossl::http::post_oauth2 -url <url> -data <data> -access_token <token> ?-refresh_token <refresh> -client_id <id> -client_secret <secret> -token_url <url>?
```

#### **4.2 OAuth2 Provider Presets**
- [ ] Google OAuth2 configuration
- [ ] Microsoft OAuth2 configuration
- [ ] GitHub OAuth2 configuration
- [ ] Generic OAuth2 provider template

**New Commands:**
```tcl
tossl::oauth2::provider::google -client_id <id> -client_secret <secret> -redirect_uri <uri>
tossl::oauth2::provider::microsoft -client_id <id> -client_secret <secret> -redirect_uri <uri>
tossl::oauth2::provider::github -client_id <id> -client_secret <secret> -redirect_uri <uri>
tossl::oauth2::provider::custom -authorization_url <url> -token_url <url> -client_id <id> -client_secret <secret> -redirect_uri <uri>
```

## Technical Implementation Details

### **File Structure**
```
tossl_oauth2.c      # Core OAuth2 functionality
tossl_jwt.c         # JWT support
tossl_http.c        # Enhanced HTTP client (existing)
tossl_oauth2.h      # OAuth2 function prototypes
test_oauth2.tcl     # OAuth2 test suite
oauth2_example.tcl  # Usage examples
```

### **Dependencies**
- **Existing**: libcurl, json-c, OpenSSL
- **New**: None (uses existing infrastructure)

### **Build System Updates**
```makefile
# Add to Makefile
SRC_MODULAR += tossl_oauth2.c tossl_jwt.c
CFLAGS += -DOAUTH2_SUPPORT
```

### **Header File Updates (`tossl.h`)**
```c
// OAuth2 function prototypes
int Oauth2AuthUrlCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Oauth2ExchangeCodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Oauth2RefreshTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Oauth2ClientCredentialsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Oauth2ParseTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// JWT function prototypes
int JwtCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int JwtVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int JwtDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Initialization functions
int Tossl_Oauth2Init(Tcl_Interp *interp);
int Tossl_JwtInit(Tcl_Interp *interp);
```

## Example Usage Scenarios

### **1. Authorization Code Flow**
```tcl
# Generate authorization URL
set auth_url [tossl::oauth2::authorization_url \
    -client_id "your_client_id" \
    -redirect_uri "https://your-app.com/callback" \
    -scope "read write" \
    -state [tossl::oauth2::generate_state] \
    -authorization_url "https://auth.example.com/oauth/authorize"]

puts "Visit: $auth_url"

# Exchange code for tokens
set token_response [tossl::oauth2::exchange_code \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -code "received_code" \
    -redirect_uri "https://your-app.com/callback" \
    -token_url "https://auth.example.com/oauth/token"]

set tokens [tossl::oauth2::parse_token $token_response]
```

### **2. Client Credentials Flow**
```tcl
set token_response [tossl::oauth2::client_credentials \
    -client_id "your_client_id" \
    -client_secret "your_client_secret" \
    -token_url "https://auth.example.com/oauth/token" \
    -scope "api:read"]

set tokens [tossl::oauth2::parse_token $token_response]
```

### **3. JWT Token Handling**
```tcl
# Create JWT
set header [dict create alg RS256 typ JWT]
set payload [dict create sub user123 iss your-app.com exp [expr [clock seconds] + 3600]]
set jwt [tossl::jwt::create -header $header -payload $payload -key $private_key -alg RS256]

# Verify JWT
set valid [tossl::jwt::verify -token $jwt -key $public_key -alg RS256]
```

### **4. OAuth2-Aware HTTP Client**
```tcl
# Automatic token handling
set response [tossl::http::get_oauth2 \
    -url "https://api.example.com/data" \
    -access_token $access_token \
    -refresh_token $refresh_token \
    -client_id $client_id \
    -client_secret $client_secret \
    -token_url $token_url]
```

## Testing Strategy

### **Unit Tests (`test_oauth2.tcl`)**
- [ ] Authorization URL generation tests
- [ ] Token exchange tests
- [ ] JWT creation/verification tests
- [ ] Error handling tests
- [ ] Input validation tests

### **Integration Tests**
- [ ] End-to-end OAuth2 flow tests
- [ ] HTTP client integration tests
- [ ] Token refresh tests
- [ ] Error recovery tests

### **Mock OAuth2 Server**
- [ ] Simple OAuth2 server for testing
- [ ] Various OAuth2 flows support
- [ ] Error condition simulation

## Security Considerations

### **Token Security**
- [ ] Secure token storage with encryption
- [ ] Token expiration validation
- [ ] Secure state parameter generation
- [ ] PKCE support for public clients

### **Input Validation**
- [ ] URL validation and sanitization
- [ ] Client ID/secret validation
- [ ] Scope validation
- [ ] Redirect URI validation

### **Error Handling**
- [ ] Comprehensive error reporting
- [ ] Secure error messages (no sensitive data)
- [ ] Graceful failure handling

## Documentation Updates

### **README.md Updates**
- [ ] Add OAuth2 section to features list
- [ ] Add OAuth2 usage examples
- [ ] Add JWT usage examples
- [ ] Update API reference

### **New Documentation**
- [ ] `OAUTH2-README.md` - Comprehensive OAuth2 guide
- [ ] `JWT-README.md` - JWT usage guide
- [ ] `OAUTH2-EXAMPLES.md` - Real-world examples

## Migration and Compatibility

### **Backward Compatibility**
- [ ] All existing TOSSL commands remain unchanged
- [ ] New OAuth2 commands are additive
- [ ] No breaking changes to existing API

### **Dependency Management**
- [ ] OAuth2 support is optional (compile-time flag)
- [ ] Graceful degradation if OAuth2 not compiled
- [ ] Clear dependency requirements

## Timeline Estimate

### **Phase 1 (Core Infrastructure)**: 2-3 weeks
- Enhanced HTTP client: 1 week
- JWT support: 1 week
- Core OAuth2 commands: 1 week

### **Phase 2 (Advanced Features)**: 2-3 weeks
- PKCE support: 1 week
- Token introspection: 1 week
- Device authorization: 1 week

### **Phase 3 (Security)**: 1-2 weeks
- Token security: 1 week
- Input validation: 1 week

### **Phase 4 (Integration)**: 1-2 weeks
- HTTP client integration: 1 week
- Provider presets: 1 week

### **Testing and Documentation**: 1-2 weeks
- Unit and integration tests: 1 week
- Documentation updates: 1 week

**Total Estimated Time**: 7-12 weeks

## Success Criteria

### **Functional Requirements**
- [ ] All OAuth2 flows (authorization code, client credentials, device flow)
- [ ] JWT token support
- [ ] PKCE support for public clients
- [ ] Token introspection
- [ ] Automatic token refresh
- [ ] Comprehensive error handling

### **Performance Requirements**
- [ ] HTTP requests complete within 30 seconds
- [ ] JWT operations complete within 1 second
- [ ] Memory usage remains reasonable (< 10MB for typical usage)

### **Security Requirements**
- [ ] Secure token storage
- [ ] Input validation
- [ ] Secure random generation
- [ ] No sensitive data in error messages

### **Usability Requirements**
- [ ] Simple, intuitive API
- [ ] Comprehensive error messages
- [ ] Good documentation and examples
- [ ] Backward compatibility

## Risk Assessment

### **Technical Risks**
- **Low**: HTTP client integration (existing infrastructure)
- **Low**: JSON processing (existing infrastructure)
- **Medium**: JWT implementation (new cryptographic code)
- **Medium**: OAuth2 state management (security critical)

### **Mitigation Strategies**
- [ ] Extensive testing of JWT implementation
- [ ] Security review of state management
- [ ] Comprehensive error handling
- [ ] Gradual rollout with testing

## Conclusion

The OAuth2 implementation for TOSSL is highly feasible given the existing infrastructure. The implementation will provide a secure, performant, and user-friendly OAuth2 client library for Tcl applications, leveraging TOSSL's existing cryptographic and HTTP capabilities.

The phased approach allows for incremental development and testing, with each phase building upon the previous one. The estimated timeline of 7-12 weeks is realistic given the scope and complexity of the implementation. 