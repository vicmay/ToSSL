# HTTP Client Enhancement Plan for TOSSL

## Current State Analysis

### **Current Limitations**
- No custom headers support
- No content-type control
- Fixed 30-second timeout
- Always follows redirects
- No SSL/TLS options
- No authentication support
- No file upload support
- No session management
- No proxy support
- No cookie handling

## Enhancement Strategy

### **Phase 1: Core HTTP Enhancements (Priority: High)**

#### **1.1 Enhanced GET/POST Commands**
```tcl
# Enhanced GET with options
tossl::http::get url ?-headers {header1 value1 header2 value2}? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}?

# Enhanced POST with options
tossl::http::post url data ?-headers {header1 value1}? ?-content_type type? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}?
```

**Implementation Tasks:**
- [ ] Add option parsing to existing GET/POST commands
- [ ] Implement custom headers support
- [ ] Add timeout configuration
- [ ] Add user-agent customization
- [ ] Add redirect control
- [ ] Add SSL/TLS verification options
- [ ] Add proxy support
- [ ] Add Basic Authentication support
- [ ] Add content-type specification for POST

#### **1.2 Universal Request Command**
```tcl
# Full-featured HTTP request
tossl::http::request -method GET|POST|PUT|DELETE|PATCH -url url ?-headers {header1 value1}? ?-data data? ?-content_type type? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-cookies {cookie1 value1}?
```

**Implementation Tasks:**
- [ ] Create new universal request function
- [ ] Support all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- [ ] Implement comprehensive option parsing
- [ ] Add cookie support
- [ ] Add request/response logging for debugging

### **Phase 2: Advanced Features (Priority: Medium)**

#### **2.1 File Upload Support**
```tcl
# Single file upload
tossl::http::upload url file_path ?-field_name file? ?-additional_fields {field1 value1}? ?-headers {header1 value1}?

# Multiple file upload
tossl::http::upload_multiple url {file1_path field1_name file2_path field2_name} ?-additional_fields {field1 value1}? ?-headers {header1 value1}?
```

**Implementation Tasks:**
- [ ] Implement multipart form data creation
- [ ] Add file upload with progress callback
- [ ] Support multiple file uploads
- [ ] Add file validation and size limits

#### **2.2 Session Management**
```tcl
# Session creation and management
tossl::http::session create ?-timeout seconds? ?-user_agent string? ?-verify_ssl boolean? ?-proxy url? ?-keep_alive boolean?

# Session-based requests
tossl::http::session::get session_id url ?-headers {header1 value1}?
tossl::http::session::post session_id url data ?-headers {header1 value1}? ?-content_type type?
tossl::http::session::request session_id -method GET|POST|PUT|DELETE -url url ?-headers {header1 value1}? ?-data data?

# Session cleanup
tossl::http::session::destroy session_id
tossl::http::session::list
```

**Implementation Tasks:**
- [ ] Implement session storage and management
- [ ] Add connection pooling and keep-alive
- [ ] Add session-based cookie handling
- [ ] Add session cleanup and resource management

#### **2.3 Advanced Authentication**
```tcl
# OAuth2 Bearer token
tossl::http::get url -auth_oauth2 $access_token

# API Key authentication
tossl::http::get url -auth_apikey $api_key -apikey_header X-API-Key

# Digest Authentication
tossl::http::get url -auth_digest {username password}

# Custom authentication
tossl::http::get url -auth_custom {header_name value}
```

**Implementation Tasks:**
- [ ] Add OAuth2 Bearer token support
- [ ] Add API key authentication
- [ ] Add Digest Authentication
- [ ] Add custom authentication header support

### **Phase 3: Performance and Debugging (Priority: Low)**

#### **3.1 Performance Features**
```tcl
# Connection pooling
tossl::http::pool create -max_connections 10 -timeout 30
tossl::http::pool::get pool_id url ?-headers {header1 value1}?
tossl::http::pool::destroy pool_id

# Compression support
tossl::http::get url -accept_encoding gzip,deflate

# Request batching
tossl::http::batch {url1 url2 url3} ?-headers {header1 value1}? ?-concurrent 5?
```

**Implementation Tasks:**
- [ ] Implement connection pooling
- [ ] Add compression support (gzip, deflate)
- [ ] Add concurrent request batching
- [ ] Add request/response caching

#### **3.2 Debugging and Monitoring**
```tcl
# Enable detailed logging
tossl::http::debug enable ?-level verbose|info|warning|error?
tossl::http::debug disable

# Get request/response details
set details [tossl::http::get url -return_details true]
puts "Request time: [dict get $details request_time]"
puts "Response size: [dict get $details response_size]"
puts "SSL info: [dict get $details ssl_info]"

# Performance metrics
set metrics [tossl::http::metrics]
puts "Total requests: [dict get $metrics total_requests]"
puts "Average response time: [dict get $metrics avg_response_time]"
```

**Implementation Tasks:**
- [ ] Add detailed request/response logging
- [ ] Implement performance metrics collection
- [ ] Add SSL/TLS connection information
- [ ] Add request timing and statistics

## Technical Implementation

### **Enhanced HTTP Structure**
```c
// Enhanced HTTP response structure
struct HttpResponse {
    char *data;
    size_t size;
    long status_code;
    char *headers;
    size_t headers_size;
    double request_time;
    size_t response_size;
    char *ssl_info;
    char *error_message;
    int redirect_count;
};

// HTTP session structure
struct HttpSession {
    CURL *curl;
    char *session_id;
    struct curl_slist *headers;
    char *cookies;
    int timeout;
    char *user_agent;
    int verify_ssl;
    char *proxy;
    char *auth_username;
    char *auth_password;
};
```

### **New Command Functions**
```c
// Enhanced GET with options
int Tossl_HttpGetEnhancedCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Enhanced POST with options
int Tossl_HttpPostEnhancedCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Universal request command
int Tossl_HttpRequestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// File upload command
int Tossl_HttpUploadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Session management commands
int Tossl_HttpSessionCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Tossl_HttpSessionGetCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Tossl_HttpSessionPostCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Tossl_HttpSessionDestroyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Debug and metrics commands
int Tossl_HttpDebugCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Tossl_HttpMetricsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
```

### **Helper Functions**
```c
// Parse HTTP options
int ParseHttpOptions(Tcl_Interp *interp, int objc, Tcl_Obj *const objv[], 
                    struct HttpOptions *options);

// Configure curl with options
void ConfigureCurlWithOptions(CURL *curl, struct HttpOptions *options);

// Create HTTP response dict
Tcl_Obj* CreateHttpResponseDict(Tcl_Interp *interp, struct HttpResponse *response);

// Session management
struct HttpSession* CreateHttpSession(const char *session_id);
void DestroyHttpSession(struct HttpSession *session);
struct HttpSession* GetHttpSession(const char *session_id);
```

## Example Usage Scenarios

### **1. OAuth2 API Integration**
```tcl
# OAuth2 API call with Bearer token
set response [tossl::http::get "https://api.example.com/users" \
    -headers "Authorization: Bearer $access_token" \
    -content_type "application/json" \
    -timeout 30]

# Parse JSON response
set users [tossl::json::parse [dict get $response body]]
```

### **2. File Upload**
```tcl
# Upload file with additional fields
set result [tossl::http::upload "https://api.example.com/upload" \
    "/path/to/file.txt" \
    -field_name "file" \
    -additional_fields "description: My file" \
    -headers "Authorization: Bearer $access_token"]
```

### **3. Session-Based API Client**
```tcl
# Create session for API client
set session [tossl::http::session create \
    -timeout 30 \
    -user_agent "MyApp/1.0" \
    -keep_alive true]

# Make authenticated requests
set users [tossl::http::session::get $session "https://api.example.com/users" \
    -headers "Authorization: Bearer $access_token"]

set new_user [tossl::http::session::post $session "https://api.example.com/users" \
    $user_data \
    -headers "Authorization: Bearer $access_token" \
    -content_type "application/json"]

# Clean up session
tossl::http::session::destroy $session
```

### **4. Debugging and Monitoring**
```tcl
# Enable debug logging
tossl::http::debug enable -level verbose

# Make request with detailed response
set response [tossl::http::request \
    -method POST \
    -url "https://api.example.com/data" \
    -data $json_data \
    -headers "Content-Type: application/json" \
    -return_details true]

puts "Request time: [dict get $response request_time] ms"
puts "Response size: [dict get $response response_size] bytes"
puts "SSL info: [dict get $response ssl_info]"

# Get performance metrics
set metrics [tossl::http::metrics]
puts "Total requests: [dict get $metrics total_requests]"
puts "Average response time: [dict get $metrics avg_response_time] ms"
```

## Benefits of Enhanced HTTP Client

### **For OAuth2 Implementation**
- **Custom Headers**: Essential for `Authorization: Bearer token`
- **Content-Type Control**: Required for JSON API calls
- **Timeout Control**: Important for token refresh operations
- **SSL/TLS Options**: Security requirements for OAuth2
- **Session Management**: Connection reuse for better performance

### **For General API Integration**
- **Professional-Grade**: Suitable for production applications
- **Standards Compliant**: RFC-compliant HTTP behavior
- **Performance Optimized**: Connection pooling and keep-alive
- **Debugging Friendly**: Detailed logging and metrics
- **Flexible**: Supports any HTTP client requirement

### **For TOSSL Ecosystem**
- **Reduces Dependencies**: No need for additional HTTP libraries
- **Consistent API**: All HTTP functionality in one place
- **Native Performance**: C implementation vs Tcl-only solutions
- **Security**: Proper SSL/TLS handling with OpenSSL

## Implementation Timeline

### **Phase 1 (Core Enhancements)**: 1-2 weeks
- Enhanced GET/POST with options: 1 week
- Universal request command: 1 week

### **Phase 2 (Advanced Features)**: 2-3 weeks
- File upload support: 1 week
- Session management: 1 week
- Advanced authentication: 1 week

### **Phase 3 (Performance/Debugging)**: 1-2 weeks
- Performance features: 1 week
- Debugging and monitoring: 1 week

**Total Estimated Time**: 4-7 weeks

## Conclusion

A full-featured HTTP client makes **significant sense** for TOSSL because:

1. **OAuth2 Requirements**: Essential for proper OAuth2 implementation
2. **API Integration**: Modern APIs require sophisticated HTTP capabilities
3. **Professional Use**: Makes TOSSL suitable for production applications
4. **Performance**: Native C implementation provides better performance
5. **Reduced Dependencies**: Eliminates need for additional HTTP libraries

The enhanced HTTP client will provide a solid foundation for OAuth2 implementation and make TOSSL a comprehensive solution for modern API integration needs. 