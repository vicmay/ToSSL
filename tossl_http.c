/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <tcl.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

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

// HTTP options structure
struct HttpOptions {
    char *headers;
    int timeout;
    char *user_agent;
    int follow_redirects;
    int verify_ssl;
    char *proxy;
    char *auth_username;
    char *auth_password;
    char *content_type;
    char *cookies;
    int return_details;
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

// Global session storage
static struct HttpSession **sessions = NULL;
static int session_count = 0;
static int session_capacity = 0;

// Global metrics
static int total_requests = 0;
static double total_request_time = 0.0;
static int debug_enabled = 0;
static int debug_level = 0; // 0=none, 1=error, 2=warning, 3=info, 4=verbose

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct HttpResponse *mem = (struct HttpResponse *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if(ptr == NULL) return 0; // out of memory
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

static size_t HeaderCallback(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t realsize = size * nitems;
    struct HttpResponse *mem = (struct HttpResponse *)userdata;
    char *ptr = realloc(mem->headers, mem->headers_size + realsize + 1);
    if(ptr == NULL) return 0; // out of memory
    mem->headers = ptr;
    memcpy(&(mem->headers[mem->headers_size]), buffer, realsize);
    mem->headers_size += realsize;
    mem->headers[mem->headers_size] = 0;
    return realsize;
}

// Initialize HTTP options with defaults
static void InitHttpOptions(struct HttpOptions *options) {
    options->headers = NULL;
    options->timeout = 30;
    options->user_agent = NULL;
    options->follow_redirects = 1;
    options->verify_ssl = 1;
    options->proxy = NULL;
    options->auth_username = NULL;
    options->auth_password = NULL;
    options->content_type = NULL;
    options->cookies = NULL;
    options->return_details = 0;
}

// Parse HTTP options from Tcl arguments
static int ParseHttpOptions(Tcl_Interp *interp, int objc, Tcl_Obj *const objv[], 
                           struct HttpOptions *options, int start_arg) {
    InitHttpOptions(options);
    
    for (int i = start_arg; i < objc; i += 2) {
        if (i + 1 >= objc) {
            Tcl_SetResult(interp, "Missing value for option", TCL_STATIC);
            return TCL_ERROR;
        }
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-headers") == 0) {
            options->headers = strdup(value);
        } else if (strcmp(option, "-timeout") == 0) {
            int timeout;
            if (Tcl_GetIntFromObj(interp, objv[i + 1], &timeout) != TCL_OK) {
                return TCL_ERROR;
            }
            options->timeout = timeout;
        } else if (strcmp(option, "-user_agent") == 0) {
            options->user_agent = strdup(value);
        } else if (strcmp(option, "-follow_redirects") == 0) {
            int follow;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &follow) != TCL_OK) {
                return TCL_ERROR;
            }
            options->follow_redirects = follow;
        } else if (strcmp(option, "-verify_ssl") == 0) {
            int verify;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &verify) != TCL_OK) {
                return TCL_ERROR;
            }
            options->verify_ssl = verify;
        } else if (strcmp(option, "-proxy") == 0) {
            options->proxy = strdup(value);
        } else if (strcmp(option, "-auth") == 0) {
            // Parse auth as "username:password"
            char *auth_copy = strdup(value);
            char *colon = strchr(auth_copy, ':');
            if (colon) {
                *colon = '\0';
                options->auth_username = strdup(auth_copy);
                options->auth_password = strdup(colon + 1);
            } else {
                options->auth_username = strdup(auth_copy);
            }
            free(auth_copy);
        } else if (strcmp(option, "-content_type") == 0) {
            options->content_type = strdup(value);
        } else if (strcmp(option, "-cookies") == 0) {
            options->cookies = strdup(value);
        } else if (strcmp(option, "-return_details") == 0) {
            int details;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &details) != TCL_OK) {
                return TCL_ERROR;
            }
            options->return_details = details;
        } else {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Unknown option: %s", option);
            Tcl_SetResult(interp, error_msg, TCL_VOLATILE);
            return TCL_ERROR;
        }
    }
    
    return TCL_OK;
}

// Configure curl with options
static void ConfigureCurlWithOptions(CURL *curl, struct HttpOptions *options) {
    if (options->timeout > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)options->timeout);
    }
    
    if (options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, options->user_agent);
    }
    
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, (long)options->follow_redirects);
    
    if (!options->verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    if (options->proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, options->proxy);
    }
    
    if (options->auth_username && options->auth_password) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, options->auth_username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, options->auth_password);
    }
    
    if (options->cookies) {
        curl_easy_setopt(curl, CURLOPT_COOKIE, options->cookies);
    }
}

// Create HTTP response dict
static Tcl_Obj* CreateHttpResponseDict(Tcl_Interp *interp, struct HttpResponse *response, 
                                      struct HttpOptions *options) {
    Tcl_Obj *result = Tcl_NewDictObj();
    
    // Basic response info
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("status_code", -1),
                   Tcl_NewIntObj(response->status_code));
    
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("body", -1),
                   Tcl_NewStringObj(response->data, response->size));
    
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("headers", -1),
                   Tcl_NewStringObj(response->headers, response->headers_size));
    
    // Detailed info if requested
    if (options && options->return_details) {
        Tcl_DictObjPut(interp, result, 
                       Tcl_NewStringObj("request_time", -1),
                       Tcl_NewDoubleObj(response->request_time));
        
        Tcl_DictObjPut(interp, result, 
                       Tcl_NewStringObj("response_size", -1),
                       Tcl_NewIntObj((int)response->size));
        
        if (response->ssl_info) {
            Tcl_DictObjPut(interp, result, 
                           Tcl_NewStringObj("ssl_info", -1),
                           Tcl_NewStringObj(response->ssl_info, -1));
        }
        
        if (response->error_message) {
            Tcl_DictObjPut(interp, result, 
                           Tcl_NewStringObj("error_message", -1),
                           Tcl_NewStringObj(response->error_message, -1));
        }
        
        Tcl_DictObjPut(interp, result, 
                       Tcl_NewStringObj("redirect_count", -1),
                       Tcl_NewIntObj(response->redirect_count));
    }
    
    return result;
}

// Free HTTP options
static void FreeHttpOptions(struct HttpOptions *options) {
    if (options->headers) free(options->headers);
    if (options->user_agent) free(options->user_agent);
    if (options->proxy) free(options->proxy);
    if (options->auth_username) free(options->auth_username);
    if (options->auth_password) free(options->auth_password);
    if (options->content_type) free(options->content_type);
    if (options->cookies) free(options->cookies);
}

// Perform HTTP request with options
static int PerformHttpRequest(Tcl_Interp *interp, const char *url, const char *method,
                             const char *data, struct HttpOptions *options) {
    clock_t start_time = clock();
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to init curl", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct HttpResponse response = {malloc(1), 0, 0, malloc(1), 0, 0.0, 0, NULL, NULL, 0};
    
    // Set basic options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&response);
    
    // Configure with options
    ConfigureCurlWithOptions(curl, options);
    
    // Set method and data
    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        }
    } else if (strcmp(method, "PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        }
    }
    
    // Set custom headers if provided
    if (options && options->headers) {
        struct curl_slist *headers = NULL;
        char *headers_copy = strdup(options->headers);
        char *token = strtok(headers_copy, "\n");
        while (token) {
            headers = curl_slist_append(headers, token);
            token = strtok(NULL, "\n");
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        free(headers_copy);
    }
    
    // Set content type if provided
    if (options && options->content_type) {
        char content_type_header[256];
        snprintf(content_type_header, sizeof(content_type_header), 
                "Content-Type: %s", options->content_type);
        struct curl_slist *headers = curl_slist_append(NULL, content_type_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Calculate request time
    clock_t end_time = clock();
    response.request_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC * 1000.0;
    
    // Update metrics
    total_requests++;
    total_request_time += response.request_time;
    
    if (res != CURLE_OK) {
        response.error_message = strdup(curl_easy_strerror(res));
        if (debug_enabled && debug_level >= 1) {
            printf("HTTP Error: %s\n", response.error_message);
        }
    }
    
    // Get response info
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &response.redirect_count);
    
    // Get SSL info if available
    if (options && options->return_details) {
        char *ssl_info = NULL;
        if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_info) == CURLE_OK && ssl_info) {
            response.ssl_info = strdup(ssl_info);
        }
    }
    
    // Create result dict
    Tcl_Obj *result = CreateHttpResponseDict(interp, &response, options);
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    curl_easy_cleanup(curl);
    free(response.data);
    free(response.headers);
    if (response.ssl_info) free(response.ssl_info);
    if (response.error_message) free(response.error_message);
    
    return TCL_OK;
}



// Universal request command
int Tossl_HttpRequestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-method GET|POST|PUT|DELETE|PATCH -url url ?-data data? ?-headers {header1 value1}? ?-content_type type? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-cookies {cookie1 value1}? ?-return_details boolean?");
        return TCL_ERROR;
    }
    
    const char *method = NULL;
    const char *url = NULL;
    const char *data = NULL;
    struct HttpOptions options;
    InitHttpOptions(&options);
    
    // Parse all options
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-method") == 0) {
            method = value;
        } else if (strcmp(option, "-url") == 0) {
            url = value;
        } else if (strcmp(option, "-data") == 0) {
            data = value;
        } else if (strcmp(option, "-headers") == 0) {
            options.headers = strdup(value);
        } else if (strcmp(option, "-content_type") == 0) {
            options.content_type = strdup(value);
        } else if (strcmp(option, "-timeout") == 0) {
            int timeout;
            if (Tcl_GetIntFromObj(interp, objv[i + 1], &timeout) != TCL_OK) {
                FreeHttpOptions(&options);
                return TCL_ERROR;
            }
            options.timeout = timeout;
        } else if (strcmp(option, "-user_agent") == 0) {
            options.user_agent = strdup(value);
        } else if (strcmp(option, "-follow_redirects") == 0) {
            int follow;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &follow) != TCL_OK) {
                FreeHttpOptions(&options);
                return TCL_ERROR;
            }
            options.follow_redirects = follow;
        } else if (strcmp(option, "-verify_ssl") == 0) {
            int verify;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &verify) != TCL_OK) {
                FreeHttpOptions(&options);
                return TCL_ERROR;
            }
            options.verify_ssl = verify;
        } else if (strcmp(option, "-proxy") == 0) {
            options.proxy = strdup(value);
        } else if (strcmp(option, "-auth") == 0) {
            char *auth_copy = strdup(value);
            char *colon = strchr(auth_copy, ':');
            if (colon) {
                *colon = '\0';
                options.auth_username = strdup(auth_copy);
                options.auth_password = strdup(colon + 1);
            } else {
                options.auth_username = strdup(auth_copy);
            }
            free(auth_copy);
        } else if (strcmp(option, "-cookies") == 0) {
            options.cookies = strdup(value);
        } else if (strcmp(option, "-return_details") == 0) {
            int details;
            if (Tcl_GetBooleanFromObj(interp, objv[i + 1], &details) != TCL_OK) {
                FreeHttpOptions(&options);
                return TCL_ERROR;
            }
            options.return_details = details;
        } else {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Unknown option: %s", option);
            Tcl_SetResult(interp, error_msg, TCL_VOLATILE);
            FreeHttpOptions(&options);
            return TCL_ERROR;
        }
    }
    
    if (!method || !url) {
        Tcl_SetResult(interp, "Missing -method or -url parameter", TCL_STATIC);
        FreeHttpOptions(&options);
        return TCL_ERROR;
    }
    
    int result = PerformHttpRequest(interp, url, method, data, &options);
    FreeHttpOptions(&options);
    return result;
}

// File upload command
int Tossl_HttpUploadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "url file_path ?-field_name file? ?-additional_fields {field1 value1}? ?-headers {header1 value1}?");
        return TCL_ERROR;
    }
    
    const char *url = Tcl_GetString(objv[1]);
    const char *file_path = Tcl_GetString(objv[2]);
    const char *field_name = "file";
    const char *additional_fields = NULL;
    const char *headers = NULL;
    
    // Parse options
    for (int i = 3; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-field_name") == 0) {
            field_name = value;
        } else if (strcmp(option, "-additional_fields") == 0) {
            additional_fields = value;
        } else if (strcmp(option, "-headers") == 0) {
            headers = value;
        }
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to init curl", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct HttpResponse response = {malloc(1), 0, 0, malloc(1), 0, 0.0, 0, NULL, NULL, 0};
    
    // Set basic options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&response);
    
    // Set up multipart form data
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, field_name);
    curl_mime_filedata(part, file_path);
    
    // Add additional fields if provided
    if (additional_fields) {
        char *fields_copy = strdup(additional_fields);
        char *token = strtok(fields_copy, "\n");
        while (token) {
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                curl_mimepart *field_part = curl_mime_addpart(mime);
                curl_mime_name(field_part, token);
                curl_mime_data(field_part, colon + 1, CURL_ZERO_TERMINATED);
            }
            token = strtok(NULL, "\n");
        }
        free(fields_copy);
    }
    
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    
    // Set headers if provided
    if (headers) {
        struct curl_slist *header_list = NULL;
        char *headers_copy = strdup(headers);
        char *token = strtok(headers_copy, "\n");
        while (token) {
            header_list = curl_slist_append(header_list, token);
            token = strtok(NULL, "\n");
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
        free(headers_copy);
    }
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        response.error_message = strdup(curl_easy_strerror(res));
    }
    
    // Get response info
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
    
    // Create result dict
    struct HttpOptions options = {0};
    options.return_details = 1;
    Tcl_Obj *result = CreateHttpResponseDict(interp, &response, &options);
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    free(response.data);
    free(response.headers);
    if (response.error_message) free(response.error_message);
    
    return TCL_OK;
}

// Session management functions
int Tossl_HttpSessionCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "session_id ?-timeout seconds? ?-user_agent string? ?-verify_ssl boolean? ?-proxy url? ?-keep_alive boolean?");
        return TCL_ERROR;
    }
    
    const char *session_id = Tcl_GetString(objv[1]);
    
    // Check if session already exists
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i]->session_id, session_id) == 0) {
            Tcl_SetResult(interp, "Session already exists", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // Create new session
    if (session_count >= session_capacity) {
        session_capacity = session_capacity == 0 ? 10 : session_capacity * 2;
        sessions = realloc(sessions, session_capacity * sizeof(struct HttpSession*));
    }
    
    struct HttpSession *session = malloc(sizeof(struct HttpSession));
    session->curl = curl_easy_init();
    session->session_id = strdup(session_id);
    session->headers = NULL;
    session->cookies = NULL;
    session->timeout = 30;
    session->user_agent = NULL;
    session->verify_ssl = 1;
    session->proxy = NULL;
    session->auth_username = NULL;
    session->auth_password = NULL;
    
    // Parse options
    struct HttpOptions options;
    if (ParseHttpOptions(interp, objc, objv, &options, 2) == TCL_OK) {
        session->timeout = options.timeout;
        session->user_agent = options.user_agent ? strdup(options.user_agent) : NULL;
        session->verify_ssl = options.verify_ssl;
        session->proxy = options.proxy ? strdup(options.proxy) : NULL;
        session->auth_username = options.auth_username ? strdup(options.auth_username) : NULL;
        session->auth_password = options.auth_password ? strdup(options.auth_password) : NULL;
        FreeHttpOptions(&options);
    }
    
    // Configure session
    ConfigureCurlWithOptions(session->curl, &options);
    
    sessions[session_count++] = session;
    
    Tcl_SetResult(interp, (char *)session_id, TCL_STATIC);
    return TCL_OK;
}

int Tossl_HttpSessionGetCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "session_id url ?-headers {header1 value1}?");
        return TCL_ERROR;
    }
    
    const char *session_id = Tcl_GetString(objv[1]);
    const char *url = Tcl_GetString(objv[2]);
    
    // Find session
    struct HttpSession *session = NULL;
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i]->session_id, session_id) == 0) {
            session = sessions[i];
            break;
        }
    }
    
    if (!session) {
        Tcl_SetResult(interp, "Session not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse headers if provided
    const char *headers = NULL;
    if (objc > 3) {
        headers = Tcl_GetString(objv[3]);
    }
    
    // Use session's curl handle
    CURL *curl = session->curl;
    struct HttpResponse response = {malloc(1), 0, 0, malloc(1), 0, 0.0, 0, NULL, NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&response);
    
    // Set headers if provided
    if (headers) {
        struct curl_slist *header_list = NULL;
        char *headers_copy = strdup(headers);
        char *token = strtok(headers_copy, "\n");
        while (token) {
            header_list = curl_slist_append(header_list, token);
            token = strtok(NULL, "\n");
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
        free(headers_copy);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        response.error_message = strdup(curl_easy_strerror(res));
    }
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
    
    struct HttpOptions options = {0};
    Tcl_Obj *result = CreateHttpResponseDict(interp, &response, &options);
    Tcl_SetObjResult(interp, result);
    
    free(response.data);
    free(response.headers);
    if (response.error_message) free(response.error_message);
    
    return TCL_OK;
}

int Tossl_HttpSessionPostCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "session_id url data ?-headers {header1 value1}? ?-content_type type?");
        return TCL_ERROR;
    }
    
    const char *session_id = Tcl_GetString(objv[1]);
    const char *url = Tcl_GetString(objv[2]);
    const char *data = Tcl_GetString(objv[3]);
    
    // Find session
    struct HttpSession *session = NULL;
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i]->session_id, session_id) == 0) {
            session = sessions[i];
            break;
        }
    }
    
    if (!session) {
        Tcl_SetResult(interp, "Session not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse options
    const char *headers = NULL;
    const char *content_type = NULL;
    for (int i = 4; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-headers") == 0) {
            headers = value;
        } else if (strcmp(option, "-content_type") == 0) {
            content_type = value;
        }
    }
    
    // Use session's curl handle
    CURL *curl = session->curl;
    struct HttpResponse response = {malloc(1), 0, 0, malloc(1), 0, 0.0, 0, NULL, NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&response);
    
    // Set headers
    struct curl_slist *header_list = NULL;
    if (headers) {
        char *headers_copy = strdup(headers);
        char *token = strtok(headers_copy, "\n");
        while (token) {
            header_list = curl_slist_append(header_list, token);
            token = strtok(NULL, "\n");
        }
        free(headers_copy);
    }
    
    if (content_type) {
        char content_type_header[256];
        snprintf(content_type_header, sizeof(content_type_header), 
                "Content-Type: %s", content_type);
        header_list = curl_slist_append(header_list, content_type_header);
    }
    
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        response.error_message = strdup(curl_easy_strerror(res));
    }
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
    
    struct HttpOptions options = {0};
    Tcl_Obj *result = CreateHttpResponseDict(interp, &response, &options);
    Tcl_SetObjResult(interp, result);
    
    free(response.data);
    free(response.headers);
    if (response.error_message) free(response.error_message);
    
    return TCL_OK;
}

int Tossl_HttpSessionDestroyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "session_id");
        return TCL_ERROR;
    }
    
    const char *session_id = Tcl_GetString(objv[1]);
    
    // Find and remove session
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i]->session_id, session_id) == 0) {
            struct HttpSession *session = sessions[i];
            
            // Cleanup session
            curl_easy_cleanup(session->curl);
            free(session->session_id);
            if (session->headers) curl_slist_free_all(session->headers);
            if (session->cookies) free(session->cookies);
            if (session->user_agent) free(session->user_agent);
            if (session->proxy) free(session->proxy);
            if (session->auth_username) free(session->auth_username);
            if (session->auth_password) free(session->auth_password);
            free(session);
            
            // Remove from array
            for (int j = i; j < session_count - 1; j++) {
                sessions[j] = sessions[j + 1];
            }
            session_count--;
            
            Tcl_SetResult(interp, "Session destroyed", TCL_STATIC);
            return TCL_OK;
        }
    }
    
    Tcl_SetResult(interp, "Session not found", TCL_STATIC);
    return TCL_ERROR;
}

// Debug and metrics commands
int Tossl_HttpDebugCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "enable|disable ?-level verbose|info|warning|error?");
        return TCL_ERROR;
    }
    
    const char *action = Tcl_GetString(objv[1]);
    
    if (strcmp(action, "enable") == 0) {
        debug_enabled = 1;
        debug_level = 3; // Default to info level
        
        if (objc > 3) {
            const char *level = Tcl_GetString(objv[3]);
            if (strcmp(level, "verbose") == 0) debug_level = 4;
            else if (strcmp(level, "info") == 0) debug_level = 3;
            else if (strcmp(level, "warning") == 0) debug_level = 2;
            else if (strcmp(level, "error") == 0) debug_level = 1;
        }
        
        Tcl_SetResult(interp, "Debug logging enabled", TCL_STATIC);
    } else if (strcmp(action, "disable") == 0) {
        debug_enabled = 0;
        debug_level = 0;
        Tcl_SetResult(interp, "Debug logging disabled", TCL_STATIC);
    } else {
        Tcl_SetResult(interp, "Invalid action: use 'enable' or 'disable'", TCL_STATIC);
        return TCL_ERROR;
    }
    
    return TCL_OK;
}

int Tossl_HttpMetricsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Obj *result = Tcl_NewDictObj();
    
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("total_requests", -1),
                   Tcl_NewIntObj(total_requests));
    
    double avg_time = total_requests > 0 ? total_request_time / total_requests : 0.0;
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("avg_response_time", -1),
                   Tcl_NewDoubleObj(avg_time));
    
    Tcl_DictObjPut(interp, result, 
                   Tcl_NewStringObj("total_request_time", -1),
                   Tcl_NewDoubleObj(total_request_time));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Enhanced GET command (replaces legacy simple version)
int Tossl_HttpGetCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "url ?-headers {header1 value1}? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-return_details boolean?");
        return TCL_ERROR;
    }
    
    const char *url = Tcl_GetString(objv[1]);
    struct HttpOptions options;
    
    if (ParseHttpOptions(interp, objc, objv, &options, 2) != TCL_OK) {
        return TCL_ERROR;
    }
    
    int result = PerformHttpRequest(interp, url, "GET", NULL, &options);
    FreeHttpOptions(&options);
    return result;
}

// Enhanced POST command (replaces legacy simple version)
int Tossl_HttpPostCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "url data ?-headers {header1 value1}? ?-content_type type? ?-timeout seconds? ?-user_agent string? ?-follow_redirects boolean? ?-verify_ssl boolean? ?-proxy url? ?-auth {username password}? ?-return_details boolean?");
        return TCL_ERROR;
    }
    
    const char *url = Tcl_GetString(objv[1]);
    const char *data = Tcl_GetString(objv[2]);
    struct HttpOptions options;
    
    if (ParseHttpOptions(interp, objc, objv, &options, 3) != TCL_OK) {
        return TCL_ERROR;
    }
    
    int result = PerformHttpRequest(interp, url, "POST", data, &options);
    FreeHttpOptions(&options);
    return result;
}

int Tossl_HttpInit(Tcl_Interp *interp) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Register HTTP commands
    Tcl_CreateObjCommand(interp, "tossl::http::get", Tossl_HttpGetCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::post", Tossl_HttpPostCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::request", Tossl_HttpRequestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::upload", Tossl_HttpUploadCmd, NULL, NULL);
    
    // Register session management commands
    Tcl_CreateObjCommand(interp, "tossl::http::session::create", Tossl_HttpSessionCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::session::get", Tossl_HttpSessionGetCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::session::post", Tossl_HttpSessionPostCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::session::destroy", Tossl_HttpSessionDestroyCmd, NULL, NULL);
    
    // Register debug and metrics commands
    Tcl_CreateObjCommand(interp, "tossl::http::debug", Tossl_HttpDebugCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::metrics", Tossl_HttpMetricsCmd, NULL, NULL);
    
    return TCL_OK;
} 