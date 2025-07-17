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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json.h>
#include <curl/curl.h>

// OAuth2 token structure
typedef struct {
    char *access_token;
    char *token_type;
    char *refresh_token;
    long expires_in;
    time_t expires_at;
    char *scope;
    char *error;
    char *error_description;
} OAuth2Token;

// OAuth2 configuration structure
typedef struct {
    char *client_id;
    char *client_secret;
    char *redirect_uri;
    char *authorization_url;
    char *token_url;
    char *scope;
    char *state;
} OAuth2Config;

// Token introspection response structure
typedef struct {
    int active;
    char *scope;
    char *client_id;
    char *username;
    long exp;
    long iat;
    char *token_type;
    char *error;
} OAuth2Introspection;

// Device authorization response structure
typedef struct {
    char *device_code;
    char *user_code;
    char *verification_uri;
    char *verification_uri_complete;
    int expires_in;
    int interval;
    char *error;
} OAuth2DeviceAuth;

// Free OAuth2 token
static void free_oauth2_token(OAuth2Token *token) {
    if (token->access_token) free(token->access_token);
    if (token->token_type) free(token->token_type);
    if (token->refresh_token) free(token->refresh_token);
    if (token->scope) free(token->scope);
    if (token->error) free(token->error);
    if (token->error_description) free(token->error_description);
    free(token);
}

// Free introspection response
static void free_oauth2_introspection(OAuth2Introspection *introspection) {
    if (introspection->scope) free(introspection->scope);
    if (introspection->client_id) free(introspection->client_id);
    if (introspection->username) free(introspection->username);
    if (introspection->token_type) free(introspection->token_type);
    if (introspection->error) free(introspection->error);
    free(introspection);
}

// Free device authorization response
static void free_oauth2_device_auth(OAuth2DeviceAuth *device_auth) {
    if (device_auth->device_code) free(device_auth->device_code);
    if (device_auth->user_code) free(device_auth->user_code);
    if (device_auth->verification_uri) free(device_auth->verification_uri);
    if (device_auth->verification_uri_complete) free(device_auth->verification_uri_complete);
    if (device_auth->error) free(device_auth->error);
    free(device_auth);
}

// Generate secure random state parameter
static char *generate_state() {
    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return NULL;
    }
    
    char *state = malloc(65); // 32 bytes = 64 hex chars + null terminator
    for (int i = 0; i < 32; i++) {
        sprintf(state + (i * 2), "%02x", random_bytes[i]);
    }
    state[64] = '\0';
    return state;
}

// URL encode string
static char *url_encode(const char *str) {
    if (!str) return NULL;
    
    char *encoded = malloc(strlen(str) * 3 + 1);
    char *p = encoded;
    
    while (*str) {
        if ((*str >= 'A' && *str <= 'Z') ||
            (*str >= 'a' && *str <= 'z') ||
            (*str >= '0' && *str <= '9') ||
            *str == '-' || *str == '_' || *str == '.' || *str == '~') {
            *p++ = *str;
        } else {
            sprintf(p, "%%%02X", (unsigned char)*str);
            p += 3;
        }
        str++;
    }
    *p = '\0';
    return encoded;
}

// CURL write callback function
static size_t oauth2_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **data = (char **)userp;
    char *ptr = realloc(*data, (*data ? strlen(*data) : 0) + realsize + 1);
    if (!ptr) return 0;
    *data = ptr;
    memcpy(*data + (*data ? strlen(*data) : 0), contents, realsize);
    (*data)[(*data ? strlen(*data) : 0) + realsize] = 0;
    return realsize;
}

// Parse OAuth2 token response
static OAuth2Token *parse_token_response(const char *response_str) {
    OAuth2Token *token = calloc(1, sizeof(OAuth2Token));
    if (!token) return NULL;
    
    json_object *json = json_tokener_parse(response_str);
    if (!json) {
        token->error = strdup("Invalid JSON response");
        return token;
    }
    
    json_object *access_token_obj, *token_type_obj, *refresh_token_obj;
    json_object *expires_in_obj, *scope_obj, *error_obj, *error_desc_obj;
    
    if (json_object_object_get_ex(json, "access_token", &access_token_obj)) {
        token->access_token = strdup(json_object_get_string(access_token_obj));
    }
    
    if (json_object_object_get_ex(json, "token_type", &token_type_obj)) {
        token->token_type = strdup(json_object_get_string(token_type_obj));
    }
    
    if (json_object_object_get_ex(json, "refresh_token", &refresh_token_obj)) {
        token->refresh_token = strdup(json_object_get_string(refresh_token_obj));
    }
    
    if (json_object_object_get_ex(json, "expires_in", &expires_in_obj)) {
        token->expires_in = json_object_get_int(expires_in_obj);
        token->expires_at = time(NULL) + token->expires_in;
    }
    
    if (json_object_object_get_ex(json, "scope", &scope_obj)) {
        token->scope = strdup(json_object_get_string(scope_obj));
    }
    
    if (json_object_object_get_ex(json, "error", &error_obj)) {
        token->error = strdup(json_object_get_string(error_obj));
    }
    
    if (json_object_object_get_ex(json, "error_description", &error_desc_obj)) {
        token->error_description = strdup(json_object_get_string(error_desc_obj));
    }
    
    json_object_put(json);
    return token;
}

// Parse token introspection response
static OAuth2Introspection *parse_introspection_response(const char *response_str) {
    OAuth2Introspection *introspection = calloc(1, sizeof(OAuth2Introspection));
    if (!introspection) return NULL;
    
    json_object *json = json_tokener_parse(response_str);
    if (!json) {
        introspection->error = strdup("Invalid JSON response");
        return introspection;
    }
    
    json_object *active_obj, *scope_obj, *client_id_obj, *username_obj;
    json_object *exp_obj, *iat_obj, *token_type_obj, *error_obj;
    
    if (json_object_object_get_ex(json, "active", &active_obj)) {
        introspection->active = json_object_get_boolean(active_obj);
    }
    
    if (json_object_object_get_ex(json, "scope", &scope_obj)) {
        introspection->scope = strdup(json_object_get_string(scope_obj));
    }
    
    if (json_object_object_get_ex(json, "client_id", &client_id_obj)) {
        introspection->client_id = strdup(json_object_get_string(client_id_obj));
    }
    
    if (json_object_object_get_ex(json, "username", &username_obj)) {
        introspection->username = strdup(json_object_get_string(username_obj));
    }
    
    if (json_object_object_get_ex(json, "exp", &exp_obj)) {
        introspection->exp = json_object_get_int(exp_obj);
    }
    
    if (json_object_object_get_ex(json, "iat", &iat_obj)) {
        introspection->iat = json_object_get_int(iat_obj);
    }
    
    if (json_object_object_get_ex(json, "token_type", &token_type_obj)) {
        introspection->token_type = strdup(json_object_get_string(token_type_obj));
    }
    
    if (json_object_object_get_ex(json, "error", &error_obj)) {
        introspection->error = strdup(json_object_get_string(error_obj));
    }
    
    json_object_put(json);
    return introspection;
}

// Parse device authorization response
static OAuth2DeviceAuth *parse_device_auth_response(const char *response_str) {
    OAuth2DeviceAuth *device_auth = calloc(1, sizeof(OAuth2DeviceAuth));
    if (!device_auth) return NULL;
    
    json_object *json = json_tokener_parse(response_str);
    if (!json) {
        device_auth->error = strdup("Invalid JSON response");
        return device_auth;
    }
    
    json_object *device_code_obj, *user_code_obj, *verification_uri_obj;
    json_object *verification_uri_complete_obj, *expires_in_obj, *interval_obj, *error_obj;
    
    if (json_object_object_get_ex(json, "device_code", &device_code_obj)) {
        device_auth->device_code = strdup(json_object_get_string(device_code_obj));
    }
    
    if (json_object_object_get_ex(json, "user_code", &user_code_obj)) {
        device_auth->user_code = strdup(json_object_get_string(user_code_obj));
    }
    
    if (json_object_object_get_ex(json, "verification_uri", &verification_uri_obj)) {
        device_auth->verification_uri = strdup(json_object_get_string(verification_uri_obj));
    }
    
    if (json_object_object_get_ex(json, "verification_uri_complete", &verification_uri_complete_obj)) {
        device_auth->verification_uri_complete = strdup(json_object_get_string(verification_uri_complete_obj));
    }
    
    if (json_object_object_get_ex(json, "expires_in", &expires_in_obj)) {
        device_auth->expires_in = json_object_get_int(expires_in_obj);
    }
    
    if (json_object_object_get_ex(json, "interval", &interval_obj)) {
        device_auth->interval = json_object_get_int(interval_obj);
    }
    
    if (json_object_object_get_ex(json, "error", &error_obj)) {
        device_auth->error = strdup(json_object_get_string(error_obj));
    }
    
    json_object_put(json);
    return device_auth;
}

// Create authorization URL
int Oauth2AuthUrlCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url>");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *redirect_uri = NULL;
    const char *scope = NULL;
    const char *state = NULL;
    const char *authorization_url = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-redirect_uri") == 0) {
            redirect_uri = value;
        } else if (strcmp(option, "-scope") == 0) {
            scope = value;
        } else if (strcmp(option, "-state") == 0) {
            state = value;
        } else if (strcmp(option, "-authorization_url") == 0) {
            authorization_url = value;
        }
    }
    
    if (!client_id || !redirect_uri || !authorization_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // URL encode parameters
    char *client_id_encoded = url_encode(client_id);
    char *redirect_uri_encoded = url_encode(redirect_uri);
    char *scope_encoded = scope ? url_encode(scope) : NULL;
    char *state_encoded = state ? url_encode(state) : NULL;
    
    if (!client_id_encoded || !redirect_uri_encoded) {
        if (client_id_encoded) free(client_id_encoded);
        if (redirect_uri_encoded) free(redirect_uri_encoded);
        if (scope_encoded) free(scope_encoded);
        if (state_encoded) free(state_encoded);
        Tcl_SetResult(interp, "Failed to encode parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Build authorization URL
    char *auth_url = malloc(strlen(authorization_url) + strlen(client_id_encoded) + 
                           strlen(redirect_uri_encoded) + (scope_encoded ? strlen(scope_encoded) : 0) +
                           (state_encoded ? strlen(state_encoded) : 0) + 100);
    
    sprintf(auth_url, "%s?response_type=code&client_id=%s&redirect_uri=%s", 
            authorization_url, client_id_encoded, redirect_uri_encoded);
    
    if (scope_encoded) {
        char *temp = malloc(strlen(auth_url) + strlen(scope_encoded) + 10);
        sprintf(temp, "%s&scope=%s", auth_url, scope_encoded);
        free(auth_url);
        auth_url = temp;
    }
    
    if (state_encoded) {
        char *temp = malloc(strlen(auth_url) + strlen(state_encoded) + 10);
        sprintf(temp, "%s&state=%s", auth_url, state_encoded);
        free(auth_url);
        auth_url = temp;
    }
    
    Tcl_SetResult(interp, auth_url, TCL_VOLATILE);
    
    // Cleanup
    free(client_id_encoded);
    free(redirect_uri_encoded);
    if (scope_encoded) free(scope_encoded);
    if (state_encoded) free(state_encoded);
    
    return TCL_OK;
}

// Exchange authorization code for tokens
int Oauth2ExchangeCodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> -code <code> -redirect_uri <uri> -token_url <url>");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *code = NULL;
    const char *redirect_uri = NULL;
    const char *token_url = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(option, "-code") == 0) {
            code = value;
        } else if (strcmp(option, "-redirect_uri") == 0) {
            redirect_uri = value;
        } else if (strcmp(option, "-token_url") == 0) {
            token_url = value;
        }
    }
    
    if (!client_id || !client_secret || !code || !redirect_uri || !token_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // URL encode parameters
    char *client_id_encoded = url_encode(client_id);
    char *client_secret_encoded = url_encode(client_secret);
    char *code_encoded = url_encode(code);
    char *redirect_uri_encoded = url_encode(redirect_uri);
    
    if (!client_id_encoded || !client_secret_encoded || !code_encoded || !redirect_uri_encoded) {
        if (client_id_encoded) free(client_id_encoded);
        if (client_secret_encoded) free(client_secret_encoded);
        if (code_encoded) free(code_encoded);
        if (redirect_uri_encoded) free(redirect_uri_encoded);
        Tcl_SetResult(interp, "Failed to encode parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Build POST data
    char *post_data = malloc(strlen(client_id_encoded) + strlen(client_secret_encoded) + 
                            strlen(code_encoded) + strlen(redirect_uri_encoded) + 100);
    sprintf(post_data, "grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s",
            client_id_encoded, client_secret_encoded, code_encoded, redirect_uri_encoded);
    
    // Make HTTP request
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(client_id_encoded);
        free(client_secret_encoded);
        free(code_encoded);
        free(redirect_uri_encoded);
        free(post_data);
        Tcl_SetResult(interp, "Failed to initialize curl", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    char *response_data = NULL;
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(client_id_encoded);
        free(client_secret_encoded);
        free(code_encoded);
        free(redirect_uri_encoded);
        free(post_data);
        if (response_data) free(response_data);
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    // Parse response
    OAuth2Token *token = parse_token_response(response_data);
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
        if (token->error_description) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                           Tcl_NewStringObj(token->error_description, -1));
        }
    } else {
        if (token->access_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                           Tcl_NewStringObj(token->access_token, -1));
        }
        if (token->token_type) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                           Tcl_NewStringObj(token->token_type, -1));
        }
        if (token->refresh_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), 
                           Tcl_NewStringObj(token->refresh_token, -1));
        }
        if (token->scope) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                           Tcl_NewStringObj(token->scope, -1));
        }
        if (token->expires_in > 0) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                           Tcl_NewIntObj(token->expires_in));
        }
    }
    
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("http_code", -1), 
                   Tcl_NewIntObj(http_code));
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_oauth2_token(token);
    free(client_id_encoded);
    free(client_secret_encoded);
    free(code_encoded);
    free(redirect_uri_encoded);
    free(post_data);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Refresh access token
int Oauth2RefreshTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> -refresh_token <token> -token_url <url>");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *refresh_token = NULL;
    const char *token_url = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(option, "-refresh_token") == 0) {
            refresh_token = value;
        } else if (strcmp(option, "-token_url") == 0) {
            token_url = value;
        }
    }
    
    if (!client_id || !client_secret || !refresh_token || !token_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // URL encode parameters
    char *client_id_encoded = url_encode(client_id);
    char *client_secret_encoded = url_encode(client_secret);
    char *refresh_token_encoded = url_encode(refresh_token);
    
    if (!client_id_encoded || !client_secret_encoded || !refresh_token_encoded) {
        if (client_id_encoded) free(client_id_encoded);
        if (client_secret_encoded) free(client_secret_encoded);
        if (refresh_token_encoded) free(refresh_token_encoded);
        Tcl_SetResult(interp, "Failed to encode parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Build POST data
    char *post_data = malloc(strlen(client_id_encoded) + strlen(client_secret_encoded) + 
                            strlen(refresh_token_encoded) + 100);
    sprintf(post_data, "grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
            client_id_encoded, client_secret_encoded, refresh_token_encoded);
    
    // Make HTTP request
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(client_id_encoded);
        free(client_secret_encoded);
        free(refresh_token_encoded);
        free(post_data);
        Tcl_SetResult(interp, "Failed to initialize curl", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    char *response_data = NULL;
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(client_id_encoded);
        free(client_secret_encoded);
        free(refresh_token_encoded);
        free(post_data);
        if (response_data) free(response_data);
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    // Parse response
    OAuth2Token *token = parse_token_response(response_data);
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
        if (token->error_description) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                           Tcl_NewStringObj(token->error_description, -1));
        }
    } else {
        if (token->access_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                           Tcl_NewStringObj(token->access_token, -1));
        }
        if (token->token_type) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                           Tcl_NewStringObj(token->token_type, -1));
        }
        if (token->refresh_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), 
                           Tcl_NewStringObj(token->refresh_token, -1));
        }
        if (token->scope) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                           Tcl_NewStringObj(token->scope, -1));
        }
        if (token->expires_in > 0) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                           Tcl_NewIntObj(token->expires_in));
        }
    }
    
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("http_code", -1), 
                   Tcl_NewIntObj(http_code));
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_oauth2_token(token);
    free(client_id_encoded);
    free(client_secret_encoded);
    free(refresh_token_encoded);
    free(post_data);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Client credentials flow
int Oauth2ClientCredentialsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> -token_url <url> ?-scope <scope>?");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *token_url = NULL;
    const char *scope = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(option, "-token_url") == 0) {
            token_url = value;
        } else if (strcmp(option, "-scope") == 0) {
            scope = value;
        }
    }
    
    if (!client_id || !client_secret || !token_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // URL encode parameters
    char *client_id_encoded = url_encode(client_id);
    char *client_secret_encoded = url_encode(client_secret);
    char *scope_encoded = scope ? url_encode(scope) : NULL;
    
    if (!client_id_encoded || !client_secret_encoded) {
        if (client_id_encoded) free(client_id_encoded);
        if (client_secret_encoded) free(client_secret_encoded);
        if (scope_encoded) free(scope_encoded);
        Tcl_SetResult(interp, "Failed to encode parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Build POST data
    char *post_data = malloc(strlen(client_id_encoded) + strlen(client_secret_encoded) + 
                            (scope_encoded ? strlen(scope_encoded) : 0) + 100);
    sprintf(post_data, "grant_type=client_credentials&client_id=%s&client_secret=%s",
            client_id_encoded, client_secret_encoded);
    
    if (scope_encoded) {
        char *temp = malloc(strlen(post_data) + strlen(scope_encoded) + 10);
        sprintf(temp, "%s&scope=%s", post_data, scope_encoded);
        free(post_data);
        post_data = temp;
    }
    
    // Make HTTP request
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(client_id_encoded);
        free(client_secret_encoded);
        if (scope_encoded) free(scope_encoded);
        free(post_data);
        Tcl_SetResult(interp, "Failed to initialize curl", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    char *response_data = NULL;
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(client_id_encoded);
        free(client_secret_encoded);
        if (scope_encoded) free(scope_encoded);
        free(post_data);
        if (response_data) free(response_data);
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    // Parse response
    OAuth2Token *token = parse_token_response(response_data);
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
        if (token->error_description) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                           Tcl_NewStringObj(token->error_description, -1));
        }
    } else {
        if (token->access_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                           Tcl_NewStringObj(token->access_token, -1));
        }
        if (token->token_type) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                           Tcl_NewStringObj(token->token_type, -1));
        }
        if (token->scope) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                           Tcl_NewStringObj(token->scope, -1));
        }
        if (token->expires_in > 0) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                           Tcl_NewIntObj(token->expires_in));
        }
    }
    
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("http_code", -1), 
                   Tcl_NewIntObj(http_code));
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_oauth2_token(token);
    free(client_id_encoded);
    free(client_secret_encoded);
    if (scope_encoded) free(scope_encoded);
    free(post_data);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Parse token response
int Oauth2ParseTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "<token_response>");
        return TCL_ERROR;
    }
    
    const char *response_str = Tcl_GetString(objv[1]);
    
    OAuth2Token *token = parse_token_response(response_str);
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
        if (token->error_description) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                           Tcl_NewStringObj(token->error_description, -1));
        }
    } else {
        if (token->access_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                           Tcl_NewStringObj(token->access_token, -1));
        }
        if (token->token_type) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                           Tcl_NewStringObj(token->token_type, -1));
        }
        if (token->refresh_token) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), 
                           Tcl_NewStringObj(token->refresh_token, -1));
        }
        if (token->scope) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                           Tcl_NewStringObj(token->scope, -1));
        }
        if (token->expires_in > 0) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                           Tcl_NewIntObj(token->expires_in));
        }
    }
    
    Tcl_SetObjResult(interp, result);
    
    // Cleanup
    free_oauth2_token(token);
    
    return TCL_OK;
}

// Generate state parameter
int Oauth2GenerateStateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    char *state = generate_state();
    if (!state) {
        Tcl_SetResult(interp, "Failed to generate state parameter", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, state, TCL_VOLATILE);
    return TCL_OK;
}

// Validate state parameter
int Oauth2ValidateStateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "<state> <expected_state>");
        return TCL_ERROR;
    }
    
    const char *state = Tcl_GetString(objv[1]);
    const char *expected_state = Tcl_GetString(objv[2]);
    
    int is_valid = (strcmp(state, expected_state) == 0);
    
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(is_valid));
    return TCL_OK;
}

// --- PKCE Support ---
#include <openssl/sha.h>

// Generate a high-entropy code verifier (RFC 7636)
static char *generate_code_verifier(int length) {
    if (length < 43) length = 43;
    if (length > 128) length = 128;
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    char *verifier = malloc(length + 1);
    if (!verifier) return NULL;
    for (int i = 0; i < length; i++) {
        unsigned char rnd;
        RAND_bytes(&rnd, 1);
        verifier[i] = charset[rnd % (sizeof(charset) - 1)];
    }
    verifier[length] = '\0';
    return verifier;
}

// Create code challenge (S256)
static char *create_code_challenge(const char *verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)verifier, strlen(verifier), hash);
    // Base64url encode
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *challenge = malloc(45); // 43 chars + null
    int j = 0, i = 0;
    for (; i + 3 <= SHA256_DIGEST_LENGTH; i += 3) {
        unsigned int val = (hash[i] << 16) | (hash[i+1] << 8) | hash[i+2];
        challenge[j++] = b64[(val >> 18) & 0x3F];
        challenge[j++] = b64[(val >> 12) & 0x3F];
        challenge[j++] = b64[(val >> 6) & 0x3F];
        challenge[j++] = b64[val & 0x3F];
    }
    if (i < SHA256_DIGEST_LENGTH) {
        unsigned int val = hash[i] << 16;
        if (i + 1 < SHA256_DIGEST_LENGTH) val |= hash[i+1] << 8;
        challenge[j++] = b64[(val >> 18) & 0x3F];
        challenge[j++] = b64[(val >> 12) & 0x3F];
        if (i + 1 < SHA256_DIGEST_LENGTH) challenge[j++] = b64[(val >> 6) & 0x3F];
    }
    challenge[j] = '\0';
    return challenge;
}

// Tcl: tossl::oauth2::generate_code_verifier ?-length N?
int Oauth2GenerateCodeVerifierCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int length = 64;
    if (objc == 3 && strcmp(Tcl_GetString(objv[1]), "-length") == 0) {
        Tcl_GetIntFromObj(interp, objv[2], &length);
    } else if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-length N?");
        return TCL_ERROR;
    }
    if (length < 43 || length > 128) {
        Tcl_SetResult(interp, "Failed to generate code verifier: length must be 43-128", TCL_STATIC);
        return TCL_ERROR;
    }
    char *verifier = generate_code_verifier(length);
    if (!verifier) {
        Tcl_SetResult(interp, "Failed to generate code verifier", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, verifier, TCL_VOLATILE);
    return TCL_OK;
}

// Tcl: tossl::oauth2::create_code_challenge -verifier <code_verifier>
int Oauth2CreateCodeChallengeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3 || strcmp(Tcl_GetString(objv[1]), "-verifier") != 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "-verifier <code_verifier>");
        return TCL_ERROR;
    }
    const char *verifier = Tcl_GetString(objv[2]);
    char *challenge = create_code_challenge(verifier);
    if (!challenge) {
        Tcl_SetResult(interp, "Failed to create code challenge", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, challenge, TCL_VOLATILE);
    return TCL_OK;
}

// Tcl: tossl::oauth2::authorization_url_pkce ...
int Oauth2AuthUrlPkceCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Same as Oauth2AuthUrlCmd, but requires -code_challenge and -code_challenge_method
    if (objc < 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -redirect_uri <uri> -scope <scope> -state <state> -authorization_url <url> -code_challenge <challenge> -code_challenge_method S256");
        return TCL_ERROR;
    }
    const char *client_id = NULL, *redirect_uri = NULL, *scope = NULL, *state = NULL, *authorization_url = NULL, *code_challenge = NULL, *code_challenge_method = NULL;
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        if (strcmp(option, "-client_id") == 0) client_id = value;
        else if (strcmp(option, "-redirect_uri") == 0) redirect_uri = value;
        else if (strcmp(option, "-scope") == 0) scope = value;
        else if (strcmp(option, "-state") == 0) state = value;
        else if (strcmp(option, "-authorization_url") == 0) authorization_url = value;
        else if (strcmp(option, "-code_challenge") == 0) code_challenge = value;
        else if (strcmp(option, "-code_challenge_method") == 0) code_challenge_method = value;
    }
    if (!client_id || !redirect_uri || !authorization_url || !code_challenge || !code_challenge_method) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    char *client_id_encoded = url_encode(client_id);
    char *redirect_uri_encoded = url_encode(redirect_uri);
    char *scope_encoded = scope ? url_encode(scope) : NULL;
    char *state_encoded = state ? url_encode(state) : NULL;
    char *code_challenge_encoded = url_encode(code_challenge);
    char *auth_url = malloc(strlen(authorization_url) + strlen(client_id_encoded) + strlen(redirect_uri_encoded) + (scope_encoded ? strlen(scope_encoded) : 0) + (state_encoded ? strlen(state_encoded) : 0) + strlen(code_challenge_encoded) + strlen(code_challenge_method) + 200);
    sprintf(auth_url, "%s?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=%s", authorization_url, client_id_encoded, redirect_uri_encoded, code_challenge_encoded, code_challenge_method);
    if (scope_encoded) {
        char *temp = malloc(strlen(auth_url) + strlen(scope_encoded) + 10);
        sprintf(temp, "%s&scope=%s", auth_url, scope_encoded);
        free(auth_url);
        auth_url = temp;
    }
    if (state_encoded) {
        char *temp = malloc(strlen(auth_url) + strlen(state_encoded) + 10);
        sprintf(temp, "%s&state=%s", auth_url, state_encoded);
        free(auth_url);
        auth_url = temp;
    }
    Tcl_SetResult(interp, auth_url, TCL_VOLATILE);
    free(client_id_encoded);
    free(redirect_uri_encoded);
    if (scope_encoded) free(scope_encoded);
    if (state_encoded) free(state_encoded);
    free(code_challenge_encoded);
    return TCL_OK;
}

// Tcl: tossl::oauth2::exchange_code_pkce ...
int Oauth2ExchangeCodePkceCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 13) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -code_verifier <verifier> -code <code> -redirect_uri <uri> -token_url <url>");
        return TCL_ERROR;
    }
    const char *client_id = NULL, *code_verifier = NULL, *code = NULL, *redirect_uri = NULL, *token_url = NULL;
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        if (strcmp(option, "-client_id") == 0) client_id = value;
        else if (strcmp(option, "-code_verifier") == 0) code_verifier = value;
        else if (strcmp(option, "-code") == 0) code = value;
        else if (strcmp(option, "-redirect_uri") == 0) redirect_uri = value;
        else if (strcmp(option, "-token_url") == 0) token_url = value;
    }
    if (!client_id || !code_verifier || !code || !redirect_uri || !token_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    char *client_id_encoded = url_encode(client_id);
    char *code_verifier_encoded = url_encode(code_verifier);
    char *code_encoded = url_encode(code);
    char *redirect_uri_encoded = url_encode(redirect_uri);
    char *post_data = malloc(strlen(client_id_encoded) + strlen(code_verifier_encoded) + strlen(code_encoded) + strlen(redirect_uri_encoded) + 100);
    sprintf(post_data, "grant_type=authorization_code&client_id=%s&code_verifier=%s&code=%s&redirect_uri=%s", client_id_encoded, code_verifier_encoded, code_encoded, redirect_uri_encoded);
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(client_id_encoded); free(code_verifier_encoded); free(code_encoded); free(redirect_uri_encoded); free(post_data);
        Tcl_SetResult(interp, "Failed to initialize curl", TCL_STATIC);
        return TCL_ERROR;
    }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    char *response_data = NULL;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl); curl_slist_free_all(headers);
        free(client_id_encoded); free(code_verifier_encoded); free(code_encoded); free(redirect_uri_encoded); free(post_data);
        if (response_data) free(response_data);
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        return TCL_ERROR;
    }
    long http_code; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl); curl_slist_free_all(headers);
    OAuth2Token *token = parse_token_response(response_data);
    Tcl_Obj *result = Tcl_NewDictObj();
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), Tcl_NewStringObj(token->error, -1));
        if (token->error_description) {
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), Tcl_NewStringObj(token->error_description, -1));
        }
    } else {
        if (token->access_token) Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), Tcl_NewStringObj(token->access_token, -1));
        if (token->token_type) Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), Tcl_NewStringObj(token->token_type, -1));
        if (token->refresh_token) Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), Tcl_NewStringObj(token->refresh_token, -1));
        if (token->scope) Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), Tcl_NewStringObj(token->scope, -1));
        if (token->expires_in > 0) Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), Tcl_NewIntObj(token->expires_in));
    }
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("http_code", -1), Tcl_NewIntObj(http_code));
    Tcl_SetObjResult(interp, result);
    free_oauth2_token(token);
    free(client_id_encoded); free(code_verifier_encoded); free(code_encoded); free(redirect_uri_encoded); free(post_data); if (response_data) free(response_data);
    return TCL_OK;
}

// Token introspection command
int Oauth2IntrospectTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <access_token> -introspection_url <url> -client_id <id> -client_secret <secret>");
        return TCL_ERROR;
    }
    
    const char *token = NULL;
    const char *introspection_url = NULL;
    const char *client_id = NULL;
    const char *client_secret = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-token") == 0) {
            token = value;
        } else if (strcmp(option, "-introspection_url") == 0) {
            introspection_url = value;
        } else if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        }
    }
    
    if (!token || !introspection_url || !client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to initialize CURL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *response_data = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    
    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    // Create form data
    char post_data[2048];
    snprintf(post_data, sizeof(post_data), 
             "token=%s&client_id=%s&client_secret=%s",
             token, client_id, client_secret);
    
    curl_easy_setopt(curl, CURLOPT_URL, introspection_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_STATIC);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (http_code != 200) {
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    OAuth2Introspection *introspection = parse_introspection_response(response_data);
    if (!introspection) {
        Tcl_SetResult(interp, "Failed to parse introspection response", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_Obj *active_obj = Tcl_NewIntObj(introspection->active);
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("active", -1), active_obj);
    
    if (introspection->scope) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                       Tcl_NewStringObj(introspection->scope, -1));
    }
    
    if (introspection->client_id) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("client_id", -1), 
                       Tcl_NewStringObj(introspection->client_id, -1));
    }
    
    if (introspection->username) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("username", -1), 
                       Tcl_NewStringObj(introspection->username, -1));
    }
    
    if (introspection->exp > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("exp", -1), 
                       Tcl_NewIntObj(introspection->exp));
    }
    
    if (introspection->iat > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("iat", -1), 
                       Tcl_NewIntObj(introspection->iat));
    }
    
    if (introspection->token_type) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                       Tcl_NewStringObj(introspection->token_type, -1));
    }
    
    if (introspection->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(introspection->error, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    free_oauth2_introspection(introspection);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Validate introspection result command
int Oauth2ValidateIntrospectionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-introspection_result <result> -required_scopes {scope1 scope2}");
        return TCL_ERROR;
    }
    
    const char *introspection_result_str = NULL;
    const char *required_scopes_str = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-introspection_result") == 0) {
            introspection_result_str = value;
        } else if (strcmp(option, "-required_scopes") == 0) {
            required_scopes_str = value;
        }
    }
    
    if (!introspection_result_str) {
        Tcl_SetResult(interp, "Missing introspection_result parameter", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse introspection result
    json_object *introspection_json = json_tokener_parse(introspection_result_str);
    if (!introspection_json) {
        Tcl_SetResult(interp, "Invalid introspection result JSON", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *active_obj, *scope_obj;
    int active = 0;
    const char *scope = NULL;
    
    if (json_object_object_get_ex(introspection_json, "active", &active_obj)) {
        active = json_object_get_boolean(active_obj);
    }
    
    if (json_object_object_get_ex(introspection_json, "scope", &scope_obj)) {
        scope = json_object_get_string(scope_obj);
    }
    
    // Check if token is active
    if (!active) {
        Tcl_SetResult(interp, "Token is not active", TCL_STATIC);
        json_object_put(introspection_json);
        return TCL_ERROR;
    }
    
    // Check required scopes if specified
    if (required_scopes_str && scope) {
        // Simple scope validation - check if all required scopes are present
        // This is a basic implementation; more sophisticated scope checking could be added
        Tcl_Obj *required_scopes_list = Tcl_NewStringObj(required_scopes_str, -1);
        int list_length;
        Tcl_ListObjLength(interp, required_scopes_list, &list_length);
        
        for (int i = 0; i < list_length; i++) {
            Tcl_Obj *required_scope;
            Tcl_ListObjIndex(interp, required_scopes_list, i, &required_scope);
            const char *req_scope = Tcl_GetString(required_scope);
            
            if (!strstr(scope, req_scope)) {
                Tcl_SetResult(interp, "Required scope not found", TCL_STATIC);
                json_object_put(introspection_json);
                return TCL_ERROR;
            }
        }
    }
    
    json_object_put(introspection_json);
    Tcl_SetResult(interp, "Token validation successful", TCL_STATIC);
    return TCL_OK;
}

// Device authorization command
int Oauth2DeviceAuthorizationCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -device_authorization_url <url> -scope <scope>");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *device_authorization_url = NULL;
    const char *scope = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-device_authorization_url") == 0) {
            device_authorization_url = value;
        } else if (strcmp(option, "-scope") == 0) {
            scope = value;
        }
    }
    
    if (!client_id || !device_authorization_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to initialize CURL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *response_data = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    
    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    // Create form data
    char post_data[1024];
    if (scope) {
        snprintf(post_data, sizeof(post_data), "client_id=%s&scope=%s", client_id, scope);
    } else {
        snprintf(post_data, sizeof(post_data), "client_id=%s", client_id);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, device_authorization_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_STATIC);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (http_code != 200) {
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    OAuth2DeviceAuth *device_auth = parse_device_auth_response(response_data);
    if (!device_auth) {
        Tcl_SetResult(interp, "Failed to parse device authorization response", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (device_auth->device_code) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("device_code", -1), 
                       Tcl_NewStringObj(device_auth->device_code, -1));
    }
    
    if (device_auth->user_code) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("user_code", -1), 
                       Tcl_NewStringObj(device_auth->user_code, -1));
    }
    
    if (device_auth->verification_uri) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("verification_uri", -1), 
                       Tcl_NewStringObj(device_auth->verification_uri, -1));
    }
    
    if (device_auth->verification_uri_complete) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("verification_uri_complete", -1), 
                       Tcl_NewStringObj(device_auth->verification_uri_complete, -1));
    }
    
    if (device_auth->expires_in > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                       Tcl_NewIntObj(device_auth->expires_in));
    }
    
    if (device_auth->interval > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("interval", -1), 
                       Tcl_NewIntObj(device_auth->interval));
    }
    
    if (device_auth->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(device_auth->error, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    free_oauth2_device_auth(device_auth);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Poll device token command
int Oauth2PollDeviceTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-device_code <code> -token_url <url> -client_id <id> -client_secret <secret>");
        return TCL_ERROR;
    }
    
    const char *device_code = NULL;
    const char *token_url = NULL;
    const char *client_id = NULL;
    const char *client_secret = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-device_code") == 0) {
            device_code = value;
        } else if (strcmp(option, "-token_url") == 0) {
            token_url = value;
        } else if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        }
    }
    
    if (!device_code || !token_url || !client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to initialize CURL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *response_data = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    
    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    // Create form data
    char post_data[1024];
    snprintf(post_data, sizeof(post_data), 
             "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s&client_secret=%s",
             device_code, client_id, client_secret);
    
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_STATIC);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (http_code != 200) {
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    OAuth2Token *token = parse_token_response(response_data);
    if (!token) {
        Tcl_SetResult(interp, "Failed to parse token response", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->access_token) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                       Tcl_NewStringObj(token->access_token, -1));
    }
    
    if (token->token_type) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                       Tcl_NewStringObj(token->token_type, -1));
    }
    
    if (token->refresh_token) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), 
                       Tcl_NewStringObj(token->refresh_token, -1));
    }
    
    if (token->expires_in > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                       Tcl_NewIntObj(token->expires_in));
    }
    
    if (token->scope) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                       Tcl_NewStringObj(token->scope, -1));
    }
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
    }
    
    if (token->error_description) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                       Tcl_NewStringObj(token->error_description, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    free_oauth2_token(token);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Check if token is expired
int Oauth2IsTokenExpiredCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <token_data>");
        return TCL_ERROR;
    }
    
    const char *token_data_str = Tcl_GetString(objv[2]);
    
    // Parse token data
    json_object *token_json = json_tokener_parse(token_data_str);
    if (!token_json) {
        Tcl_SetResult(interp, "Invalid token data JSON", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *expires_in_obj, *expires_at_obj;
    long expires_in = 0;
    long expires_at = 0;
    
    if (json_object_object_get_ex(token_json, "expires_in", &expires_in_obj)) {
        expires_in = json_object_get_int(expires_in_obj);
    }
    
    if (json_object_object_get_ex(token_json, "expires_at", &expires_at_obj)) {
        expires_at = json_object_get_int(expires_at_obj);
    }
    
    json_object_put(token_json);
    
    time_t now = time(NULL);
    int expired = 0;
    
    if (expires_at > 0) {
        expired = (now >= expires_at);
    } else if (expires_in > 0) {
        // If we don't have expires_at, we can't determine if expired
        // This is a limitation - we'd need to track when the token was issued
        expired = 0; // Assume not expired if we can't determine
    }
    
    Tcl_SetObjResult(interp, Tcl_NewIntObj(expired));
    return TCL_OK;
}

// Secure token storage with encryption
int Oauth2StoreTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token_data <dict> -encryption_key <key>");
        return TCL_ERROR;
    }
    
    const char *token_data_str = Tcl_GetString(objv[2]);
    const char *encryption_key = Tcl_GetString(objv[4]);
    
    if (!token_data_str || !encryption_key) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // For now, we'll implement a simple base64 encoding as a placeholder
    // In a real implementation, this would use proper encryption (AES, etc.)
    
    // Create a simple "encrypted" version by base64 encoding
    size_t data_len = strlen(token_data_str);
    char *encoded = malloc(data_len * 2 + 1);
    if (!encoded) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Simple XOR with key (not secure, just for demonstration)
    size_t key_len = strlen(encryption_key);
    if (key_len == 0) {
        free(encoded);
        Tcl_SetResult(interp, "Empty encryption key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        encoded[i] = token_data_str[i] ^ encryption_key[i % key_len];
    }
    encoded[data_len] = '\0';
    
    // Convert to base64-like format for storage
    char *result = malloc(data_len * 2 + 1);
    for (size_t i = 0; i < data_len; i++) {
        sprintf(result + (i * 2), "%02x", (unsigned char)encoded[i]);
    }
    result[data_len * 2] = '\0';
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    free(encoded);
    free(result);
    
    return TCL_OK;
}

// Load encrypted token
int Oauth2LoadTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-encrypted_data <data> -encryption_key <key>");
        return TCL_ERROR;
    }
    
    const char *encrypted_data = Tcl_GetString(objv[2]);
    const char *encryption_key = Tcl_GetString(objv[4]);
    
    if (!encrypted_data || !encryption_key) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Decode the "encrypted" data
    size_t data_len = strlen(encrypted_data) / 2;
    char *decoded = malloc(data_len + 1);
    if (!decoded) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert from hex back to bytes
    for (size_t i = 0; i < data_len; i++) {
        char hex[3] = {encrypted_data[i * 2], encrypted_data[i * 2 + 1], '\0'};
        decoded[i] = (char)strtol(hex, NULL, 16);
    }
    decoded[data_len] = '\0';
    
    // XOR decode
    size_t key_len = strlen(encryption_key);
    if (key_len == 0) {
        free(decoded);
        Tcl_SetResult(interp, "Empty encryption key", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *result = malloc(data_len + 1);
    for (size_t i = 0; i < data_len; i++) {
        result[i] = decoded[i] ^ encryption_key[i % key_len];
    }
    result[data_len] = '\0';
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    free(decoded);
    free(result);
    
    return TCL_OK;
}

// Automatic token refresh
int Oauth2AutoRefreshCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 11) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token_data <dict> -client_id <id> -client_secret <secret> -token_url <url>");
        return TCL_ERROR;
    }
    
    const char *token_data_str = NULL;
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *token_url = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-token_data") == 0) {
            token_data_str = value;
        } else if (strcmp(option, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(option, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(option, "-token_url") == 0) {
            token_url = value;
        }
    }
    
    if (!token_data_str || !client_id || !client_secret || !token_url) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse token data to get refresh token
    json_object *token_json = json_tokener_parse(token_data_str);
    if (!token_json) {
        Tcl_SetResult(interp, "Invalid token data JSON", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *refresh_token_obj;
    const char *refresh_token = NULL;
    
    if (json_object_object_get_ex(token_json, "refresh_token", &refresh_token_obj)) {
        refresh_token = json_object_get_string(refresh_token_obj);
    }
    
    json_object_put(token_json);
    
    if (!refresh_token) {
        Tcl_SetResult(interp, "No refresh token available", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Perform token refresh
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to initialize CURL", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *response_data = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    
    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    // Create form data
    char post_data[2048];
    snprintf(post_data, sizeof(post_data), 
             "grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s",
             refresh_token, client_id, client_secret);
    
    curl_easy_setopt(curl, CURLOPT_URL, token_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_STATIC);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (http_code != 200) {
        Tcl_SetResult(interp, "HTTP request failed", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    OAuth2Token *token = parse_token_response(response_data);
    if (!token) {
        Tcl_SetResult(interp, "Failed to parse token response", TCL_STATIC);
        if (response_data) free(response_data);
        return TCL_ERROR;
    }
    
    // Create result dictionary
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (token->access_token) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("access_token", -1), 
                       Tcl_NewStringObj(token->access_token, -1));
    }
    
    if (token->token_type) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_type", -1), 
                       Tcl_NewStringObj(token->token_type, -1));
    }
    
    if (token->refresh_token) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("refresh_token", -1), 
                       Tcl_NewStringObj(token->refresh_token, -1));
    }
    
    if (token->expires_in > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expires_in", -1), 
                       Tcl_NewIntObj(token->expires_in));
    }
    
    if (token->scope) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scope", -1), 
                       Tcl_NewStringObj(token->scope, -1));
    }
    
    if (token->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj(token->error, -1));
    }
    
    if (token->error_description) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                       Tcl_NewStringObj(token->error_description, -1));
    }
    
    Tcl_SetObjResult(interp, result);
    free_oauth2_token(token);
    if (response_data) free(response_data);
    
    return TCL_OK;
}

// Initialize OAuth2 module
int Tossl_Oauth2Init(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::oauth2::authorization_url", Oauth2AuthUrlCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::exchange_code", Oauth2ExchangeCodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::refresh_token", Oauth2RefreshTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::client_credentials", Oauth2ClientCredentialsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::parse_token", Oauth2ParseTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::generate_state", Oauth2GenerateStateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::validate_state", Oauth2ValidateStateCmd, NULL, NULL);
    // PKCE
    Tcl_CreateObjCommand(interp, "tossl::oauth2::generate_code_verifier", Oauth2GenerateCodeVerifierCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::create_code_challenge", Oauth2CreateCodeChallengeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::authorization_url_pkce", Oauth2AuthUrlPkceCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::exchange_code_pkce", Oauth2ExchangeCodePkceCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::introspect_token", Oauth2IntrospectTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::validate_introspection", Oauth2ValidateIntrospectionCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::device_authorization", Oauth2DeviceAuthorizationCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::poll_device_token", Oauth2PollDeviceTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::is_token_expired", Oauth2IsTokenExpiredCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::store_token", Oauth2StoreTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::load_token", Oauth2LoadTokenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oauth2::auto_refresh", Oauth2AutoRefreshCmd, NULL, NULL);
    return TCL_OK;
} 