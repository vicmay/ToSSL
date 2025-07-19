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
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// OIDC discovery configuration structure
typedef struct {
    char *issuer;
    char *authorization_endpoint;
    char *token_endpoint;
    char *userinfo_endpoint;
    char *jwks_uri;
    char *end_session_endpoint;
    char **supported_scopes;
    int supported_scopes_count;
    char **supported_response_types;
    int supported_response_types_count;
    char **supported_grant_types;
    int supported_grant_types_count;
    char **supported_claim_types;
    int supported_claim_types_count;
    char **supported_claims;
    int supported_claims_count;
    char **supported_token_endpoint_auth_methods;
    int supported_token_endpoint_auth_methods_count;
    char **supported_subject_types;
    int supported_subject_types_count;
    char **supported_id_token_signing_alg_values;
    int supported_id_token_signing_alg_values_count;
    char **supported_id_token_encryption_alg_values;
    int supported_id_token_encryption_alg_values_count;
    char **supported_userinfo_signing_alg_values;
    int supported_userinfo_signing_alg_values_count;
    char **supported_userinfo_encryption_alg_values;
    int supported_userinfo_encryption_alg_values_count;
    char **supported_request_object_signing_alg_values;
    int supported_request_object_signing_alg_values_count;
    char **supported_request_object_encryption_alg_values;
    int supported_request_object_encryption_alg_values_count;
    char **supported_display_values;
    int supported_display_values_count;
    char *service_documentation;
    char **claims_locales_supported;
    int claims_locales_supported_count;
    char **ui_locales_supported;
    int ui_locales_supported_count;
    int claims_parameter_supported;
    int request_parameter_supported;
    int request_uri_parameter_supported;
    int require_request_uri_registration;
    char *op_policy_uri;
    char *op_tos_uri;
    char *error;
    char *error_description;
} OidcDiscovery;

// JWKS (JSON Web Key Set) structure
typedef struct {
    char **keys;
    int keys_count;
    char *error;
    char *error_description;
} OidcJwks;

// OIDC ID token validation result
typedef struct {
    int valid;
    char *issuer;
    char *audience;
    char *subject;
    char *nonce;
    long issued_at;
    long expiration;
    long auth_time;
    char *acr;
    char *amr;
    char *error;
    char *error_description;
} OidcIdTokenValidation;

// Global discovery cache (currently disabled to avoid memory issues)
// TODO: Implement proper URL-based caching
static OidcDiscovery **discovery_cache = NULL;
static int discovery_cache_count = 0;
static int discovery_cache_capacity = 0;

// Global JWKS cache (currently disabled to avoid memory issues)
// TODO: Implement proper URL-based caching
static OidcJwks **jwks_cache = NULL;
static int jwks_cache_count = 0;
static int jwks_cache_capacity = 0;

// Free OIDC discovery configuration
static void free_oidc_discovery(OidcDiscovery *discovery) {
    if (!discovery) return;
    
    if (discovery->issuer) free(discovery->issuer);
    if (discovery->authorization_endpoint) free(discovery->authorization_endpoint);
    if (discovery->token_endpoint) free(discovery->token_endpoint);
    if (discovery->userinfo_endpoint) free(discovery->userinfo_endpoint);
    if (discovery->jwks_uri) free(discovery->jwks_uri);
    if (discovery->end_session_endpoint) free(discovery->end_session_endpoint);
    if (discovery->service_documentation) free(discovery->service_documentation);
    if (discovery->op_policy_uri) free(discovery->op_policy_uri);
    if (discovery->op_tos_uri) free(discovery->op_tos_uri);
    if (discovery->error) free(discovery->error);
    if (discovery->error_description) free(discovery->error_description);
    
    // Free string arrays
    for (int i = 0; i < discovery->supported_scopes_count; i++) {
        if (discovery->supported_scopes[i]) free(discovery->supported_scopes[i]);
    }
    if (discovery->supported_scopes) free(discovery->supported_scopes);
    
    for (int i = 0; i < discovery->supported_response_types_count; i++) {
        if (discovery->supported_response_types[i]) free(discovery->supported_response_types[i]);
    }
    if (discovery->supported_response_types) free(discovery->supported_response_types);
    
    for (int i = 0; i < discovery->supported_grant_types_count; i++) {
        if (discovery->supported_grant_types[i]) free(discovery->supported_grant_types[i]);
    }
    if (discovery->supported_grant_types) free(discovery->supported_grant_types);
    
    for (int i = 0; i < discovery->supported_claim_types_count; i++) {
        if (discovery->supported_claim_types[i]) free(discovery->supported_claim_types[i]);
    }
    if (discovery->supported_claim_types) free(discovery->supported_claim_types);
    
    for (int i = 0; i < discovery->supported_claims_count; i++) {
        if (discovery->supported_claims[i]) free(discovery->supported_claims[i]);
    }
    if (discovery->supported_claims) free(discovery->supported_claims);
    
    for (int i = 0; i < discovery->supported_token_endpoint_auth_methods_count; i++) {
        if (discovery->supported_token_endpoint_auth_methods[i]) free(discovery->supported_token_endpoint_auth_methods[i]);
    }
    if (discovery->supported_token_endpoint_auth_methods) free(discovery->supported_token_endpoint_auth_methods);
    
    for (int i = 0; i < discovery->supported_subject_types_count; i++) {
        if (discovery->supported_subject_types[i]) free(discovery->supported_subject_types[i]);
    }
    if (discovery->supported_subject_types) free(discovery->supported_subject_types);
    
    for (int i = 0; i < discovery->supported_id_token_signing_alg_values_count; i++) {
        if (discovery->supported_id_token_signing_alg_values[i]) free(discovery->supported_id_token_signing_alg_values[i]);
    }
    if (discovery->supported_id_token_signing_alg_values) free(discovery->supported_id_token_signing_alg_values);
    
    for (int i = 0; i < discovery->supported_id_token_encryption_alg_values_count; i++) {
        if (discovery->supported_id_token_encryption_alg_values[i]) free(discovery->supported_id_token_encryption_alg_values[i]);
    }
    if (discovery->supported_id_token_encryption_alg_values) free(discovery->supported_id_token_encryption_alg_values);
    
    for (int i = 0; i < discovery->supported_userinfo_signing_alg_values_count; i++) {
        if (discovery->supported_userinfo_signing_alg_values[i]) free(discovery->supported_userinfo_signing_alg_values[i]);
    }
    if (discovery->supported_userinfo_signing_alg_values) free(discovery->supported_userinfo_signing_alg_values);
    
    for (int i = 0; i < discovery->supported_userinfo_encryption_alg_values_count; i++) {
        if (discovery->supported_userinfo_encryption_alg_values[i]) free(discovery->supported_userinfo_encryption_alg_values[i]);
    }
    if (discovery->supported_userinfo_encryption_alg_values) free(discovery->supported_userinfo_encryption_alg_values);
    
    for (int i = 0; i < discovery->supported_request_object_signing_alg_values_count; i++) {
        if (discovery->supported_request_object_signing_alg_values[i]) free(discovery->supported_request_object_signing_alg_values[i]);
    }
    if (discovery->supported_request_object_signing_alg_values) free(discovery->supported_request_object_signing_alg_values);
    
    for (int i = 0; i < discovery->supported_request_object_encryption_alg_values_count; i++) {
        if (discovery->supported_request_object_encryption_alg_values[i]) free(discovery->supported_request_object_encryption_alg_values[i]);
    }
    if (discovery->supported_request_object_encryption_alg_values) free(discovery->supported_request_object_encryption_alg_values);
    
    for (int i = 0; i < discovery->supported_display_values_count; i++) {
        if (discovery->supported_display_values[i]) free(discovery->supported_display_values[i]);
    }
    if (discovery->supported_display_values) free(discovery->supported_display_values);
    
    for (int i = 0; i < discovery->claims_locales_supported_count; i++) {
        if (discovery->claims_locales_supported[i]) free(discovery->claims_locales_supported[i]);
    }
    if (discovery->claims_locales_supported) free(discovery->claims_locales_supported);
    
    for (int i = 0; i < discovery->ui_locales_supported_count; i++) {
        if (discovery->ui_locales_supported[i]) free(discovery->ui_locales_supported[i]);
    }
    if (discovery->ui_locales_supported) free(discovery->ui_locales_supported);
    
    free(discovery);
}

// Free OIDC JWKS
static void free_oidc_jwks(OidcJwks *jwks) {
    if (!jwks) return;
    
    for (int i = 0; i < jwks->keys_count; i++) {
        if (jwks->keys[i]) free(jwks->keys[i]);
    }
    if (jwks->keys) free(jwks->keys);
    
    if (jwks->error) free(jwks->error);
    if (jwks->error_description) free(jwks->error_description);
    
    free(jwks);
}

// Free OIDC ID token validation result
static void free_oidc_id_token_validation(OidcIdTokenValidation *validation) {
    if (!validation) return;
    
    if (validation->issuer) free(validation->issuer);
    if (validation->audience) free(validation->audience);
    if (validation->subject) free(validation->subject);
    if (validation->nonce) free(validation->nonce);
    if (validation->acr) free(validation->acr);
    if (validation->amr) free(validation->amr);
    if (validation->error) free(validation->error);
    if (validation->error_description) free(validation->error_description);
    
    free(validation);
}

// Parse string array from JSON array
static char **parse_string_array(json_object *json_array, int *count) {
    if (!json_array || json_object_get_type(json_array) != json_type_array) {
        *count = 0;
        return NULL;
    }
    
    int array_length = json_object_array_length(json_array);
    char **strings = malloc(array_length * sizeof(char *));
    if (!strings) {
        *count = 0;
        return NULL;
    }
    
    for (int i = 0; i < array_length; i++) {
        json_object *item = json_object_array_get_idx(json_array, i);
        if (json_object_get_type(item) == json_type_string) {
            strings[i] = strdup(json_object_get_string(item));
        } else {
            strings[i] = NULL;
        }
    }
    
    *count = array_length;
    return strings;
}

// Parse OIDC discovery response
static OidcDiscovery *parse_oidc_discovery(const char *response_data) {
    OidcDiscovery *discovery = calloc(1, sizeof(OidcDiscovery));
    if (!discovery) return NULL;
    
    json_object *json = json_tokener_parse(response_data);
    if (!json) {
        discovery->error = strdup("Invalid JSON response");
        return discovery;
    }
    
    json_object *issuer_obj, *auth_endpoint_obj, *token_endpoint_obj, *userinfo_endpoint_obj;
    json_object *jwks_uri_obj, *end_session_endpoint_obj, *scopes_obj, *response_types_obj;
    json_object *grant_types_obj, *claim_types_obj, *claims_obj, *auth_methods_obj;
    json_object *subject_types_obj, *id_token_signing_obj, *id_token_encryption_obj;
    json_object *userinfo_signing_obj, *userinfo_encryption_obj, *request_signing_obj;
    json_object *request_encryption_obj, *display_values_obj, *service_doc_obj;
    json_object *claims_locales_obj, *ui_locales_obj, *claims_param_obj, *request_param_obj;
    json_object *request_uri_param_obj, *require_uri_reg_obj, *policy_uri_obj, *tos_uri_obj;
    
    // Parse required fields
    if (json_object_object_get_ex(json, "issuer", &issuer_obj)) {
        discovery->issuer = strdup(json_object_get_string(issuer_obj));
    }
    
    if (json_object_object_get_ex(json, "authorization_endpoint", &auth_endpoint_obj)) {
        discovery->authorization_endpoint = strdup(json_object_get_string(auth_endpoint_obj));
    }
    
    if (json_object_object_get_ex(json, "token_endpoint", &token_endpoint_obj)) {
        discovery->token_endpoint = strdup(json_object_get_string(token_endpoint_obj));
    }
    
    // Parse optional fields
    if (json_object_object_get_ex(json, "userinfo_endpoint", &userinfo_endpoint_obj)) {
        discovery->userinfo_endpoint = strdup(json_object_get_string(userinfo_endpoint_obj));
    }
    
    if (json_object_object_get_ex(json, "jwks_uri", &jwks_uri_obj)) {
        discovery->jwks_uri = strdup(json_object_get_string(jwks_uri_obj));
    }
    
    if (json_object_object_get_ex(json, "end_session_endpoint", &end_session_endpoint_obj)) {
        discovery->end_session_endpoint = strdup(json_object_get_string(end_session_endpoint_obj));
    }
    
    if (json_object_object_get_ex(json, "service_documentation", &service_doc_obj)) {
        discovery->service_documentation = strdup(json_object_get_string(service_doc_obj));
    }
    
    if (json_object_object_get_ex(json, "op_policy_uri", &policy_uri_obj)) {
        discovery->op_policy_uri = strdup(json_object_get_string(policy_uri_obj));
    }
    
    if (json_object_object_get_ex(json, "op_tos_uri", &tos_uri_obj)) {
        discovery->op_tos_uri = strdup(json_object_get_string(tos_uri_obj));
    }
    
    // Parse arrays
    if (json_object_object_get_ex(json, "scopes_supported", &scopes_obj)) {
        discovery->supported_scopes = parse_string_array(scopes_obj, &discovery->supported_scopes_count);
    }
    
    if (json_object_object_get_ex(json, "response_types_supported", &response_types_obj)) {
        discovery->supported_response_types = parse_string_array(response_types_obj, &discovery->supported_response_types_count);
    }
    
    if (json_object_object_get_ex(json, "grant_types_supported", &grant_types_obj)) {
        discovery->supported_grant_types = parse_string_array(grant_types_obj, &discovery->supported_grant_types_count);
    }
    
    if (json_object_object_get_ex(json, "claim_types_supported", &claim_types_obj)) {
        discovery->supported_claim_types = parse_string_array(claim_types_obj, &discovery->supported_claim_types_count);
    }
    
    if (json_object_object_get_ex(json, "claims_supported", &claims_obj)) {
        discovery->supported_claims = parse_string_array(claims_obj, &discovery->supported_claims_count);
    }
    
    if (json_object_object_get_ex(json, "token_endpoint_auth_methods_supported", &auth_methods_obj)) {
        discovery->supported_token_endpoint_auth_methods = parse_string_array(auth_methods_obj, &discovery->supported_token_endpoint_auth_methods_count);
    }
    
    if (json_object_object_get_ex(json, "subject_types_supported", &subject_types_obj)) {
        discovery->supported_subject_types = parse_string_array(subject_types_obj, &discovery->supported_subject_types_count);
    }
    
    if (json_object_object_get_ex(json, "id_token_signing_alg_values_supported", &id_token_signing_obj)) {
        discovery->supported_id_token_signing_alg_values = parse_string_array(id_token_signing_obj, &discovery->supported_id_token_signing_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "id_token_encryption_alg_values_supported", &id_token_encryption_obj)) {
        discovery->supported_id_token_encryption_alg_values = parse_string_array(id_token_encryption_obj, &discovery->supported_id_token_encryption_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "userinfo_signing_alg_values_supported", &userinfo_signing_obj)) {
        discovery->supported_userinfo_signing_alg_values = parse_string_array(userinfo_signing_obj, &discovery->supported_userinfo_signing_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "userinfo_encryption_alg_values_supported", &userinfo_encryption_obj)) {
        discovery->supported_userinfo_encryption_alg_values = parse_string_array(userinfo_encryption_obj, &discovery->supported_userinfo_encryption_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "request_object_signing_alg_values_supported", &request_signing_obj)) {
        discovery->supported_request_object_signing_alg_values = parse_string_array(request_signing_obj, &discovery->supported_request_object_signing_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "request_object_encryption_alg_values_supported", &request_encryption_obj)) {
        discovery->supported_request_object_encryption_alg_values = parse_string_array(request_encryption_obj, &discovery->supported_request_object_encryption_alg_values_count);
    }
    
    if (json_object_object_get_ex(json, "display_values_supported", &display_values_obj)) {
        discovery->supported_display_values = parse_string_array(display_values_obj, &discovery->supported_display_values_count);
    }
    
    if (json_object_object_get_ex(json, "claims_locales_supported", &claims_locales_obj)) {
        discovery->claims_locales_supported = parse_string_array(claims_locales_obj, &discovery->claims_locales_supported_count);
    }
    
    if (json_object_object_get_ex(json, "ui_locales_supported", &ui_locales_obj)) {
        discovery->ui_locales_supported = parse_string_array(ui_locales_obj, &discovery->ui_locales_supported_count);
    }
    
    // Parse boolean fields
    if (json_object_object_get_ex(json, "claims_parameter_supported", &claims_param_obj)) {
        discovery->claims_parameter_supported = json_object_get_boolean(claims_param_obj);
    }
    
    if (json_object_object_get_ex(json, "request_parameter_supported", &request_param_obj)) {
        discovery->request_parameter_supported = json_object_get_boolean(request_param_obj);
    }
    
    if (json_object_object_get_ex(json, "request_uri_parameter_supported", &request_uri_param_obj)) {
        discovery->request_uri_parameter_supported = json_object_get_boolean(request_uri_param_obj);
    }
    
    if (json_object_object_get_ex(json, "require_request_uri_registration", &require_uri_reg_obj)) {
        discovery->require_request_uri_registration = json_object_get_boolean(require_uri_reg_obj);
    }
    
    json_object_put(json);
    return discovery;
}

// HTTP write callback for OIDC requests
static size_t oidc_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response_data = (char **)userp;
    
    char *ptr = realloc(*response_data, strlen(*response_data) + realsize + 1);
    if (!ptr) return 0;
    
    *response_data = ptr;
    memcpy(&((*response_data)[strlen(*response_data)]), contents, realsize);
    (*response_data)[strlen(*response_data) + realsize] = 0;
    
    return realsize;
}

// Perform OIDC discovery HTTP request
static char *perform_oidc_discovery_request(const char *issuer_url) {
    // Construct discovery URL
    char discovery_url[2048];
    snprintf(discovery_url, sizeof(discovery_url), "%s/.well-known/openid_configuration", issuer_url);
    
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    char *response_data = malloc(1);
    response_data[0] = '\0';
    
    curl_easy_setopt(curl, CURLOPT_URL, discovery_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ToSSL-OIDC-Client/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || http_code != 200) {
        free(response_data);
        return NULL;
    }
    
    return response_data;
}

// OIDC Discovery Command
int OidcDiscoverCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-issuer <issuer_url>");
        return TCL_ERROR;
    }
    
    const char *issuer_url = Tcl_GetString(objv[2]);
    
        // For now, skip cache to avoid memory issues
    // TODO: Implement proper URL-based caching
    
    // Perform discovery request
    char *response_data = perform_oidc_discovery_request(issuer_url);
    if (!response_data) {
        Tcl_SetResult(interp, "Failed to fetch OIDC discovery document", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse discovery response
    OidcDiscovery *discovery = parse_oidc_discovery(response_data);
    free(response_data);
    
    if (!discovery) {
        Tcl_SetResult(interp, "Failed to parse OIDC discovery document", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (discovery->error) {
        Tcl_SetResult(interp, discovery->error, TCL_STATIC);
        free_oidc_discovery(discovery);
        return TCL_ERROR;
    }
    
    // Validate required fields
    if (!discovery->issuer || !discovery->authorization_endpoint || !discovery->token_endpoint) {
        Tcl_SetResult(interp, "Invalid OIDC discovery document: missing required fields", TCL_STATIC);
        free_oidc_discovery(discovery);
        return TCL_ERROR;
    }
    
    // Create result dict before freeing discovery
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (discovery->issuer) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issuer", -1), 
                       Tcl_NewStringObj(discovery->issuer, -1));
    }
    
    if (discovery->authorization_endpoint) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("authorization_endpoint", -1), 
                       Tcl_NewStringObj(discovery->authorization_endpoint, -1));
    }
    
    if (discovery->token_endpoint) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("token_endpoint", -1), 
                       Tcl_NewStringObj(discovery->token_endpoint, -1));
    }
    
    if (discovery->userinfo_endpoint) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("userinfo_endpoint", -1), 
                       Tcl_NewStringObj(discovery->userinfo_endpoint, -1));
    }
    
    if (discovery->jwks_uri) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("jwks_uri", -1), 
                       Tcl_NewStringObj(discovery->jwks_uri, -1));
    }
    
    if (discovery->end_session_endpoint) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("end_session_endpoint", -1), 
                       Tcl_NewStringObj(discovery->end_session_endpoint, -1));
    }
    
    if (discovery->service_documentation) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("service_documentation", -1), 
                       Tcl_NewStringObj(discovery->service_documentation, -1));
    }
    
    if (discovery->op_policy_uri) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("op_policy_uri", -1), 
                       Tcl_NewStringObj(discovery->op_policy_uri, -1));
    }
    
    if (discovery->op_tos_uri) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("op_tos_uri", -1), 
                       Tcl_NewStringObj(discovery->op_tos_uri, -1));
    }
    
    // Add arrays
    if (discovery->supported_scopes_count > 0) {
        Tcl_Obj *scopes_list = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < discovery->supported_scopes_count; i++) {
            if (discovery->supported_scopes[i]) {
                Tcl_ListObjAppendElement(interp, scopes_list, 
                                       Tcl_NewStringObj(discovery->supported_scopes[i], -1));
            }
        }
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("scopes_supported", -1), scopes_list);
    }
    
    if (discovery->supported_response_types_count > 0) {
        Tcl_Obj *response_types_list = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < discovery->supported_response_types_count; i++) {
            if (discovery->supported_response_types[i]) {
                Tcl_ListObjAppendElement(interp, response_types_list, 
                                       Tcl_NewStringObj(discovery->supported_response_types[i], -1));
            }
        }
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("response_types_supported", -1), response_types_list);
    }
    
    if (discovery->supported_grant_types_count > 0) {
        Tcl_Obj *grant_types_list = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < discovery->supported_grant_types_count; i++) {
            if (discovery->supported_grant_types[i]) {
                Tcl_ListObjAppendElement(interp, grant_types_list, 
                                       Tcl_NewStringObj(discovery->supported_grant_types[i], -1));
            }
        }
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("grant_types_supported", -1), grant_types_list);
    }
    
    if (discovery->supported_claims_count > 0) {
        Tcl_Obj *claims_list = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < discovery->supported_claims_count; i++) {
            if (discovery->supported_claims[i]) {
                Tcl_ListObjAppendElement(interp, claims_list, 
                                       Tcl_NewStringObj(discovery->supported_claims[i], -1));
            }
        }
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("claims_supported", -1), claims_list);
    }
    
    if (discovery->supported_id_token_signing_alg_values_count > 0) {
        Tcl_Obj *algs_list = Tcl_NewListObj(0, NULL);
        for (int i = 0; i < discovery->supported_id_token_signing_alg_values_count; i++) {
            if (discovery->supported_id_token_signing_alg_values[i]) {
                Tcl_ListObjAppendElement(interp, algs_list, 
                                       Tcl_NewStringObj(discovery->supported_id_token_signing_alg_values[i], -1));
            }
        }
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("id_token_signing_alg_values_supported", -1), algs_list);
    }
    
    // Add boolean fields
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("claims_parameter_supported", -1), 
                   Tcl_NewBooleanObj(discovery->claims_parameter_supported));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("request_parameter_supported", -1), 
                   Tcl_NewBooleanObj(discovery->request_parameter_supported));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("request_uri_parameter_supported", -1), 
                   Tcl_NewBooleanObj(discovery->request_uri_parameter_supported));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("require_request_uri_registration", -1), 
                   Tcl_NewBooleanObj(discovery->require_request_uri_registration));
    
    // For now, skip caching to avoid memory issues
    // TODO: Implement proper URL-based caching
    free_oidc_discovery(discovery);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Generate OIDC nonce
int OidcGenerateNonceCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    
    // Generate 32 random bytes and base64url encode
    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        Tcl_SetResult(interp, "Failed to generate random bytes", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Proper base64url encoding
    const char *base64url_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char nonce[64];
    int nonce_len = 0;
    
    // Process 3 bytes at a time for proper base64 encoding
    for (int i = 0; i < 30; i += 3) {
        unsigned int triple = (random_bytes[i] << 16) | (random_bytes[i+1] << 8) | random_bytes[i+2];
        
        nonce[nonce_len++] = base64url_chars[(triple >> 18) & 0x3F];
        nonce[nonce_len++] = base64url_chars[(triple >> 12) & 0x3F];
        nonce[nonce_len++] = base64url_chars[(triple >> 6) & 0x3F];
        nonce[nonce_len++] = base64url_chars[triple & 0x3F];
    }
    
    // Handle the last 2 bytes
    unsigned int last_triple = (random_bytes[30] << 16) | (random_bytes[31] << 8);
    nonce[nonce_len++] = base64url_chars[(last_triple >> 18) & 0x3F];
    nonce[nonce_len++] = base64url_chars[(last_triple >> 12) & 0x3F];
    nonce[nonce_len++] = base64url_chars[(last_triple >> 6) & 0x3F];
    
    nonce[nonce_len] = '\0';
    
    Tcl_SetResult(interp, nonce, TCL_VOLATILE);
    return TCL_OK;
}

// Parse JWT header to extract algorithm and key ID
static int parse_jwt_header(const char *token, char **alg, char **kid) {
    char *token_copy = strdup(token);
    if (!token_copy) return 0;
    
    char *dot1 = strchr(token_copy, '.');
    if (!dot1) {
        free(token_copy);
        return 0;
    }
    *dot1 = '\0';
    
    // Base64url decode header
    size_t header_len = strlen(token_copy);
    size_t decoded_len = (header_len * 3) / 4;
    unsigned char *decoded = malloc(decoded_len + 1);
    if (!decoded) {
        free(token_copy);
        return 0;
    }
    
    // Simple base64url decode (for now)
    int j = 0;
    for (int i = 0; i < header_len; i += 4) {
        unsigned int sextet_a = token_copy[i] == '-' ? 62 : 
                               token_copy[i] == '_' ? 63 : 
                               token_copy[i] >= 'A' && token_copy[i] <= 'Z' ? token_copy[i] - 'A' :
                               token_copy[i] >= 'a' && token_copy[i] <= 'z' ? token_copy[i] - 'a' + 26 :
                               token_copy[i] >= '0' && token_copy[i] <= '9' ? token_copy[i] - '0' + 52 : 0;
        
        unsigned int sextet_b = i + 1 < header_len ? 
                               (token_copy[i+1] == '-' ? 62 : 
                                token_copy[i+1] == '_' ? 63 : 
                                token_copy[i+1] >= 'A' && token_copy[i+1] <= 'Z' ? token_copy[i+1] - 'A' :
                                token_copy[i+1] >= 'a' && token_copy[i+1] <= 'z' ? token_copy[i+1] - 'a' + 26 :
                                token_copy[i+1] >= '0' && token_copy[i+1] <= '9' ? token_copy[i+1] - '0' + 52 : 0) : 0;
        
        unsigned int sextet_c = i + 2 < header_len ? 
                               (token_copy[i+2] == '-' ? 62 : 
                                token_copy[i+2] == '_' ? 63 : 
                                token_copy[i+2] >= 'A' && token_copy[i+2] <= 'Z' ? token_copy[i+2] - 'A' :
                                token_copy[i+2] >= 'a' && token_copy[i+2] <= 'z' ? token_copy[i+2] - 'a' + 26 :
                                token_copy[i+2] >= '0' && token_copy[i+2] <= '9' ? token_copy[i+2] - '0' + 52 : 0) : 0;
        
        unsigned int sextet_d = i + 3 < header_len ? 
                               (token_copy[i+3] == '-' ? 62 : 
                                token_copy[i+3] == '_' ? 63 : 
                                token_copy[i+3] >= 'A' && token_copy[i+3] <= 'Z' ? token_copy[i+3] - 'A' :
                                token_copy[i+3] >= 'a' && token_copy[i+3] <= 'z' ? token_copy[i+3] - 'a' + 26 :
                                token_copy[i+3] >= '0' && token_copy[i+3] <= '9' ? token_copy[i+3] - '0' + 52 : 0) : 0;
        
        unsigned int triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;
        
        if (j < decoded_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len) decoded[j++] = triple & 0xFF;
    }
    decoded[j] = '\0';
    
    // Parse JSON header
    json_object *header_json = json_tokener_parse((char*)decoded);
    if (!header_json) {
        free(decoded);
        free(token_copy);
        return 0;
    }
    
    json_object *alg_obj, *kid_obj;
    if (json_object_object_get_ex(header_json, "alg", &alg_obj)) {
        *alg = strdup(json_object_get_string(alg_obj));
    } else {
        *alg = NULL;
    }
    
    if (json_object_object_get_ex(header_json, "kid", &kid_obj)) {
        *kid = strdup(json_object_get_string(kid_obj));
    } else {
        *kid = NULL;
    }
    
    json_object_put(header_json);
    free(decoded);
    free(token_copy);
    
    return 1;
}

// Parse OIDC JWKS
static OidcJwks *parse_oidc_jwks(const char *response_data) {
    OidcJwks *jwks = calloc(1, sizeof(OidcJwks));
    if (!jwks) return NULL;
    
    json_object *json = json_tokener_parse(response_data);
    if (!json) {
        jwks->error = strdup("Invalid JSON response");
        return jwks;
    }
    
    json_object *keys_obj;
    if (json_object_object_get_ex(json, "keys", &keys_obj)) {
        if (json_object_get_type(keys_obj) == json_type_array) {
            int keys_count = json_object_array_length(keys_obj);
            jwks->keys = malloc(keys_count * sizeof(char *));
            if (!jwks->keys) {
                jwks->error = strdup("Memory allocation failed");
                json_object_put(json);
                return jwks;
            }
            
            for (int i = 0; i < keys_count; i++) {
                json_object *key_obj = json_object_array_get_idx(keys_obj, i);
                if (json_object_get_type(key_obj) == json_type_object) {
                    jwks->keys[i] = strdup(json_object_to_json_string(key_obj));
                } else {
                    jwks->keys[i] = NULL;
                }
            }
            jwks->keys_count = keys_count;
        }
    } else {
        jwks->error = strdup("Missing 'keys' field in JWKS");
    }
    
    json_object_put(json);
    return jwks;
}

// Perform JWKS HTTP request
static char *perform_jwks_request(const char *jwks_url) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    char *response_data = malloc(1);
    response_data[0] = '\0';
    
    curl_easy_setopt(curl, CURLOPT_URL, jwks_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ToSSL-OIDC-Client/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || http_code != 200) {
        free(response_data);
        return NULL;
    }
    
    return response_data;
}

// JWKS Fetch Command
int OidcFetchJwksCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-jwks_uri <jwks_url>");
        return TCL_ERROR;
    }
    
    const char *jwks_url = Tcl_GetString(objv[2]);
    
    // For now, skip cache to avoid memory issues
    // TODO: Implement proper URL-based caching
    
    // Perform JWKS request
    char *response_data = perform_jwks_request(jwks_url);
    if (!response_data) {
        Tcl_SetResult(interp, "Failed to fetch JWKS", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse JWKS response
    OidcJwks *jwks = parse_oidc_jwks(response_data);
    free(response_data);
    
    if (!jwks) {
        Tcl_SetResult(interp, "Failed to parse JWKS", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (jwks->error) {
        Tcl_SetResult(interp, jwks->error, TCL_STATIC);
        free_oidc_jwks(jwks);
        return TCL_ERROR;
    }
    
    // Create result dict before freeing jwks
    Tcl_Obj *result = Tcl_NewDictObj();
    
    Tcl_Obj *keys_list = Tcl_NewListObj(0, NULL);
    for (int i = 0; i < jwks->keys_count; i++) {
        if (jwks->keys[i]) {
            Tcl_ListObjAppendElement(interp, keys_list, 
                                   Tcl_NewStringObj(jwks->keys[i], -1));
        }
    }
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("keys", -1), keys_list);
    
    // For now, skip caching to avoid memory issues
    // TODO: Implement proper URL-based caching
    free_oidc_jwks(jwks);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Get specific JWK by key ID
int OidcGetJwkCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-jwks <jwks_data> -kid <key_id>");
        return TCL_ERROR;
    }
    
    const char *jwks_data = Tcl_GetString(objv[2]);
    const char *kid = Tcl_GetString(objv[4]);
    
    // Parse JWKS data
    json_object *jwks_json = json_tokener_parse(jwks_data);
    if (!jwks_json) {
        Tcl_SetResult(interp, "Invalid JWKS data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *keys_obj;
    if (!json_object_object_get_ex(jwks_json, "keys", &keys_obj)) {
        Tcl_SetResult(interp, "Missing 'keys' field in JWKS", TCL_STATIC);
        json_object_put(jwks_json);
        return TCL_ERROR;
    }
    
    if (json_object_get_type(keys_obj) != json_type_array) {
        Tcl_SetResult(interp, "Invalid 'keys' field format", TCL_STATIC);
        json_object_put(jwks_json);
        return TCL_ERROR;
    }
    
    // Search for key with matching kid
    int keys_count = json_object_array_length(keys_obj);
    for (int i = 0; i < keys_count; i++) {
        json_object *key_obj = json_object_array_get_idx(keys_obj, i);
        if (json_object_get_type(key_obj) == json_type_object) {
            json_object *key_kid;
            if (json_object_object_get_ex(key_obj, "kid", &key_kid)) {
                if (strcmp(json_object_get_string(key_kid), kid) == 0) {
                    // Found matching key
                    Tcl_SetResult(interp, json_object_to_json_string(key_obj), TCL_VOLATILE);
                    json_object_put(jwks_json);
                    return TCL_OK;
                }
            }
        }
    }
    
    json_object_put(jwks_json);
    Tcl_SetResult(interp, "Key with specified 'kid' not found", TCL_STATIC);
    return TCL_ERROR;
}

// Validate JWKS structure
int OidcValidateJwksCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-jwks <jwks_data>");
        return TCL_ERROR;
    }
    
    const char *jwks_data = Tcl_GetString(objv[2]);
    
    // Parse JWKS data
    json_object *jwks_json = json_tokener_parse(jwks_data);
    if (!jwks_json) {
        Tcl_SetResult(interp, "Invalid JSON format", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *keys_obj;
    if (!json_object_object_get_ex(jwks_json, "keys", &keys_obj)) {
        Tcl_SetResult(interp, "Missing 'keys' field", TCL_STATIC);
        json_object_put(jwks_json);
        return TCL_ERROR;
    }
    
    if (json_object_get_type(keys_obj) != json_type_array) {
        Tcl_SetResult(interp, "Invalid 'keys' field format", TCL_STATIC);
        json_object_put(jwks_json);
        return TCL_ERROR;
    }
    
    int keys_count = json_object_array_length(keys_obj);
    if (keys_count == 0) {
        Tcl_SetResult(interp, "No keys found in JWKS", TCL_STATIC);
        json_object_put(jwks_json);
        return TCL_ERROR;
    }
    
    // Validate each key
    int valid_keys = 0;
    for (int i = 0; i < keys_count; i++) {
        json_object *key_obj = json_object_array_get_idx(keys_obj, i);
        if (json_object_get_type(key_obj) == json_type_object) {
            json_object *kty, *kid, *use, *alg;
            
            // Check for required fields
            if (json_object_object_get_ex(key_obj, "kty", &kty) &&
                json_object_object_get_ex(key_obj, "kid", &kid)) {
                valid_keys++;
            }
        }
    }
    
    json_object_put(jwks_json);
    
    if (valid_keys == 0) {
        Tcl_SetResult(interp, "No valid keys found in JWKS", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("keys_count", -1), Tcl_NewIntObj(keys_count));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid_keys", -1), Tcl_NewIntObj(valid_keys));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Validate OIDC ID token
int OidcValidateIdTokenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 7 || objc > 15) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <id_token> -issuer <issuer> -audience <audience> ?-nonce <nonce>? ?-max_age <seconds>? ?-acr_values <acr>? ?-auth_time <timestamp>?");
        return TCL_ERROR;
    }
    
    const char *token = NULL;
    const char *issuer = NULL;
    const char *audience = NULL;
    const char *nonce = NULL;
    long max_age = 0;
    const char *acr_values = NULL;
    long auth_time = 0;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-token") == 0) {
            token = value;
        } else if (strcmp(arg, "-issuer") == 0) {
            issuer = value;
        } else if (strcmp(arg, "-audience") == 0) {
            audience = value;
        } else if (strcmp(arg, "-nonce") == 0) {
            nonce = value;
        } else if (strcmp(arg, "-max_age") == 0) {
            max_age = atol(value);
        } else if (strcmp(arg, "-acr_values") == 0) {
            acr_values = value;
        } else if (strcmp(arg, "-auth_time") == 0) {
            auth_time = atol(value);
        }
    }
    
    if (!token || !issuer || !audience) {
        Tcl_SetResult(interp, "Missing required parameters: -token, -issuer, -audience", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse JWT token (header.payload.signature)
    char *token_copy = strdup(token);
    if (!token_copy) {
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char *dot1 = strchr(token_copy, '.');
    char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    
    if (!dot1 || !dot2) {
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT format", TCL_STATIC);
        return TCL_ERROR;
    }
    
    *dot1 = '\0';
    *dot2 = '\0';
    char *header = token_copy;
    char *payload = dot1 + 1;
    char *signature = dot2 + 1;
    
    // Parse payload
    size_t payload_len = strlen(payload);
    size_t decoded_len = (payload_len * 3) / 4;
    unsigned char *decoded = malloc(decoded_len + 1);
    if (!decoded) {
        free(token_copy);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Simple base64url decode
    int j = 0;
    for (int i = 0; i < payload_len; i += 4) {
        unsigned int sextet_a = payload[i] == '-' ? 62 : 
                               payload[i] == '_' ? 63 : 
                               payload[i] >= 'A' && payload[i] <= 'Z' ? payload[i] - 'A' :
                               payload[i] >= 'a' && payload[i] <= 'z' ? payload[i] - 'a' + 26 :
                               payload[i] >= '0' && payload[i] <= '9' ? payload[i] - '0' + 52 : 0;
        
        unsigned int sextet_b = i + 1 < payload_len ? 
                               (payload[i+1] == '-' ? 62 : 
                                payload[i+1] == '_' ? 63 : 
                                payload[i+1] >= 'A' && payload[i+1] <= 'Z' ? payload[i+1] - 'A' :
                                payload[i+1] >= 'a' && payload[i+1] <= 'z' ? payload[i+1] - 'a' + 26 :
                                payload[i+1] >= '0' && payload[i+1] <= '9' ? payload[i+1] - '0' + 52 : 0) : 0;
        
        unsigned int sextet_c = i + 2 < payload_len ? 
                               (payload[i+2] == '-' ? 62 : 
                                payload[i+2] == '_' ? 63 : 
                                payload[i+2] >= 'A' && payload[i+2] <= 'Z' ? payload[i+2] - 'A' :
                                payload[i+2] >= 'a' && payload[i+2] <= 'z' ? payload[i+2] - 'a' + 26 :
                                payload[i+2] >= '0' && payload[i+2] <= '9' ? payload[i+2] - '0' + 52 : 0) : 0;
        
        unsigned int sextet_d = i + 3 < payload_len ? 
                               (payload[i+3] == '-' ? 62 : 
                                payload[i+3] == '_' ? 63 : 
                                payload[i+3] >= 'A' && payload[i+3] <= 'Z' ? payload[i+3] - 'A' :
                                payload[i+3] >= 'a' && payload[i+3] <= 'z' ? payload[i+3] - 'a' + 26 :
                                payload[i+3] >= '0' && payload[i+3] <= '9' ? payload[i+3] - '0' + 52 : 0) : 0;
        
        unsigned int triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;
        
        if (j < decoded_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len) decoded[j++] = triple & 0xFF;
    }
    decoded[j] = '\0';
    
    // Parse claims
    json_object *claims_json = json_tokener_parse((char*)decoded);
    if (!claims_json) {
        free(decoded);
        free(token_copy);
        Tcl_SetResult(interp, "Invalid JWT payload", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create validation result
    OidcIdTokenValidation *validation = calloc(1, sizeof(OidcIdTokenValidation));
    if (!validation) {
        json_object_put(claims_json);
        free(decoded);
        free(token_copy);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    validation->valid = 1;
    
    // Extract claims
    json_object *iss_obj, *aud_obj, *sub_obj, *exp_obj, *iat_obj, *nbf_obj, *nonce_obj, *acr_obj, *auth_time_obj;
    
    if (json_object_object_get_ex(claims_json, "iss", &iss_obj)) {
        validation->issuer = strdup(json_object_get_string(iss_obj));
    }
    
    if (json_object_object_get_ex(claims_json, "aud", &aud_obj)) {
        validation->audience = strdup(json_object_get_string(aud_obj));
    }
    
    if (json_object_object_get_ex(claims_json, "sub", &sub_obj)) {
        validation->subject = strdup(json_object_get_string(sub_obj));
    }
    
    if (json_object_object_get_ex(claims_json, "exp", &exp_obj)) {
        validation->expiration = json_object_get_int64(exp_obj);
    }
    
    if (json_object_object_get_ex(claims_json, "iat", &iat_obj)) {
        validation->issued_at = json_object_get_int64(iat_obj);
    }
    
    if (json_object_object_get_ex(claims_json, "nbf", &nbf_obj)) {
        // Not-before time validation
        long nbf = json_object_get_int64(nbf_obj);
        time_t now = time(NULL);
        if (nbf > now) {
            validation->valid = 0;
            validation->error = strdup("Token not yet valid (nbf)");
        }
    }
    
    if (json_object_object_get_ex(claims_json, "nonce", &nonce_obj)) {
        validation->nonce = strdup(json_object_get_string(nonce_obj));
    }
    
    if (json_object_object_get_ex(claims_json, "acr", &acr_obj)) {
        validation->acr = strdup(json_object_get_string(acr_obj));
    }
    
    if (json_object_object_get_ex(claims_json, "auth_time", &auth_time_obj)) {
        validation->auth_time = json_object_get_int64(auth_time_obj);
    }
    
    // Validate issuer
    if (validation->issuer && strcmp(validation->issuer, issuer) != 0) {
        validation->valid = 0;
        validation->error = strdup("Issuer mismatch");
    }
    
    // Validate audience
    if (validation->audience && strcmp(validation->audience, audience) != 0) {
        validation->valid = 0;
        validation->error = strdup("Audience mismatch");
    }
    
    // Validate expiration
    if (validation->expiration > 0) {
        time_t now = time(NULL);
        if (validation->expiration < now) {
            validation->valid = 0;
            validation->error = strdup("Token expired");
        }
    }
    
    // Validate nonce (if provided)
    if (nonce && validation->nonce && strcmp(validation->nonce, nonce) != 0) {
        validation->valid = 0;
        validation->error = strdup("Nonce mismatch");
    }
    
    // Validate max_age (if provided)
    if (max_age > 0 && validation->auth_time > 0) {
        time_t now = time(NULL);
        if ((now - validation->auth_time) > max_age) {
            validation->valid = 0;
            validation->error = strdup("Authentication too old (max_age)");
        }
    }
    
    // Validate acr (if provided)
    if (acr_values && validation->acr && strcmp(validation->acr, acr_values) != 0) {
        validation->valid = 0;
        validation->error = strdup("ACR mismatch");
    }
    
    // Create result
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(validation->valid));
    
    if (validation->issuer) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(validation->issuer, -1));
    }
    
    if (validation->audience) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("audience", -1), Tcl_NewStringObj(validation->audience, -1));
    }
    
    if (validation->subject) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("subject", -1), Tcl_NewStringObj(validation->subject, -1));
    }
    
    if (validation->nonce) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("nonce", -1), Tcl_NewStringObj(validation->nonce, -1));
    }
    
    if (validation->issued_at > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("issued_at", -1), Tcl_NewLongObj(validation->issued_at));
    }
    
    if (validation->expiration > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("expiration", -1), Tcl_NewLongObj(validation->expiration));
    }
    
    if (validation->auth_time > 0) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("auth_time", -1), Tcl_NewLongObj(validation->auth_time));
    }
    
    if (validation->acr) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("acr", -1), Tcl_NewStringObj(validation->acr, -1));
    }
    
    if (validation->error) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), Tcl_NewStringObj(validation->error, -1));
    }
    
    // Cleanup
    free_oidc_id_token_validation(validation);
    json_object_put(claims_json);
    free(decoded);
    free(token_copy);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Initialize OIDC module
int Tossl_OidcInit(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::oidc::discover", OidcDiscoverCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::generate_nonce", OidcGenerateNonceCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::fetch_jwks", OidcFetchJwksCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::get_jwk", OidcGetJwkCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::validate_jwks", OidcValidateJwksCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::validate_id_token", OidcValidateIdTokenCmd, NULL, NULL);
    
    return TCL_OK;
} 