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
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Forward declarations for helper functions
static EVP_PKEY *create_rsa_key_from_jwk(const char *n, const char *e);
static EVP_PKEY *create_ec_key_from_jwk(const char *x, const char *y, const char *crv);
static int verify_jwt_signature(const char *token, EVP_PKEY *pkey, const char *alg);
static unsigned char *base64url_decode(const char *input, size_t input_len, size_t *output_len);

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
    
    // Handle NULL or uninitialized response_data
    if (!response_data) return 0;
    
    // Get current length safely
    size_t current_len = (*response_data) ? strlen(*response_data) : 0;
    
    char *ptr = realloc(*response_data, current_len + realsize + 1);
    if (!ptr) return 0;
    
    *response_data = ptr;
    memcpy(&((*response_data)[current_len]), contents, realsize);
    (*response_data)[current_len + realsize] = 0;
    
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
    
    // Convert base64url to base64 manually
    char *base64_input = malloc(strlen(token_copy) + 4);
    if (!base64_input) {
        free(token_copy);
        return 0;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < strlen(token_copy); i++) {
        if (token_copy[i] == '-') {
            base64_input[j++] = '+';
        } else if (token_copy[i] == '_') {
            base64_input[j++] = '/';
        } else {
            base64_input[j++] = token_copy[i];
        }
    }
    
    // Add padding if needed
    while (j % 4 != 0) {
        base64_input[j++] = '=';
    }
    base64_input[j] = '\0';
    
    // Use OpenSSL BIO to decode
    BIO *bio = BIO_new_mem_buf(base64_input, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    unsigned char *decoded = malloc(strlen(token_copy));
    if (!decoded) {
        BIO_free_all(bio);
        free(base64_input);
        free(token_copy);
        return 0;
    }
    
    int decoded_len = BIO_read(bio, decoded, strlen(token_copy));
    BIO_free_all(bio);
    free(base64_input);
    
    if (decoded_len < 0) {
        free(decoded);
        free(token_copy);
        return 0;
    }
    
    // Ensure null termination
    decoded[decoded_len] = '\0';
    
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

// Verify JWT signature using JWKS
int OidcVerifyJwtWithJwksCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-token <jwt_token> -jwks <jwks_data>");
        return TCL_ERROR;
    }
    
    const char *token = Tcl_GetString(objv[2]);
    const char *jwks_data = Tcl_GetString(objv[4]);
    
    // Parse JWT header to get algorithm and key ID
    char *alg = NULL;
    char *kid = NULL;
    
    if (parse_jwt_header(token, &alg, &kid) == 0) {
        Tcl_SetResult(interp, "Failed to parse JWT header", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (!alg || !kid) {
        Tcl_SetResult(interp, "Missing 'alg' or 'kid' in JWT header", TCL_STATIC);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    // Parse JWKS to find the key
    json_object *jwks_json = json_tokener_parse(jwks_data);
    if (!jwks_json) {
        Tcl_SetResult(interp, "Invalid JWKS data", TCL_STATIC);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    json_object *keys_obj;
    if (!json_object_object_get_ex(jwks_json, "keys", &keys_obj)) {
        Tcl_SetResult(interp, "Missing 'keys' field in JWKS", TCL_STATIC);
        json_object_put(jwks_json);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    if (json_object_get_type(keys_obj) != json_type_array) {
        Tcl_SetResult(interp, "Invalid 'keys' field format", TCL_STATIC);
        json_object_put(jwks_json);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    // Find the key with matching kid
    json_object *matching_key = NULL;
    int keys_count = json_object_array_length(keys_obj);
    
    for (int i = 0; i < keys_count; i++) {
        json_object *key_obj = json_object_array_get_idx(keys_obj, i);
        if (json_object_get_type(key_obj) == json_type_object) {
            json_object *key_kid;
            if (json_object_object_get_ex(key_obj, "kid", &key_kid)) {
                if (strcmp(json_object_get_string(key_kid), kid) == 0) {
                    matching_key = key_obj;
                    break;
                }
            }
        }
    }
    
    if (!matching_key) {
        Tcl_SetResult(interp, "Key with specified 'kid' not found in JWKS", TCL_STATIC);
        json_object_put(jwks_json);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    // Extract key type and parameters
    json_object *kty_obj, *n_obj, *e_obj, *x_obj, *y_obj, *crv_obj;
    const char *kty = NULL;
    
    if (json_object_object_get_ex(matching_key, "kty", &kty_obj)) {
        kty = json_object_get_string(kty_obj);
    }
    
    if (!kty) {
        Tcl_SetResult(interp, "Missing 'kty' field in JWK", TCL_STATIC);
        json_object_put(jwks_json);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    // Verify JWT signature based on key type and algorithm
    int verification_result = 0;
    
    if (strcmp(kty, "RSA") == 0) {
        // RSA key verification
        if (json_object_object_get_ex(matching_key, "n", &n_obj) &&
            json_object_object_get_ex(matching_key, "e", &e_obj)) {
            
            const char *n = json_object_get_string(n_obj);
            const char *e = json_object_get_string(e_obj);
            
            // Create RSA public key from JWK parameters
            EVP_PKEY *pkey = create_rsa_key_from_jwk(n, e);
            if (pkey) {
                verification_result = verify_jwt_signature(token, pkey, alg);
                EVP_PKEY_free(pkey);
            }
        }
    } else if (strcmp(kty, "EC") == 0) {
        // EC key verification
        if (json_object_object_get_ex(matching_key, "x", &x_obj) &&
            json_object_object_get_ex(matching_key, "y", &y_obj) &&
            json_object_object_get_ex(matching_key, "crv", &crv_obj)) {
            
            const char *x = json_object_get_string(x_obj);
            const char *y = json_object_get_string(y_obj);
            const char *crv = json_object_get_string(crv_obj);
            
            // Create EC public key from JWK parameters
            EVP_PKEY *pkey = create_ec_key_from_jwk(x, y, crv);
            if (pkey) {
                verification_result = verify_jwt_signature(token, pkey, alg);
                EVP_PKEY_free(pkey);
            }
        }
    } else {
        Tcl_SetResult(interp, "Unsupported key type in JWK", TCL_STATIC);
        json_object_put(jwks_json);
        free(alg);
        free(kid);
        return TCL_ERROR;
    }
    
    // Create result
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(verification_result));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("algorithm", -1), Tcl_NewStringObj(alg, -1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("key_id", -1), Tcl_NewStringObj(kid, -1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("key_type", -1), Tcl_NewStringObj(kty, -1));
    
    if (!verification_result) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), 
                       Tcl_NewStringObj("JWT signature verification failed", -1));
    }
    
    json_object_put(jwks_json);
    free(alg);
    free(kid);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Helper function to create RSA key from JWK parameters using modern OpenSSL 3.x API
static EVP_PKEY *create_rsa_key_from_jwk(const char *n, const char *e) {
    if (!n || !e) return NULL;
    
    // Decode base64url parameters
    size_t n_len, e_len;
    unsigned char *n_bytes = base64url_decode(n, strlen(n), &n_len);
    unsigned char *e_bytes = base64url_decode(e, strlen(e), &e_len);
    
    if (!n_bytes || !e_bytes) {
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    // Create BIGNUMs from the decoded bytes
    BIGNUM *n_bn = BN_bin2bn(n_bytes, n_len, NULL);
    BIGNUM *e_bn = BN_bin2bn(e_bytes, e_len, NULL);
    
    if (!n_bn || !e_bn) {
        BN_free(n_bn);
        BN_free(e_bn);
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    // Create EVP_PKEY using modern API
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        BN_free(n_bn);
        BN_free(e_bn);
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    // Use OSSL_PARAM to set RSA parameters
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN("n", n_bn, 0),
        OSSL_PARAM_BN("e", e_bn, 0),
        OSSL_PARAM_END
    };
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BN_free(n_bn);
        BN_free(e_bn);
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    if (EVP_PKEY_fromdata_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BN_free(n_bn);
        BN_free(e_bn);
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BN_free(n_bn);
        BN_free(e_bn);
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    BN_free(n_bn);
    BN_free(e_bn);
    free(n_bytes);
    free(e_bytes);
    
    return pkey;
}

// Helper function to create EC key from JWK parameters using modern OpenSSL 3.x API
static EVP_PKEY *create_ec_key_from_jwk(const char *x, const char *y, const char *crv) {
    if (!x || !y || !crv) return NULL;
    
    // Decode base64url parameters
    size_t x_len, y_len;
    unsigned char *x_bytes = base64url_decode(x, strlen(x), &x_len);
    unsigned char *y_bytes = base64url_decode(y, strlen(y), &y_len);
    
    if (!x_bytes || !y_bytes) {
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    // Get curve name
    const char *curve_name = NULL;
    if (strcmp(crv, "P-256") == 0) {
        curve_name = "P-256";
    } else if (strcmp(crv, "P-384") == 0) {
        curve_name = "P-384";
    } else if (strcmp(crv, "P-521") == 0) {
        curve_name = "P-521";
    } else {
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    // Create BIGNUMs from the decoded bytes
    BIGNUM *x_bn = BN_bin2bn(x_bytes, x_len, NULL);
    BIGNUM *y_bn = BN_bin2bn(y_bytes, y_len, NULL);
    
    if (!x_bn || !y_bn) {
        BN_free(x_bn);
        BN_free(y_bn);
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    // Create EVP_PKEY using modern API
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        BN_free(x_bn);
        BN_free(y_bn);
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    // Use OSSL_PARAM to set EC parameters
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("group", curve_name, 0),
        OSSL_PARAM_BN("pub-x", x_bn, 0),
        OSSL_PARAM_BN("pub-y", y_bn, 0),
        OSSL_PARAM_END
    };
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BN_free(x_bn);
        BN_free(y_bn);
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    if (EVP_PKEY_fromdata_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BN_free(x_bn);
        BN_free(y_bn);
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BN_free(x_bn);
        BN_free(y_bn);
        free(x_bytes);
        free(y_bytes);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    BN_free(x_bn);
    BN_free(y_bn);
    free(x_bytes);
    free(y_bytes);
    
    return pkey;
}

// Helper function to verify JWT signature
static int verify_jwt_signature(const char *token, EVP_PKEY *pkey, const char *alg) {
    if (!token || !pkey || !alg) return 0;
    
    // Split JWT into parts
    char *token_copy = strdup(token);
    if (!token_copy) return 0;
    
    char *dot1 = strchr(token_copy, '.');
    if (!dot1) {
        free(token_copy);
        return 0;
    }
    *dot1 = '\0';
    
    char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        free(token_copy);
        return 0;
    }
    *dot2 = '\0';
    
    char *header = token_copy;
    char *payload = dot1 + 1;
    char *signature = dot2 + 1;
    
    // Create data to verify (header.payload)
    char *data_to_verify = malloc(strlen(header) + 1 + strlen(payload) + 1);
    if (!data_to_verify) {
        free(token_copy);
        return 0;
    }
    
    sprintf(data_to_verify, "%s.%s", header, payload);
    
    // Decode signature
    size_t sig_len;
    unsigned char *sig_bytes = base64url_decode(signature, strlen(signature), &sig_len);
    if (!sig_bytes) {
        free(data_to_verify);
        free(token_copy);
        return 0;
    }
    
    // Verify signature based on algorithm
    int result = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        const EVP_MD *md = NULL;
        
        if (strcmp(alg, "RS256") == 0) {
            md = EVP_sha256();
        } else if (strcmp(alg, "RS384") == 0) {
            md = EVP_sha384();
        } else if (strcmp(alg, "RS512") == 0) {
            md = EVP_sha512();
        } else if (strcmp(alg, "ES256") == 0) {
            md = EVP_sha256();
        } else if (strcmp(alg, "ES384") == 0) {
            md = EVP_sha384();
        } else if (strcmp(alg, "ES512") == 0) {
            md = EVP_sha512();
        }
        
        if (md && EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1) {
            result = EVP_DigestVerify(ctx, sig_bytes, sig_len, 
                                     (unsigned char*)data_to_verify, strlen(data_to_verify));
            result = (result == 1);
        }
        
        EVP_MD_CTX_free(ctx);
    }
    
    free(sig_bytes);
    free(data_to_verify);
    free(token_copy);
    
    return result;
}

// Helper function for base64url decoding
static unsigned char *base64url_decode(const char *input, size_t input_len, size_t *output_len) {
    if (!input || !output_len) return NULL;
    
    // Convert base64url to base64
    char *base64_input = malloc(input_len + 4);
    if (!base64_input) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '-') {
            base64_input[j++] = '+';
        } else if (input[i] == '_') {
            base64_input[j++] = '/';
        } else {
            base64_input[j++] = input[i];
        }
    }
    
    // Add padding if needed
    while (j % 4 != 0) {
        base64_input[j++] = '=';
    }
    base64_input[j] = '\0';
    
    // Decode base64
    BIO *bio = BIO_new_mem_buf(base64_input, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    unsigned char *output = malloc(input_len);
    if (!output) {
        BIO_free_all(bio);
        free(base64_input);
        return NULL;
    }
    
    int decoded_len = BIO_read(bio, output, input_len);
    BIO_free_all(bio);
    free(base64_input);
    
    if (decoded_len < 0) {
        free(output);
        return NULL;
    }
    
    *output_len = decoded_len;
    return output;
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

// UserInfo response structure
typedef struct {
    char *sub;
    char *name;
    char *given_name;
    char *family_name;
    char *middle_name;
    char *nickname;
    char *preferred_username;
    char *profile;
    char *picture;
    char *website;
    char *email;
    char *email_verified;
    char *gender;
    char *birthdate;
    char *zoneinfo;
    char *locale;
    char *phone_number;
    char *phone_number_verified;
    char *address;
    char *updated_at;
    char *error;
    char *error_description;
} OidcUserinfo;

// Free UserInfo response
static void free_oidc_userinfo(OidcUserinfo *userinfo) {
    if (!userinfo) return;
    
    if (userinfo->sub) free(userinfo->sub);
    if (userinfo->name) free(userinfo->name);
    if (userinfo->given_name) free(userinfo->given_name);
    if (userinfo->family_name) free(userinfo->family_name);
    if (userinfo->middle_name) free(userinfo->middle_name);
    if (userinfo->nickname) free(userinfo->nickname);
    if (userinfo->preferred_username) free(userinfo->preferred_username);
    if (userinfo->profile) free(userinfo->profile);
    if (userinfo->picture) free(userinfo->picture);
    if (userinfo->website) free(userinfo->website);
    if (userinfo->email) free(userinfo->email);
    if (userinfo->email_verified) free(userinfo->email_verified);
    if (userinfo->gender) free(userinfo->gender);
    if (userinfo->birthdate) free(userinfo->birthdate);
    if (userinfo->zoneinfo) free(userinfo->zoneinfo);
    if (userinfo->locale) free(userinfo->locale);
    if (userinfo->phone_number) free(userinfo->phone_number);
    if (userinfo->phone_number_verified) free(userinfo->phone_number_verified);
    if (userinfo->address) free(userinfo->address);
    if (userinfo->updated_at) free(userinfo->updated_at);
    if (userinfo->error) free(userinfo->error);
    if (userinfo->error_description) free(userinfo->error_description);
    
    free(userinfo);
}

// Perform UserInfo request
static char *perform_userinfo_request(const char *userinfo_url, const char *access_token) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    struct curl_slist *headers = NULL;
    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", access_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    char *response_data = NULL;
    size_t response_size = 0;
    
    curl_easy_setopt(curl, CURLOPT_URL, userinfo_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ToSSL-OIDC-Client/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || http_code != 200) {
        free(response_data);
        return NULL;
    }
    
    return response_data;
}

// Parse UserInfo response
static OidcUserinfo *parse_oidc_userinfo(const char *response_data) {
    OidcUserinfo *userinfo = calloc(1, sizeof(OidcUserinfo));
    if (!userinfo) return NULL;
    
    json_object *json = json_tokener_parse(response_data);
    if (!json) {
        userinfo->error = strdup("Invalid JSON response");
        return userinfo;
    }
    
    json_object *sub_obj, *name_obj, *given_name_obj, *family_name_obj, *middle_name_obj;
    json_object *nickname_obj, *preferred_username_obj, *profile_obj, *picture_obj, *website_obj;
    json_object *email_obj, *email_verified_obj, *gender_obj, *birthdate_obj, *zoneinfo_obj;
    json_object *locale_obj, *phone_number_obj, *phone_number_verified_obj, *address_obj, *updated_at_obj;
    
    // Parse standard claims
    if (json_object_object_get_ex(json, "sub", &sub_obj)) {
        userinfo->sub = strdup(json_object_get_string(sub_obj));
    }
    
    if (json_object_object_get_ex(json, "name", &name_obj)) {
        userinfo->name = strdup(json_object_get_string(name_obj));
    }
    
    if (json_object_object_get_ex(json, "given_name", &given_name_obj)) {
        userinfo->given_name = strdup(json_object_get_string(given_name_obj));
    }
    
    if (json_object_object_get_ex(json, "family_name", &family_name_obj)) {
        userinfo->family_name = strdup(json_object_get_string(family_name_obj));
    }
    
    if (json_object_object_get_ex(json, "middle_name", &middle_name_obj)) {
        userinfo->middle_name = strdup(json_object_get_string(middle_name_obj));
    }
    
    if (json_object_object_get_ex(json, "nickname", &nickname_obj)) {
        userinfo->nickname = strdup(json_object_get_string(nickname_obj));
    }
    
    if (json_object_object_get_ex(json, "preferred_username", &preferred_username_obj)) {
        userinfo->preferred_username = strdup(json_object_get_string(preferred_username_obj));
    }
    
    if (json_object_object_get_ex(json, "profile", &profile_obj)) {
        userinfo->profile = strdup(json_object_get_string(profile_obj));
    }
    
    if (json_object_object_get_ex(json, "picture", &picture_obj)) {
        userinfo->picture = strdup(json_object_get_string(picture_obj));
    }
    
    if (json_object_object_get_ex(json, "website", &website_obj)) {
        userinfo->website = strdup(json_object_get_string(website_obj));
    }
    
    if (json_object_object_get_ex(json, "email", &email_obj)) {
        userinfo->email = strdup(json_object_get_string(email_obj));
    }
    
    if (json_object_object_get_ex(json, "email_verified", &email_verified_obj)) {
        userinfo->email_verified = strdup(json_object_get_string(email_verified_obj));
    }
    
    if (json_object_object_get_ex(json, "gender", &gender_obj)) {
        userinfo->gender = strdup(json_object_get_string(gender_obj));
    }
    
    if (json_object_object_get_ex(json, "birthdate", &birthdate_obj)) {
        userinfo->birthdate = strdup(json_object_get_string(birthdate_obj));
    }
    
    if (json_object_object_get_ex(json, "zoneinfo", &zoneinfo_obj)) {
        userinfo->zoneinfo = strdup(json_object_get_string(zoneinfo_obj));
    }
    
    if (json_object_object_get_ex(json, "locale", &locale_obj)) {
        userinfo->locale = strdup(json_object_get_string(locale_obj));
    }
    
    if (json_object_object_get_ex(json, "phone_number", &phone_number_obj)) {
        userinfo->phone_number = strdup(json_object_get_string(phone_number_obj));
    }
    
    if (json_object_object_get_ex(json, "phone_number_verified", &phone_number_verified_obj)) {
        userinfo->phone_number_verified = strdup(json_object_get_string(phone_number_verified_obj));
    }
    
    if (json_object_object_get_ex(json, "address", &address_obj)) {
        userinfo->address = strdup(json_object_to_json_string(address_obj));
    }
    
    if (json_object_object_get_ex(json, "updated_at", &updated_at_obj)) {
        userinfo->updated_at = strdup(json_object_get_string(updated_at_obj));
    }
    
    json_object_put(json);
    return userinfo;
}

// Fetch UserInfo from endpoint
int OidcUserinfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5 && objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-access_token <token> -userinfo_url <url> ?-headers <headers>?");
        return TCL_ERROR;
    }
    
    const char *access_token = NULL;
    const char *userinfo_url = NULL;
    const char *headers = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-access_token") == 0) {
            access_token = value;
        } else if (strcmp(arg, "-userinfo_url") == 0) {
            userinfo_url = value;
        } else if (strcmp(arg, "-headers") == 0) {
            headers = value;
        }
    }
    
    if (!access_token || !userinfo_url) {
        Tcl_SetResult(interp, "Missing required parameters: -access_token, -userinfo_url", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Perform UserInfo request
    char *response_data = perform_userinfo_request(userinfo_url, access_token);
    if (!response_data) {
        Tcl_SetResult(interp, "Failed to fetch UserInfo", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Parse UserInfo response
    OidcUserinfo *userinfo = parse_oidc_userinfo(response_data);
    free(response_data);
    
    if (!userinfo) {
        Tcl_SetResult(interp, "Failed to parse UserInfo", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (userinfo->error) {
        Tcl_SetResult(interp, userinfo->error, TCL_STATIC);
        free_oidc_userinfo(userinfo);
        return TCL_ERROR;
    }
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (userinfo->sub) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("sub", -1), Tcl_NewStringObj(userinfo->sub, -1));
    }
    
    if (userinfo->name) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("name", -1), Tcl_NewStringObj(userinfo->name, -1));
    }
    
    if (userinfo->given_name) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("given_name", -1), Tcl_NewStringObj(userinfo->given_name, -1));
    }
    
    if (userinfo->family_name) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("family_name", -1), Tcl_NewStringObj(userinfo->family_name, -1));
    }
    
    if (userinfo->middle_name) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("middle_name", -1), Tcl_NewStringObj(userinfo->middle_name, -1));
    }
    
    if (userinfo->nickname) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("nickname", -1), Tcl_NewStringObj(userinfo->nickname, -1));
    }
    
    if (userinfo->preferred_username) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("preferred_username", -1), Tcl_NewStringObj(userinfo->preferred_username, -1));
    }
    
    if (userinfo->profile) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("profile", -1), Tcl_NewStringObj(userinfo->profile, -1));
    }
    
    if (userinfo->picture) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("picture", -1), Tcl_NewStringObj(userinfo->picture, -1));
    }
    
    if (userinfo->website) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("website", -1), Tcl_NewStringObj(userinfo->website, -1));
    }
    
    if (userinfo->email) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("email", -1), Tcl_NewStringObj(userinfo->email, -1));
    }
    
    if (userinfo->email_verified) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("email_verified", -1), Tcl_NewStringObj(userinfo->email_verified, -1));
    }
    
    if (userinfo->gender) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("gender", -1), Tcl_NewStringObj(userinfo->gender, -1));
    }
    
    if (userinfo->birthdate) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("birthdate", -1), Tcl_NewStringObj(userinfo->birthdate, -1));
    }
    
    if (userinfo->zoneinfo) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("zoneinfo", -1), Tcl_NewStringObj(userinfo->zoneinfo, -1));
    }
    
    if (userinfo->locale) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("locale", -1), Tcl_NewStringObj(userinfo->locale, -1));
    }
    
    if (userinfo->phone_number) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("phone_number", -1), Tcl_NewStringObj(userinfo->phone_number, -1));
    }
    
    if (userinfo->phone_number_verified) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("phone_number_verified", -1), Tcl_NewStringObj(userinfo->phone_number_verified, -1));
    }
    
    if (userinfo->address) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("address", -1), Tcl_NewStringObj(userinfo->address, -1));
    }
    
    if (userinfo->updated_at) {
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("updated_at", -1), Tcl_NewStringObj(userinfo->updated_at, -1));
    }
    
    // Cleanup
    free_oidc_userinfo(userinfo);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Validate UserInfo response
int OidcValidateUserinfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-userinfo <userinfo_data> -expected_subject <subject>");
        return TCL_ERROR;
    }
    
    const char *userinfo_data = Tcl_GetString(objv[2]);
    const char *expected_subject = Tcl_GetString(objv[4]);
    
    // Parse UserInfo data
    json_object *userinfo_json = json_tokener_parse(userinfo_data);
    if (!userinfo_json) {
        Tcl_SetResult(interp, "Invalid UserInfo data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    json_object *sub_obj;
    if (!json_object_object_get_ex(userinfo_json, "sub", &sub_obj)) {
        Tcl_SetResult(interp, "Missing 'sub' field in UserInfo", TCL_STATIC);
        json_object_put(userinfo_json);
        return TCL_ERROR;
    }
    
    const char *actual_subject = json_object_get_string(sub_obj);
    if (strcmp(actual_subject, expected_subject) != 0) {
        Tcl_SetResult(interp, "Subject mismatch in UserInfo", TCL_STATIC);
        json_object_put(userinfo_json);
        return TCL_ERROR;
    }
    
    json_object_put(userinfo_json);
    
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("subject", -1), Tcl_NewStringObj(actual_subject, -1));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Extract specific user claims
int OidcExtractUserClaimsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc % 2 != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "-userinfo <userinfo_data> -claims {claim1 claim2 ...}");
        return TCL_ERROR;
    }
    
    const char *userinfo_data = Tcl_GetString(objv[2]);
    
    // Parse claims list
    Tcl_Obj *claims_list = objv[4];
    int claims_count;
    Tcl_Obj **claims_array;
    if (Tcl_ListObjGetElements(interp, claims_list, &claims_count, &claims_array) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Parse UserInfo data
    json_object *userinfo_json = json_tokener_parse(userinfo_data);
    if (!userinfo_json) {
        Tcl_SetResult(interp, "Invalid UserInfo data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create result dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    for (int i = 0; i < claims_count; i++) {
        const char *claim_name = Tcl_GetString(claims_array[i]);
        json_object *claim_value;
        
        if (json_object_object_get_ex(userinfo_json, claim_name, &claim_value)) {
            json_type value_type = json_object_get_type(claim_value);
            
            switch (value_type) {
                case json_type_string:
                    Tcl_DictObjPut(interp, result, Tcl_NewStringObj(claim_name, -1), 
                                   Tcl_NewStringObj(json_object_get_string(claim_value), -1));
                    break;
                case json_type_boolean:
                    Tcl_DictObjPut(interp, result, Tcl_NewStringObj(claim_name, -1), 
                                   Tcl_NewBooleanObj(json_object_get_boolean(claim_value)));
                    break;
                case json_type_int:
                    Tcl_DictObjPut(interp, result, Tcl_NewStringObj(claim_name, -1), 
                                   Tcl_NewLongObj(json_object_get_int64(claim_value)));
                    break;
                case json_type_double:
                    Tcl_DictObjPut(interp, result, Tcl_NewStringObj(claim_name, -1), 
                                   Tcl_NewDoubleObj(json_object_get_double(claim_value)));
                    break;
                case json_type_object:
                case json_type_array:
                    Tcl_DictObjPut(interp, result, Tcl_NewStringObj(claim_name, -1), 
                                   Tcl_NewStringObj(json_object_to_json_string(claim_value), -1));
                    break;
                default:
                    // Skip null or unknown types
                    break;
            }
        }
    }
    
    json_object_put(userinfo_json);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Generate logout URL
int OidcLogoutUrlCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc > 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?");
        return TCL_ERROR;
    }
    
    const char *id_token_hint = NULL;
    const char *end_session_endpoint = NULL;
    const char *post_logout_redirect_uri = NULL;
    const char *state = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-id_token_hint") == 0) {
            id_token_hint = value;
        } else if (strcmp(arg, "-end_session_endpoint") == 0) {
            end_session_endpoint = value;
        } else if (strcmp(arg, "-post_logout_redirect_uri") == 0) {
            post_logout_redirect_uri = value;
        } else if (strcmp(arg, "-state") == 0) {
            state = value;
        }
    }
    
    if (!id_token_hint || !end_session_endpoint) {
        Tcl_SetResult(interp, "Missing required parameters: -id_token_hint, -end_session_endpoint", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Build logout URL
    char logout_url[4096];
    int written = snprintf(logout_url, sizeof(logout_url), "%s?id_token_hint=%s", 
                          end_session_endpoint, id_token_hint);
    
    if (post_logout_redirect_uri) {
        written += snprintf(logout_url + written, sizeof(logout_url) - written, 
                           "&post_logout_redirect_uri=%s", post_logout_redirect_uri);
    }
    
    if (state) {
        written += snprintf(logout_url + written, sizeof(logout_url) - written, 
                           "&state=%s", state);
    }
    
    if (written >= sizeof(logout_url)) {
        Tcl_SetResult(interp, "Logout URL too long", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, logout_url, TCL_VOLATILE);
    return TCL_OK;
}

// Perform end session request
static char *perform_end_session_request(const char *end_session_endpoint, 
                                        const char *id_token_hint,
                                        const char *post_logout_redirect_uri,
                                        const char *state) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    // Build POST data
    char post_data[4096];
    int written = snprintf(post_data, sizeof(post_data), "id_token_hint=%s", id_token_hint);
    
    if (post_logout_redirect_uri) {
        written += snprintf(post_data + written, sizeof(post_data) - written, 
                           "&post_logout_redirect_uri=%s", post_logout_redirect_uri);
    }
    
    if (state) {
        written += snprintf(post_data + written, sizeof(post_data) - written, 
                           "&state=%s", state);
    }
    
    if (written >= sizeof(post_data)) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    char *response_data = NULL;
    
    curl_easy_setopt(curl, CURLOPT_URL, end_session_endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ToSSL-OIDC-Client/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || (http_code != 200 && http_code != 302)) {
        free(response_data);
        return NULL;
    }
    
    return response_data;
}

// End session command
int OidcEndSessionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc > 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-id_token_hint <id_token> -end_session_endpoint <url> ?-post_logout_redirect_uri <uri>? ?-state <state>?");
        return TCL_ERROR;
    }
    
    const char *id_token_hint = NULL;
    const char *end_session_endpoint = NULL;
    const char *post_logout_redirect_uri = NULL;
    const char *state = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-id_token_hint") == 0) {
            id_token_hint = value;
        } else if (strcmp(arg, "-end_session_endpoint") == 0) {
            end_session_endpoint = value;
        } else if (strcmp(arg, "-post_logout_redirect_uri") == 0) {
            post_logout_redirect_uri = value;
        } else if (strcmp(arg, "-state") == 0) {
            state = value;
        }
    }
    
    if (!id_token_hint || !end_session_endpoint) {
        Tcl_SetResult(interp, "Missing required parameters: -id_token_hint, -end_session_endpoint", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Perform end session request
    char *response_data = perform_end_session_request(end_session_endpoint, 
                                                     id_token_hint,
                                                     post_logout_redirect_uri,
                                                     state);
    
    if (!response_data) {
        Tcl_SetResult(interp, "Failed to perform end session request", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create result
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("success", -1), Tcl_NewBooleanObj(1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("response", -1), Tcl_NewStringObj(response_data, -1));
    
    free(response_data);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Validate logout response
int OidcValidateLogoutResponseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-response <response_data>");
        return TCL_ERROR;
    }
    
    const char *response_data = Tcl_GetString(objv[2]);
    
    // Check if response is empty (successful logout)
    if (strlen(response_data) == 0) {
        Tcl_Obj *result = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(1));
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("empty_response", -1));
        Tcl_SetObjResult(interp, result);
        return TCL_OK;
    }
    
    // Try to parse as JSON (some providers return JSON responses)
    json_object *json = json_tokener_parse(response_data);
    if (json) {
        json_object *error_obj, *error_description_obj;
        
        // Check for error response
        if (json_object_object_get_ex(json, "error", &error_obj)) {
            Tcl_Obj *result = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(0));
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("error_response", -1));
            Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error", -1), Tcl_NewStringObj(json_object_get_string(error_obj), -1));
            
            if (json_object_object_get_ex(json, "error_description", &error_description_obj)) {
                Tcl_DictObjPut(interp, result, Tcl_NewStringObj("error_description", -1), 
                               Tcl_NewStringObj(json_object_get_string(error_description_obj), -1));
            }
            
            json_object_put(json);
            Tcl_SetObjResult(interp, result);
            return TCL_OK;
        }
        
        // Valid JSON response (success)
        Tcl_Obj *result = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(1));
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("json_response", -1));
        Tcl_DictObjPut(interp, result, Tcl_NewStringObj("response", -1), Tcl_NewStringObj(response_data, -1));
        
        json_object_put(json);
        Tcl_SetObjResult(interp, result);
        return TCL_OK;
    }
    
    // Non-JSON response (treat as success)
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("valid", -1), Tcl_NewBooleanObj(1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("type", -1), Tcl_NewStringObj("text_response", -1));
    Tcl_DictObjPut(interp, result, Tcl_NewStringObj("response", -1), Tcl_NewStringObj(response_data, -1));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}



// Google OIDC Provider Configuration
int OidcProviderGoogleCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc > 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> ?-redirect_uri <uri>?");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *redirect_uri = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(arg, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(arg, "-redirect_uri") == 0) {
            redirect_uri = value;
        }
    }
    
    if (!client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters: -client_id, -client_secret", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Google OIDC configuration
    const char *issuer = "https://accounts.google.com";
    
    // Discover Google OIDC configuration
    char discover_cmd[1024];
    snprintf(discover_cmd, sizeof(discover_cmd), 
             "tossl::oidc::discover -issuer \"%s\"", issuer);
    
    if (Tcl_Eval(interp, discover_cmd) != TCL_OK) {
        // Discovery failed, but we can still return basic configuration
        // Create basic provider configuration without discovery endpoints
        Tcl_Obj *config = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("google", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
        
        if (redirect_uri) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
        }
        
        // Add default scopes for Google
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                       Tcl_NewStringObj("openid profile email", -1));
        
        // Add known Google endpoints (fallback)
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                       Tcl_NewStringObj("https://accounts.google.com/o/oauth2/v2/auth", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                       Tcl_NewStringObj("https://oauth2.googleapis.com/token", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                       Tcl_NewStringObj("https://www.googleapis.com/oauth2/v3/userinfo", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("jwks_uri", -1), 
                       Tcl_NewStringObj("https://www.googleapis.com/oauth2/v3/certs", -1));
        
        Tcl_SetObjResult(interp, config);
        return TCL_OK;
    }
    
    // Parse discovery result
    Tcl_Obj *discovery_result = Tcl_GetObjResult(interp);
    const char *discovery_json = Tcl_GetString(discovery_result);
    
    // Create provider configuration
    Tcl_Obj *config = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("google", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
    
    if (redirect_uri) {
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
    }
    
    // Add default scopes for Google
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                   Tcl_NewStringObj("openid profile email", -1));
    
    // Parse discovery JSON and merge with config
    json_object *discovery_obj = json_tokener_parse(discovery_json);
    if (discovery_obj) {
        json_object *auth_endpoint, *token_endpoint, *userinfo_endpoint, *jwks_uri, *end_session_endpoint;
        
        if (json_object_object_get_ex(discovery_obj, "authorization_endpoint", &auth_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(auth_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "token_endpoint", &token_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(token_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "userinfo_endpoint", &userinfo_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(userinfo_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "jwks_uri", &jwks_uri)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("jwks_uri", -1), 
                           Tcl_NewStringObj(json_object_get_string(jwks_uri), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "end_session_endpoint", &end_session_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("end_session_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(end_session_endpoint), -1));
        }
        
        json_object_put(discovery_obj);
    }
    
    Tcl_SetObjResult(interp, config);
    return TCL_OK;
}

// Microsoft OIDC Provider Configuration
int OidcProviderMicrosoftCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc > 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> ?-redirect_uri <uri>?");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *redirect_uri = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(arg, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(arg, "-redirect_uri") == 0) {
            redirect_uri = value;
        }
    }
    
    if (!client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters: -client_id, -client_secret", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Microsoft OIDC configuration
    const char *issuer = "https://login.microsoftonline.com/common/v2.0";
    
    // Discover Microsoft OIDC configuration
    char discover_cmd[1024];
    snprintf(discover_cmd, sizeof(discover_cmd), 
             "tossl::oidc::discover -issuer \"%s\"", issuer);
    
    if (Tcl_Eval(interp, discover_cmd) != TCL_OK) {
        // Discovery failed, but we can still return basic configuration
        // Create basic provider configuration without discovery endpoints
        Tcl_Obj *config = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("microsoft", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
        
        if (redirect_uri) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
        }
        
        // Add default scopes for Microsoft
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                       Tcl_NewStringObj("openid profile email", -1));
        
        // Add known Microsoft endpoints (fallback)
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                       Tcl_NewStringObj("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                       Tcl_NewStringObj("https://login.microsoftonline.com/common/oauth2/v2.0/token", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                       Tcl_NewStringObj("https://graph.microsoft.com/oidc/userinfo", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("jwks_uri", -1), 
                       Tcl_NewStringObj("https://login.microsoftonline.com/common/discovery/v2.0/keys", -1));
        
        Tcl_SetObjResult(interp, config);
        return TCL_OK;
    }
    
    // Parse discovery result
    Tcl_Obj *discovery_result = Tcl_GetObjResult(interp);
    const char *discovery_json = Tcl_GetString(discovery_result);
    
    // Create provider configuration
    Tcl_Obj *config = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("microsoft", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
    
    if (redirect_uri) {
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
    }
    
    // Add default scopes for Microsoft
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                   Tcl_NewStringObj("openid profile email", -1));
    
    // Parse discovery JSON and merge with config
    json_object *discovery_obj = json_tokener_parse(discovery_json);
    if (discovery_obj) {
        json_object *auth_endpoint, *token_endpoint, *userinfo_endpoint, *jwks_uri, *end_session_endpoint;
        
        if (json_object_object_get_ex(discovery_obj, "authorization_endpoint", &auth_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(auth_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "token_endpoint", &token_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(token_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "userinfo_endpoint", &userinfo_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(userinfo_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "jwks_uri", &jwks_uri)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("jwks_uri", -1), 
                           Tcl_NewStringObj(json_object_get_string(jwks_uri), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "end_session_endpoint", &end_session_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("end_session_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(end_session_endpoint), -1));
        }
        
        json_object_put(discovery_obj);
    }
    
    Tcl_SetObjResult(interp, config);
    return TCL_OK;
}

// GitHub OIDC Provider Configuration
int OidcProviderGithubCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 5 || objc > 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-client_id <id> -client_secret <secret> ?-redirect_uri <uri>?");
        return TCL_ERROR;
    }
    
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *redirect_uri = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(arg, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(arg, "-redirect_uri") == 0) {
            redirect_uri = value;
        }
    }
    
    if (!client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters: -client_id, -client_secret", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // GitHub OIDC configuration
    const char *issuer = "https://token.actions.githubusercontent.com";
    
    // Note: GitHub's OIDC discovery is limited, so we'll use known endpoints
    Tcl_Obj *config = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("github", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
    
    if (redirect_uri) {
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
    }
    
    // Add default scopes for GitHub
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                   Tcl_NewStringObj("openid profile email", -1));
    
    // GitHub OAuth2 endpoints (GitHub doesn't fully support OIDC discovery)
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                   Tcl_NewStringObj("https://github.com/login/oauth/authorize", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                   Tcl_NewStringObj("https://github.com/login/oauth/access_token", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                   Tcl_NewStringObj("https://api.github.com/user", -1));
    
    Tcl_SetObjResult(interp, config);
    return TCL_OK;
}

// Generic OIDC Provider Configuration
int OidcProviderCustomCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 7 || objc > 9) {
        Tcl_WrongNumArgs(interp, 1, objv, "-issuer <issuer> -client_id <id> -client_secret <secret> ?-redirect_uri <uri>?");
        return TCL_ERROR;
    }
    
    const char *issuer = NULL;
    const char *client_id = NULL;
    const char *client_secret = NULL;
    const char *redirect_uri = NULL;
    
    // Parse arguments
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *arg = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(arg, "-issuer") == 0) {
            issuer = value;
        } else if (strcmp(arg, "-client_id") == 0) {
            client_id = value;
        } else if (strcmp(arg, "-client_secret") == 0) {
            client_secret = value;
        } else if (strcmp(arg, "-redirect_uri") == 0) {
            redirect_uri = value;
        }
    }
    
    if (!issuer || !client_id || !client_secret) {
        Tcl_SetResult(interp, "Missing required parameters: -issuer, -client_id, -client_secret", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Discover OIDC configuration
    char discover_cmd[1024];
    snprintf(discover_cmd, sizeof(discover_cmd), 
             "tossl::oidc::discover -issuer \"%s\"", issuer);
    
    if (Tcl_Eval(interp, discover_cmd) != TCL_OK) {
        // Discovery failed, but we can still return basic configuration
        // Create basic provider configuration without discovery endpoints
        Tcl_Obj *config = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("custom", -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
        
        if (redirect_uri) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
        }
        
        // Add default scopes
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                       Tcl_NewStringObj("openid profile email", -1));
        
        // For custom providers, we can't provide fallback endpoints
        // Users will need to configure these manually or ensure discovery works
        
        Tcl_SetObjResult(interp, config);
        return TCL_OK;
    }
    
    // Parse discovery result
    Tcl_Obj *discovery_result = Tcl_GetObjResult(interp);
    const char *discovery_json = Tcl_GetString(discovery_result);
    
    // Create provider configuration
    Tcl_Obj *config = Tcl_NewDictObj();
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("provider", -1), Tcl_NewStringObj("custom", -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("issuer", -1), Tcl_NewStringObj(issuer, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_id", -1), Tcl_NewStringObj(client_id, -1));
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("client_secret", -1), Tcl_NewStringObj(client_secret, -1));
    
    if (redirect_uri) {
        Tcl_DictObjPut(interp, config, Tcl_NewStringObj("redirect_uri", -1), Tcl_NewStringObj(redirect_uri, -1));
    }
    
    // Add default scopes
    Tcl_DictObjPut(interp, config, Tcl_NewStringObj("default_scopes", -1), 
                   Tcl_NewStringObj("openid profile email", -1));
    
    // Parse discovery JSON and merge with config
    json_object *discovery_obj = json_tokener_parse(discovery_json);
    if (discovery_obj) {
        json_object *auth_endpoint, *token_endpoint, *userinfo_endpoint, *jwks_uri, *end_session_endpoint;
        
        if (json_object_object_get_ex(discovery_obj, "authorization_endpoint", &auth_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("authorization_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(auth_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "token_endpoint", &token_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("token_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(token_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "userinfo_endpoint", &userinfo_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("userinfo_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(userinfo_endpoint), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "jwks_uri", &jwks_uri)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("jwks_uri", -1), 
                           Tcl_NewStringObj(json_object_get_string(jwks_uri), -1));
        }
        
        if (json_object_object_get_ex(discovery_obj, "end_session_endpoint", &end_session_endpoint)) {
            Tcl_DictObjPut(interp, config, Tcl_NewStringObj("end_session_endpoint", -1), 
                           Tcl_NewStringObj(json_object_get_string(end_session_endpoint), -1));
        }
        
        json_object_put(discovery_obj);
    }
    
    Tcl_SetObjResult(interp, config);
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
    Tcl_CreateObjCommand(interp, "tossl::oidc::verify_jwt_with_jwks", OidcVerifyJwtWithJwksCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::userinfo", OidcUserinfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::validate_userinfo", OidcValidateUserinfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::extract_user_claims", OidcExtractUserClaimsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::logout_url", OidcLogoutUrlCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::end_session", OidcEndSessionCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::validate_logout_response", OidcValidateLogoutResponseCmd, NULL, NULL);
    
    // Provider preset commands
    Tcl_CreateObjCommand(interp, "tossl::oidc::provider::google", OidcProviderGoogleCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::provider::microsoft", OidcProviderMicrosoftCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::provider::github", OidcProviderGithubCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::oidc::provider::custom", OidcProviderCustomCmd, NULL, NULL);
    
    return TCL_OK;
}