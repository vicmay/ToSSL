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

// Structure to hold response data
struct HttpResponse {
    char *data;
    size_t size;
    long status_code;
    char *headers;
    size_t headers_size;
};

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

int Tossl_HttpGetCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "url");
        return TCL_ERROR;
    }
    const char *url = Tcl_GetString(objv[1]);
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to init curl", TCL_STATIC);
        return TCL_ERROR;
    }
    struct HttpResponse chunk = {malloc(1), 0, 0, malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_VOLATILE);
        curl_easy_cleanup(curl);
        free(chunk.data);
        free(chunk.headers);
        return TCL_ERROR;
    }
    
    // Get status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &chunk.status_code);
    
    // Create response dict
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_Obj *status_key = Tcl_NewStringObj("status_code", -1);
    Tcl_Obj *status_value = Tcl_NewIntObj(chunk.status_code);
    Tcl_DictObjPut(interp, result, status_key, status_value);
    
    Tcl_Obj *body_key = Tcl_NewStringObj("body", -1);
    Tcl_Obj *body_value = Tcl_NewStringObj(chunk.data, chunk.size);
    Tcl_DictObjPut(interp, result, body_key, body_value);
    
    Tcl_Obj *headers_key = Tcl_NewStringObj("headers", -1);
    Tcl_Obj *headers_value = Tcl_NewStringObj(chunk.headers, chunk.headers_size);
    Tcl_DictObjPut(interp, result, headers_key, headers_value);
    
    Tcl_SetObjResult(interp, result);
    curl_easy_cleanup(curl);
    free(chunk.data);
    free(chunk.headers);
    return TCL_OK;
}

int Tossl_HttpPostCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "url data");
        return TCL_ERROR;
    }
    const char *url = Tcl_GetString(objv[1]);
    const char *postfields = Tcl_GetString(objv[2]);
    CURL *curl = curl_easy_init();
    if (!curl) {
        Tcl_SetResult(interp, "Failed to init curl", TCL_STATIC);
        return TCL_ERROR;
    }
    struct HttpResponse chunk = {malloc(1), 0, 0, malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Tcl_SetResult(interp, (char *)curl_easy_strerror(res), TCL_VOLATILE);
        curl_easy_cleanup(curl);
        free(chunk.data);
        free(chunk.headers);
        return TCL_ERROR;
    }
    
    // Get status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &chunk.status_code);
    
    // Create response dict
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_Obj *status_key = Tcl_NewStringObj("status_code", -1);
    Tcl_Obj *status_value = Tcl_NewIntObj(chunk.status_code);
    Tcl_DictObjPut(interp, result, status_key, status_value);
    
    Tcl_Obj *body_key = Tcl_NewStringObj("body", -1);
    Tcl_Obj *body_value = Tcl_NewStringObj(chunk.data, chunk.size);
    Tcl_DictObjPut(interp, result, body_key, body_value);
    
    Tcl_Obj *headers_key = Tcl_NewStringObj("headers", -1);
    Tcl_Obj *headers_value = Tcl_NewStringObj(chunk.headers, chunk.headers_size);
    Tcl_DictObjPut(interp, result, headers_key, headers_value);
    
    Tcl_SetObjResult(interp, result);
    curl_easy_cleanup(curl);
    free(chunk.data);
    free(chunk.headers);
    return TCL_OK;
}

int Tossl_HttpInit(Tcl_Interp *interp) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    Tcl_CreateObjCommand(interp, "tossl::http::get", Tossl_HttpGetCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::http::post", Tossl_HttpPostCmd, NULL, NULL);
    return TCL_OK;
} 