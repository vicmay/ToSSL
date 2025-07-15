#include <tcl.h>
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>

// JSON parse command
int Tossl_JsonParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "json_string");
        return TCL_ERROR;
    }
    
    const char *json_str = Tcl_GetString(objv[1]);
    
    // Parse JSON string
    json_object *json_obj = json_tokener_parse(json_str);
    if (!json_obj) {
        Tcl_SetResult(interp, "Failed to parse JSON", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert to Tcl dict
    Tcl_Obj *result = Tcl_NewDictObj();
    
    if (json_object_is_type(json_obj, json_type_object)) {
        json_object_object_foreach(json_obj, key, val) {
            Tcl_Obj *key_obj = Tcl_NewStringObj(key, -1);
            Tcl_Obj *value_obj;
            
            if (json_object_is_type(val, json_type_string)) {
                value_obj = Tcl_NewStringObj(json_object_get_string(val), -1);
            } else if (json_object_is_type(val, json_type_int)) {
                value_obj = Tcl_NewIntObj(json_object_get_int(val));
            } else if (json_object_is_type(val, json_type_boolean)) {
                value_obj = Tcl_NewBooleanObj(json_object_get_boolean(val));
            } else if (json_object_is_type(val, json_type_double)) {
                value_obj = Tcl_NewDoubleObj(json_object_get_double(val));
            } else {
                // For complex types, convert to string
                value_obj = Tcl_NewStringObj(json_object_to_json_string(val), -1);
            }
            
            Tcl_DictObjPut(interp, result, key_obj, value_obj);
        }
    }
    
    json_object_put(json_obj);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// JSON generate command
int Tossl_JsonGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "tcl_dict");
        return TCL_ERROR;
    }
    
    Tcl_Obj *dict_obj = objv[1];
    
    // Create JSON object
    json_object *json_obj = json_object_new_object();
    
    // Iterate through Tcl dict
    Tcl_DictSearch search;
    Tcl_Obj *key, *value;
    int done;
    
    if (Tcl_DictObjFirst(interp, dict_obj, &search, &key, &value, &done) != TCL_OK) {
        json_object_put(json_obj);
        return TCL_ERROR;
    }
    
    while (!done) {
        const char *key_str = Tcl_GetString(key);
        
        // Determine value type and add to JSON
        int int_val;
        double double_val;
        
        if (Tcl_GetBooleanFromObj(interp, value, &int_val) == TCL_OK) {
            json_object_object_add(json_obj, key_str, json_object_new_boolean(int_val));
        } else if (Tcl_GetIntFromObj(interp, value, &int_val) == TCL_OK) {
            json_object_object_add(json_obj, key_str, json_object_new_int(int_val));
        } else if (Tcl_GetDoubleFromObj(interp, value, &double_val) == TCL_OK) {
            json_object_object_add(json_obj, key_str, json_object_new_double(double_val));
        } else {
            // Treat as string
            const char *value_str = Tcl_GetString(value);
            json_object_object_add(json_obj, key_str, json_object_new_string(value_str));
        }
        
        Tcl_DictObjNext(&search, &key, &value, &done);
    }
    
    // Convert to string
    const char *json_str = json_object_to_json_string(json_obj);
    Tcl_SetResult(interp, (char *)json_str, TCL_VOLATILE);
    
    json_object_put(json_obj);
    return TCL_OK;
}

// Initialize JSON module
int Tossl_JsonInit(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::json::parse", Tossl_JsonParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::json::generate", Tossl_JsonGenerateCmd, NULL, NULL);
    return TCL_OK;
} 