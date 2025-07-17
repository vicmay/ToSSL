#include <tcl.h>
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Helper function to convert JSON object to Tcl object
Tcl_Obj* json_to_tcl(json_object *json_obj) {
    if (!json_obj) return NULL;
    
    if (json_object_is_type(json_obj, json_type_string)) {
        return Tcl_NewStringObj(json_object_get_string(json_obj), -1);
    } else if (json_object_is_type(json_obj, json_type_int)) {
        return Tcl_NewIntObj(json_object_get_int(json_obj));
    } else if (json_object_is_type(json_obj, json_type_boolean)) {
        return Tcl_NewBooleanObj(json_object_get_boolean(json_obj));
    } else if (json_object_is_type(json_obj, json_type_double)) {
        return Tcl_NewDoubleObj(json_object_get_double(json_obj));
    } else if (json_object_is_type(json_obj, json_type_array)) {
        Tcl_Obj *list = Tcl_NewListObj(0, NULL);
        int array_len = json_object_array_length(json_obj);
        for (int i = 0; i < array_len; i++) {
            json_object *item = json_object_array_get_idx(json_obj, i);
            Tcl_Obj *tcl_item = json_to_tcl(item);
            if (tcl_item) {
                Tcl_ListObjAppendElement(NULL, list, tcl_item);
            }
        }
        return list;
    } else if (json_object_is_type(json_obj, json_type_object)) {
        Tcl_Obj *dict = Tcl_NewDictObj();
        json_object_object_foreach(json_obj, key, val) {
            Tcl_Obj *key_obj = Tcl_NewStringObj(key, -1);
            Tcl_Obj *value_obj = json_to_tcl(val);
            if (value_obj) {
                Tcl_DictObjPut(NULL, dict, key_obj, value_obj);
            }
        }
        return dict;
    } else {
        // For null or unknown types, return as string
        return Tcl_NewStringObj(json_object_to_json_string(json_obj), -1);
    }
}

// Helper function to convert Tcl object to JSON object
json_object* tcl_to_json(Tcl_Interp *interp, Tcl_Obj *obj) {
    if (!obj) return NULL;

    Tcl_ObjType *typePtr = obj->typePtr;
    if (typePtr && strcmp(typePtr->name, "dict") == 0) {
        int dict_size = 0;
        Tcl_DictObjSize(interp, obj, &dict_size);
        json_object *json_obj = json_object_new_object();
        if (dict_size > 0) {
            Tcl_DictSearch search;
            Tcl_Obj *key, *value;
            int done;
            if (Tcl_DictObjFirst(interp, obj, &search, &key, &value, &done) == TCL_OK) {
                while (!done) {
                    const char *key_str = Tcl_GetString(key);
                    json_object *value_json = tcl_to_json(interp, value);
                    if (value_json) {
                        json_object_object_add(json_obj, key_str, value_json);
                    }
                    Tcl_DictObjNext(&search, &key, &value, &done);
                }
            }
        }
        return json_obj;
    }

    if (typePtr && strcmp(typePtr->name, "list") == 0) {
        int list_len = 0;
        Tcl_Obj **list_elems = NULL;
        Tcl_ListObjLength(interp, obj, &list_len);
        json_object *array = json_object_new_array();
        if (list_len > 0 && Tcl_ListObjGetElements(interp, obj, &list_len, &list_elems) == TCL_OK) {
            for (int i = 0; i < list_len; i++) {
                json_object *item = tcl_to_json(interp, list_elems[i]);
                if (item) {
                    json_object_array_add(array, item);
                }
            }
        }
        return array;
    }

    const char *str = Tcl_GetString(obj);
    if (strcmp(str, "true") == 0) {
        return json_object_new_boolean(1);
    } else if (strcmp(str, "false") == 0) {
        return json_object_new_boolean(0);
    }

    int int_val;
    if (Tcl_GetIntFromObj(interp, obj, &int_val) == TCL_OK) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d", int_val);
        if (strcmp(str, buf) == 0) {
            return json_object_new_int(int_val);
        }
    }

    double double_val;
    if (Tcl_GetDoubleFromObj(interp, obj, &double_val) == TCL_OK) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%g", double_val);
        if (strcmp(str, buf) == 0) {
            return json_object_new_double(double_val);
        }
    }

    return json_object_new_string(str);
}

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
    
    // Convert to Tcl object
    Tcl_Obj *result = json_to_tcl(json_obj);
    if (!result) {
        json_object_put(json_obj);
        Tcl_SetResult(interp, "Failed to convert JSON to Tcl", TCL_STATIC);
        return TCL_ERROR;
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
    
    Tcl_Obj *obj = objv[1];
    
    // Convert Tcl object to JSON
    json_object *json_obj = tcl_to_json(interp, obj);
    if (!json_obj) {
        Tcl_SetResult(interp, "Failed to convert Tcl object to JSON", TCL_STATIC);
        return TCL_ERROR;
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