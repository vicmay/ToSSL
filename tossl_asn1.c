#include "tossl.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>

// ASN.1 parsing function
int Asn1ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "der_data");
        return TCL_ERROR;
    }
    
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[1], &data_len);
    
    // Parse ASN.1 structure
    const unsigned char *p = data;
    ASN1_TYPE *asn1_type = d2i_ASN1_TYPE(NULL, &p, data_len);
    
    if (!asn1_type) {
        Tcl_SetResult(interp, "Failed to parse ASN.1 data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert to text representation using BIO
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ASN1_TYPE_free(asn1_type);
        Tcl_SetResult(interp, "Failed to create BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Use a simpler approach - return type information based on the actual type
    char result[256];
    int value_length = 0;
    
    switch (asn1_type->type) {
        case V_ASN1_INTEGER:
            if (asn1_type->value.integer) {
                value_length = ASN1_STRING_length(asn1_type->value.integer);
            }
            break;
        case V_ASN1_OCTET_STRING:
            if (asn1_type->value.octet_string) {
                value_length = ASN1_STRING_length(asn1_type->value.octet_string);
            }
            break;
        case V_ASN1_UTF8STRING:
            if (asn1_type->value.utf8string) {
                value_length = ASN1_STRING_length(asn1_type->value.utf8string);
            }
            break;
        case V_ASN1_OBJECT:
            if (asn1_type->value.object) {
                char obj_text[128];
                OBJ_obj2txt(obj_text, sizeof(obj_text), asn1_type->value.object, 1);
                snprintf(result, sizeof(result), "type=%d, object=%s", asn1_type->type, obj_text);
                BIO_free(bio);
                ASN1_TYPE_free(asn1_type);
                Tcl_SetResult(interp, result, TCL_VOLATILE);
                return TCL_OK;
            }
            break;
        default:
            value_length = 0;
            break;
    }
    
    snprintf(result, sizeof(result), "type=%d, value_length=%d", asn1_type->type, value_length);
    
    BIO_free(bio);
    ASN1_TYPE_free(asn1_type);
    
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

// ASN.1 encoding function
int Asn1EncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "type value");
        return TCL_ERROR;
    }
    
    const char *type = Tcl_GetString(objv[1]);
    const char *value = Tcl_GetString(objv[2]);
    
    ASN1_TYPE *asn1_type = ASN1_TYPE_new();
    if (!asn1_type) {
        Tcl_SetResult(interp, "Failed to create ASN.1 type", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set type based on input
    if (strcmp(type, "integer") == 0) {
        long int_val = atol(value);
        ASN1_INTEGER *int_obj = ASN1_INTEGER_new();
        ASN1_INTEGER_set(int_obj, int_val);
        ASN1_TYPE_set(asn1_type, V_ASN1_INTEGER, int_obj);
    } else if (strcmp(type, "octetstring") == 0) {
        ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(octet, (const unsigned char*)value, strlen(value));
        ASN1_TYPE_set(asn1_type, V_ASN1_OCTET_STRING, octet);
    } else if (strcmp(type, "utf8string") == 0) {
        ASN1_UTF8STRING *utf8 = ASN1_UTF8STRING_new();
        ASN1_STRING_set(utf8, value, strlen(value));
        ASN1_TYPE_set(asn1_type, V_ASN1_UTF8STRING, utf8);
    } else if (strcmp(type, "objectidentifier") == 0) {
        ASN1_OBJECT *obj = OBJ_txt2obj(value, 0);
        if (!obj) {
            ASN1_TYPE_free(asn1_type);
            Tcl_SetResult(interp, "Invalid OID format", TCL_STATIC);
            return TCL_ERROR;
        }
        ASN1_TYPE_set(asn1_type, V_ASN1_OBJECT, obj);
    } else {
        ASN1_TYPE_free(asn1_type);
        Tcl_SetResult(interp, "Unsupported ASN.1 type", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Encode to DER
    unsigned char *der = NULL;
    int der_len = i2d_ASN1_TYPE(asn1_type, &der);
    
    if (der_len <= 0) {
        ASN1_TYPE_free(asn1_type);
        Tcl_SetResult(interp, "Failed to encode ASN.1 data", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(der, der_len);
    Tcl_SetObjResult(interp, result);
    
    OPENSSL_free(der);
    ASN1_TYPE_free(asn1_type);
    return TCL_OK;
}

// ASN.1 OID functions
int Asn1OidToTextCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "oid");
        return TCL_ERROR;
    }
    
    const char *oid = Tcl_GetString(objv[1]);
    
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 0);
    if (!obj) {
        Tcl_SetResult(interp, "Invalid OID", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char oid_text[256];
    if (!OBJ_obj2txt(oid_text, sizeof(oid_text), obj, 1)) {
        ASN1_OBJECT_free(obj);
        Tcl_SetResult(interp, "Failed to convert OID to text", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, oid_text, TCL_VOLATILE);
    ASN1_OBJECT_free(obj);
    return TCL_OK;
}

int Asn1TextToOidCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "text");
        return TCL_ERROR;
    }
    
    const char *text = Tcl_GetString(objv[1]);
    
    // Try to convert text name to OID using OBJ_txt2obj with no_name = 1
    ASN1_OBJECT *obj = OBJ_txt2obj(text, 1);
    if (!obj) {
        Tcl_SetResult(interp, "Invalid OID text", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char oid_dot[256];
    if (!OBJ_obj2txt(oid_dot, sizeof(oid_dot), obj, 0)) {
        ASN1_OBJECT_free(obj);
        Tcl_SetResult(interp, "Failed to convert text to OID", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, oid_dot, TCL_VOLATILE);
    ASN1_OBJECT_free(obj);
    return TCL_OK;
}

// Simplified ASN.1 sequence functions
int Asn1SequenceCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "element1 ?element2 ...?");
        return TCL_ERROR;
    }
    
    // Create a sequence using STACK_OF(ASN1_TYPE)
    STACK_OF(ASN1_TYPE) *seq = sk_ASN1_TYPE_new_null();
    if (!seq) {
        Tcl_SetResult(interp, "Failed to create ASN.1 sequence", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add elements to the sequence
    for (int i = 1; i < objc; i++) {
        const char *element_str = Tcl_GetString(objv[i]);
        
        // Try to parse as different ASN.1 types
        ASN1_TYPE *element = NULL;
        
        // Try as integer first
        char *endptr;
        long int_val = strtol(element_str, &endptr, 10);
        if (*endptr == '\0') {
            // Valid integer
            ASN1_INTEGER *int_obj = ASN1_INTEGER_new();
            if (ASN1_INTEGER_set(int_obj, int_val)) {
                element = ASN1_TYPE_new();
                ASN1_TYPE_set(element, V_ASN1_INTEGER, int_obj);
            }
        } else {
            // Try as octet string
            ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
            if (ASN1_OCTET_STRING_set(octet, (const unsigned char*)element_str, strlen(element_str))) {
                element = ASN1_TYPE_new();
                ASN1_TYPE_set(element, V_ASN1_OCTET_STRING, octet);
            }
        }
        
        if (element) {
            if (!sk_ASN1_TYPE_push(seq, element)) {
                ASN1_TYPE_free(element);
                sk_ASN1_TYPE_free(seq);
                Tcl_SetResult(interp, "Failed to add element to sequence", TCL_STATIC);
                return TCL_ERROR;
            }
        } else {
            sk_ASN1_TYPE_free(seq);
            Tcl_SetResult(interp, "Failed to create ASN.1 element", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // Create a simple sequence structure for encoding
    // For now, return a basic sequence structure
    // This is a simplified implementation - full ASN.1 sequence encoding is complex
    
    // Calculate total length of all elements
    int total_length = 0;
    
    // Calculate total length of all elements
    for (int i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
        ASN1_TYPE *element = sk_ASN1_TYPE_value(seq, i);
        unsigned char *der = NULL;
        int der_len = i2d_ASN1_TYPE(element, &der);
        if (der_len > 0) {
            total_length += der_len;
            OPENSSL_free(der);
        }
    }
    
    // Allocate buffer for complete sequence (with extra space for length encoding)
    unsigned char *result_buffer = malloc(6 + total_length); // Extra space for long length encoding
    if (!result_buffer) {
        sk_ASN1_TYPE_free(seq);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set sequence tag
    result_buffer[0] = 0x30; // SEQUENCE
    
    // Set length (handle both short and long form)
    int offset = 2;
    if (total_length < 128) {
        // Short form
        result_buffer[1] = total_length;
    } else {
        // Long form - calculate number of length bytes needed
        int length_bytes = 1;
        int temp_length = total_length;
        while (temp_length > 255) {
            length_bytes++;
            temp_length >>= 8;
        }
        
        // Check if we have enough space
        if (length_bytes > 3) { // Limit to reasonable size
            free(result_buffer);
            sk_ASN1_TYPE_free(seq);
            Tcl_SetResult(interp, "Sequence too long for encoding", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // Set length byte with bit 7 set and length bytes count
        result_buffer[1] = 0x80 | length_bytes;
        offset = 2 + length_bytes;
        
        // Set length bytes (big-endian)
        for (int i = length_bytes - 1; i >= 0; i--) {
            result_buffer[2 + i] = total_length & 0xFF;
            total_length >>= 8;
        }
    }
    
    // Add all elements
    for (int i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
        ASN1_TYPE *element = sk_ASN1_TYPE_value(seq, i);
        unsigned char *der = NULL;
        int der_len = i2d_ASN1_TYPE(element, &der);
        if (der_len > 0) {
            memcpy(result_buffer + offset, der, der_len);
            offset += der_len;
            OPENSSL_free(der);
        }
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(result_buffer, offset);
    Tcl_SetObjResult(interp, result);
    free(result_buffer);
    
    sk_ASN1_TYPE_free(seq);
    return TCL_OK;
}

// Simplified ASN.1 set functions
int Asn1SetCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "element1 ?element2 ...?");
        return TCL_ERROR;
    }
    
    // Create a set using STACK_OF(ASN1_TYPE)
    STACK_OF(ASN1_TYPE) *set = sk_ASN1_TYPE_new_null();
    if (!set) {
        Tcl_SetResult(interp, "Failed to create ASN.1 set", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Add elements to the set
    for (int i = 1; i < objc; i++) {
        const char *element_str = Tcl_GetString(objv[i]);
        
        // Try to parse as different ASN.1 types
        ASN1_TYPE *element = NULL;
        
        // Try as integer first
        char *endptr;
        long int_val = strtol(element_str, &endptr, 10);
        if (*endptr == '\0') {
            // Valid integer
            ASN1_INTEGER *int_obj = ASN1_INTEGER_new();
            if (ASN1_INTEGER_set(int_obj, int_val)) {
                element = ASN1_TYPE_new();
                ASN1_TYPE_set(element, V_ASN1_INTEGER, int_obj);
            }
        } else {
            // Try as octet string
            ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
            if (ASN1_OCTET_STRING_set(octet, (const unsigned char*)element_str, strlen(element_str))) {
                element = ASN1_TYPE_new();
                ASN1_TYPE_set(element, V_ASN1_OCTET_STRING, octet);
            }
        }
        
        if (element) {
            if (!sk_ASN1_TYPE_push(set, element)) {
                ASN1_TYPE_free(element);
                sk_ASN1_TYPE_free(set);
                Tcl_SetResult(interp, "Failed to add element to set", TCL_STATIC);
                return TCL_ERROR;
            }
        } else {
            sk_ASN1_TYPE_free(set);
            Tcl_SetResult(interp, "Failed to create ASN.1 element", TCL_STATIC);
            return TCL_ERROR;
        }
    }
    
    // Calculate total length of all elements
    int total_length = 0;
    
    for (int i = 0; i < sk_ASN1_TYPE_num(set); i++) {
        ASN1_TYPE *element = sk_ASN1_TYPE_value(set, i);
        unsigned char *der = NULL;
        int der_len = i2d_ASN1_TYPE(element, &der);
        if (der_len > 0) {
            total_length += der_len;
            OPENSSL_free(der);
        }
    }
    
    // Allocate buffer for complete set (with extra space for length encoding)
    unsigned char *result_buffer = malloc(6 + total_length); // Extra space for long length encoding
    if (!result_buffer) {
        sk_ASN1_TYPE_free(set);
        Tcl_SetResult(interp, "Memory allocation failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set set tag (0x31 for SET)
    result_buffer[0] = 0x31; // SET
    
    // Set length (handle both short and long form)
    int offset = 2;
    if (total_length < 128) {
        // Short form
        result_buffer[1] = total_length;
    } else {
        // Long form - calculate number of length bytes needed
        int length_bytes = 1;
        int temp_length = total_length;
        while (temp_length > 255) {
            length_bytes++;
            temp_length >>= 8;
        }
        
        // Check if we have enough space
        if (length_bytes > 3) { // Limit to reasonable size
            free(result_buffer);
            sk_ASN1_TYPE_free(set);
            Tcl_SetResult(interp, "Set too long for encoding", TCL_STATIC);
            return TCL_ERROR;
        }
        
        // Set length byte with bit 7 set and length bytes count
        result_buffer[1] = 0x80 | length_bytes;
        offset = 2 + length_bytes;
        
        // Set length bytes (big-endian)
        for (int i = length_bytes - 1; i >= 0; i--) {
            result_buffer[2 + i] = total_length & 0xFF;
            total_length >>= 8;
        }
    }
    
    // Add all elements
    for (int i = 0; i < sk_ASN1_TYPE_num(set); i++) {
        ASN1_TYPE *element = sk_ASN1_TYPE_value(set, i);
        unsigned char *der = NULL;
        int der_len = i2d_ASN1_TYPE(element, &der);
        if (der_len > 0) {
            memcpy(result_buffer + offset, der, der_len);
            offset += der_len;
            OPENSSL_free(der);
        }
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(result_buffer, offset);
    Tcl_SetObjResult(interp, result);
    free(result_buffer);
    
    sk_ASN1_TYPE_free(set);
    return TCL_OK;
} 