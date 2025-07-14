#include "tossl.h"

// OCSP create request command
int OcspCreateRequestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "cert_pem issuer_pem");
        return TCL_ERROR;
    }
    
    const char *cert_pem = Tcl_GetString(objv[1]);
    const char *issuer_pem = Tcl_GetString(objv[2]);
    
    BIO *cert_bio = BIO_new_mem_buf((void*)cert_pem, -1);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to parse certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *issuer_bio = BIO_new_mem_buf((void*)issuer_pem, -1);
    X509 *issuer = PEM_read_bio_X509(issuer_bio, NULL, NULL, NULL);
    if (!issuer) {
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to parse issuer certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    if (!req) {
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create OCSP request", TCL_STATIC);
        return TCL_ERROR;
    }
    
    OCSP_CERTID *certid = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (!certid) {
        OCSP_REQUEST_free(req);
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create certificate ID", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (OCSP_request_add0_id(req, certid) <= 0) {
        OCSP_CERTID_free(certid);
        OCSP_REQUEST_free(req);
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to add certificate ID to request", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        OCSP_REQUEST_free(req);
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to create output BIO", TCL_STATIC);
        return TCL_ERROR;
    }
    
    if (i2d_OCSP_REQUEST_bio(out_bio, req) <= 0) {
        BIO_free(out_bio);
        OCSP_REQUEST_free(req);
        X509_free(issuer);
        BIO_free(issuer_bio);
        X509_free(cert);
        BIO_free(cert_bio);
        Tcl_SetResult(interp, "Failed to write OCSP request", TCL_STATIC);
        return TCL_ERROR;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    
    BIO_free(out_bio);
    OCSP_REQUEST_free(req);
    X509_free(issuer);
    BIO_free(issuer_bio);
    X509_free(cert);
    BIO_free(cert_bio);
    return TCL_OK;
}

// OCSP parse response command
int OcspParseResponseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "ocsp_response");
        return TCL_ERROR;
    }
    
    const char *ocsp_response = Tcl_GetString(objv[1]);
    
    BIO *resp_bio = BIO_new_mem_buf((void*)ocsp_response, -1);
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE_bio(resp_bio, NULL);
    if (!resp) {
        BIO_free(resp_bio);
        Tcl_SetResult(interp, "Failed to parse OCSP response", TCL_STATIC);
        return TCL_ERROR;
    }
    
    OCSP_BASICRESP *basic = OCSP_response_get1_basic(resp);
    if (!basic) {
        OCSP_RESPONSE_free(resp);
        BIO_free(resp_bio);
        Tcl_SetResult(interp, "Failed to get basic response", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Get response status
    int status = OCSP_response_status(resp);
    const char *status_str = NULL;
    switch (status) {
        case OCSP_RESPONSE_STATUS_SUCCESSFUL: status_str = "successful"; break;
        case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST: status_str = "malformed_request"; break;
        case OCSP_RESPONSE_STATUS_INTERNALERROR: status_str = "internal_error"; break;
        case OCSP_RESPONSE_STATUS_TRYLATER: status_str = "try_later"; break;
        case OCSP_RESPONSE_STATUS_SIGREQUIRED: status_str = "sig_required"; break;
        case OCSP_RESPONSE_STATUS_UNAUTHORIZED: status_str = "unauthorized"; break;
        default: status_str = "unknown"; break;
    }
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("status", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(status_str, -1));
    
    if (status == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        // Get certificate status
        STACK_OF(OCSP_SINGLERESP) *responses = OCSP_resp_get0(basic, 0);
        if (responses) {
            int num_responses = sk_OCSP_SINGLERESP_num(responses);
            Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("num_responses", -1));
            Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(num_responses));
            
            for (int i = 0; i < num_responses; i++) {
                OCSP_SINGLERESP *single = sk_OCSP_SINGLERESP_value(responses, i);
                if (single) {
                    int cert_status = OCSP_single_get0_status(single, NULL, NULL, NULL, NULL);
                    const char *cert_status_str = NULL;
                    switch (cert_status) {
                        case V_OCSP_CERTSTATUS_GOOD: cert_status_str = "good"; break;
                        case V_OCSP_CERTSTATUS_REVOKED: cert_status_str = "revoked"; break;
                        case V_OCSP_CERTSTATUS_UNKNOWN: cert_status_str = "unknown"; break;
                        default: cert_status_str = "unknown"; break;
                    }
                    
                    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("cert_status", -1));
                    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(cert_status_str, -1));
                }
            }
        }
    }
    
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);
    BIO_free(resp_bio);
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
} 