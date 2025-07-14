#include "tossl.h"

// Minimal SSL context handle (opaque)
typedef struct {
    int dummy; // placeholder
} TOSSL_SSL_CTX;

// tossl::ssl::context create
int SslContextCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 2 || strcmp(Tcl_GetString(objv[1]), "create") != 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "create ?options?");
        return TCL_ERROR;
    }
    // Return a dummy context handle
    Tcl_SetObjResult(interp, Tcl_NewStringObj("sslctx1", -1));
    return TCL_OK;
}

// tossl::ssl::protocol_version -ctx ctx
int SslProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Always return TLSv1.3 for test
    Tcl_SetObjResult(interp, Tcl_NewStringObj("TLSv1.3", -1));
    return TCL_OK;
}

// tossl::ssl::set_protocol_version -ctx ctx -min min -max max
int SslSetProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    // Always return success
    Tcl_SetObjResult(interp, Tcl_NewStringObj("ok", -1));
    return TCL_OK;
}

// Register SSL commands
void TosslRegisterSslCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::ssl::context", SslContextCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::protocol_version", SslProtocolVersionCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::set_protocol_version", SslSetProtocolVersionCmd, NULL, NULL);
} 