#include "tossl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

// SSL context handle
typedef struct {
    SSL_CTX *ctx;
    char *handle_name;
    Tcl_Interp *interp; // Store interpreter for callback
    char *alpn_callback; // Store callback name
} TOSSL_SSL_CTX;

// SSL connection handle
typedef struct {
    SSL *ssl;
    char *handle_name;
    int socket_fd;
} TOSSL_SSL_CONN;

// Global context storage
static TOSSL_SSL_CTX *ssl_contexts = NULL;
static int ssl_context_count = 0;
static TOSSL_SSL_CONN *ssl_connections = NULL;
static int ssl_connection_count = 0;

// Forward declarations
static TOSSL_SSL_CTX *FindTosslCtxBySslCtx(SSL_CTX *ctx);
static int TosslAlpnSelectCb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                             const unsigned char *in, unsigned int inlen, void *arg);

// tossl::ssl::context create
int SslContextCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 2 || strcmp(Tcl_GetString(objv[1]), "create") != 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "create ?options?");
        return TCL_ERROR;
    }
    
    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        Tcl_SetResult(interp, "Failed to create SSL context", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set default options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    // Parse additional options
    for (int i = 2; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-cert") == 0) {
            if (!SSL_CTX_use_certificate_file(ctx, value, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to load certificate", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(option, "-key") == 0) {
            if (!SSL_CTX_use_PrivateKey_file(ctx, value, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to load private key", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(option, "-ca") == 0) {
            if (!SSL_CTX_load_verify_locations(ctx, value, NULL)) {
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to load CA certificate", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(option, "-verify") == 0) {
            if (strcmp(value, "peer") == 0) {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            } else if (strcmp(value, "require") == 0) {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            }
        } else if (strcmp(option, "-client_cert") == 0) {
            if (!SSL_CTX_use_certificate_file(ctx, value, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to load client certificate", TCL_STATIC);
                return TCL_ERROR;
            }
        } else if (strcmp(option, "-client_key") == 0) {
            if (!SSL_CTX_use_PrivateKey_file(ctx, value, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(ctx);
                Tcl_SetResult(interp, "Failed to load client private key", TCL_STATIC);
                return TCL_ERROR;
            }
        }
    }
    
    // Create handle
    char handle_name[32];
    snprintf(handle_name, sizeof(handle_name), "sslctx%d", ++ssl_context_count);
    
    TOSSL_SSL_CTX *handle = malloc(sizeof(TOSSL_SSL_CTX));
    handle->ctx = ctx;
    handle->handle_name = strdup(handle_name);
    handle->interp = interp;
    handle->alpn_callback = NULL;
    
    // Add to global list
    ssl_contexts = realloc(ssl_contexts, ssl_context_count * sizeof(TOSSL_SSL_CTX));
    ssl_contexts[ssl_context_count - 1] = *handle;
    
    Tcl_SetResult(interp, handle_name, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::connect -ctx ctx -host host -port port ?-sni servername? ?-alpn protocols?
int SslConnectCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -host host -port port ?-sni servername? ?-alpn protocols?");
        return TCL_ERROR;
    }
    
    const char *ctx_name = NULL, *host = NULL, *port = NULL, *sni = NULL, *alpn = NULL;
    
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-ctx") == 0) {
            ctx_name = value;
        } else if (strcmp(option, "-host") == 0) {
            host = value;
        } else if (strcmp(option, "-port") == 0) {
            port = value;
        } else if (strcmp(option, "-sni") == 0) {
            sni = value;
        } else if (strcmp(option, "-alpn") == 0) {
            alpn = value;
        }
    }
    
    if (!ctx_name || !host || !port) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create socket and connect
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        Tcl_SetResult(interp, "Failed to create socket", TCL_STATIC);
        return TCL_ERROR;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(host);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        Tcl_SetResult(interp, "Failed to connect", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create SSL connection
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        close(sock);
        Tcl_SetResult(interp, "Failed to create SSL connection", TCL_STATIC);
        return TCL_ERROR;
    }
    
    SSL_set_fd(ssl, sock);
    
    // Set SNI
    if (sni) {
        SSL_set_tlsext_host_name(ssl, sni);
    }
    
    // Set ALPN
    if (alpn) {
        SSL_set_alpn_protos(ssl, (const unsigned char*)alpn, strlen(alpn));
    }
    
    // Perform handshake
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(sock);
        Tcl_SetResult(interp, "SSL handshake failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create handle
    char handle_name[32];
    snprintf(handle_name, sizeof(handle_name), "sslconn%d", ++ssl_connection_count);
    
    TOSSL_SSL_CONN *handle = malloc(sizeof(TOSSL_SSL_CONN));
    handle->ssl = ssl;
    handle->handle_name = strdup(handle_name);
    handle->socket_fd = sock;
    
    // Add to global list
    ssl_connections = realloc(ssl_connections, ssl_connection_count * sizeof(TOSSL_SSL_CONN));
    ssl_connections[ssl_connection_count - 1] = *handle;
    
    Tcl_SetResult(interp, handle_name, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::accept -ctx ctx -socket socket
int SslAcceptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -socket socket");
        return TCL_ERROR;
    }
    
    const char *ctx_name = NULL, *socket_name = NULL;
    
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-ctx") == 0) {
            ctx_name = value;
        } else if (strcmp(option, "-socket") == 0) {
            socket_name = value;
        }
    }
    
    if (!ctx_name || !socket_name) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get socket file descriptor
    int sock = GetFdFromChannel(interp, socket_name);
    if (sock < 0) {
        Tcl_SetResult(interp, "Failed to get socket file descriptor", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create SSL connection
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        Tcl_SetResult(interp, "Failed to create SSL connection", TCL_STATIC);
        return TCL_ERROR;
    }
    
    SSL_set_fd(ssl, sock);
    
    // Perform accept
    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        Tcl_SetResult(interp, "SSL accept failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Create handle
    char handle_name[32];
    snprintf(handle_name, sizeof(handle_name), "sslconn%d", ++ssl_connection_count);
    
    TOSSL_SSL_CONN *handle = malloc(sizeof(TOSSL_SSL_CONN));
    handle->ssl = ssl;
    handle->handle_name = strdup(handle_name);
    handle->socket_fd = sock;
    
    // Add to global list
    ssl_connections = realloc(ssl_connections, ssl_connection_count * sizeof(TOSSL_SSL_CONN));
    ssl_connections[ssl_connection_count - 1] = *handle;
    
    Tcl_SetResult(interp, handle_name, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::read -conn conn ?-length length?
int SslReadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn ?-length length?");
        return TCL_ERROR;
    }
    
    const char *conn_name = NULL;
    int length = 1024; // Default read length
    
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-conn") == 0) {
            conn_name = value;
        } else if (strcmp(option, "-length") == 0) {
            length = atoi(value);
        }
    }
    
    if (!conn_name) {
        Tcl_SetResult(interp, "Missing connection parameter", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Read data
    unsigned char *buffer = malloc(length);
    int bytes_read = SSL_read(ssl, buffer, length);
    
    if (bytes_read <= 0) {
        free(buffer);
        Tcl_SetResult(interp, "SSL read failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewByteArrayObj(buffer, bytes_read);
    Tcl_SetObjResult(interp, result);
    free(buffer);
    
    return TCL_OK;
}

// tossl::ssl::write -conn conn data
int SslWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn data");
        return TCL_ERROR;
    }
    
    const char *conn_name = Tcl_GetString(objv[2]);
    int data_len;
    unsigned char *data = (unsigned char *)Tcl_GetByteArrayFromObj(objv[3], &data_len);
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Write data
    int bytes_written = SSL_write(ssl, data, data_len);
    
    if (bytes_written <= 0) {
        Tcl_SetResult(interp, "SSL write failed", TCL_STATIC);
        return TCL_ERROR;
    }
    
    char result[32];
    snprintf(result, sizeof(result), "%d", bytes_written);
    Tcl_SetResult(interp, result, TCL_VOLATILE);
    
    return TCL_OK;
}

// tossl::ssl::close -conn conn
int SslCloseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    
    const char *conn_name = Tcl_GetString(objv[2]);
    
    // Find and close SSL connection
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            SSL_shutdown(ssl_connections[i].ssl);
            SSL_free(ssl_connections[i].ssl);
            close(ssl_connections[i].socket_fd);
            free(ssl_connections[i].handle_name);
            
            // Remove from list
            for (int j = i; j < ssl_connection_count - 1; j++) {
                ssl_connections[j] = ssl_connections[j + 1];
            }
            ssl_connection_count--;
            
            Tcl_SetResult(interp, "ok", TCL_STATIC);
            return TCL_OK;
        }
    }
    
    Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
    return TCL_ERROR;
}

// tossl::ssl::protocol_version -ctx ctx
int SslProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx");
        return TCL_ERROR;
    }
    
    const char *ctx_name = Tcl_GetString(objv[2]);
    
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get protocol version
    int version = SSL_CTX_get_min_proto_version(ctx);
    const char *version_str = "unknown";
    
    switch (version) {
        case TLS1_VERSION:
            version_str = "TLSv1.0";
            break;
        case TLS1_1_VERSION:
            version_str = "TLSv1.1";
            break;
        case TLS1_2_VERSION:
            version_str = "TLSv1.2";
            break;
        case TLS1_3_VERSION:
            version_str = "TLSv1.3";
            break;
    }
    
    Tcl_SetResult(interp, (char*)version_str, TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::set_protocol_version -ctx ctx -min min -max max
int SslSetProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 7) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -min min -max max");
        return TCL_ERROR;
    }
    
    const char *ctx_name = NULL, *min_version = NULL, *max_version = NULL;
    
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-ctx") == 0) {
            ctx_name = value;
        } else if (strcmp(option, "-min") == 0) {
            min_version = value;
        } else if (strcmp(option, "-max") == 0) {
            max_version = value;
        }
    }
    
    if (!ctx_name || !min_version || !max_version) {
        Tcl_SetResult(interp, "Missing required parameters", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Set protocol versions
    int min_ver = 0, max_ver = 0;
    
    if (strcmp(min_version, "TLSv1.0") == 0) min_ver = TLS1_VERSION;
    else if (strcmp(min_version, "TLSv1.1") == 0) min_ver = TLS1_1_VERSION;
    else if (strcmp(min_version, "TLSv1.2") == 0) min_ver = TLS1_2_VERSION;
    else if (strcmp(min_version, "TLSv1.3") == 0) min_ver = TLS1_3_VERSION;
    
    if (strcmp(max_version, "TLSv1.0") == 0) max_ver = TLS1_VERSION;
    else if (strcmp(max_version, "TLSv1.1") == 0) max_ver = TLS1_1_VERSION;
    else if (strcmp(max_version, "TLSv1.2") == 0) max_ver = TLS1_2_VERSION;
    else if (strcmp(max_version, "TLSv1.3") == 0) max_ver = TLS1_3_VERSION;
    
    if (min_ver && max_ver) {
        SSL_CTX_set_min_proto_version(ctx, min_ver);
        SSL_CTX_set_max_proto_version(ctx, max_ver);
    }
    
    Tcl_SetResult(interp, "ok", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::alpn_selected -conn conn
int SslAlpnSelectedCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    
    const char *conn_name = Tcl_GetString(objv[2]);
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get negotiated ALPN protocol
    const unsigned char *alpn_selected;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(ssl, &alpn_selected, &alpn_len);
    
    if (alpn_len > 0) {
        char *protocol = malloc(alpn_len + 1);
        memcpy(protocol, alpn_selected, alpn_len);
        protocol[alpn_len] = '\0';
        Tcl_SetResult(interp, protocol, TCL_DYNAMIC);
    } else {
        Tcl_SetResult(interp, "", TCL_STATIC);
    }
    
    return TCL_OK;
}

// tossl::ssl::set_alpn_callback -ctx ctx -callback callback
int SslSetAlpnCallbackCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -callback callback");
        return TCL_ERROR;
    }
    
    const char *ctx_name = NULL, *callback_name = NULL;
    
    for (int i = 1; i < objc; i += 2) {
        if (i + 1 >= objc) break;
        
        const char *option = Tcl_GetString(objv[i]);
        const char *value = Tcl_GetString(objv[i + 1]);
        
        if (strcmp(option, "-ctx") == 0) {
            ctx_name = value;
        } else if (strcmp(option, "-callback") == 0) {
            callback_name = value;
        }
    }
    
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Store callback name for later use
    // Note: This is a simplified implementation
    // In a full implementation, you would store the callback and implement the C callback function
    
    TOSSL_SSL_CTX *tctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (ssl_contexts[i].ctx == ctx) {
            tctx = &ssl_contexts[i];
            break;
        }
    }
    if (!tctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    if (tctx->alpn_callback) free(tctx->alpn_callback);
    tctx->alpn_callback = strdup(callback_name);
    SSL_CTX_set_alpn_select_cb(ctx, TosslAlpnSelectCb, NULL);
    
    Tcl_SetResult(interp, "ok", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::socket_info -conn conn
int SslSocketInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    
    const char *conn_name = Tcl_GetString(objv[2]);
    
    // Find SSL connection
    SSL *ssl = NULL;
    int socket_fd = -1;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            socket_fd = ssl_connections[i].socket_fd;
            break;
        }
    }
    
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get socket information
    char info[256];
    snprintf(info, sizeof(info), "fd=%d, ssl=%p, protocol=%s", 
             socket_fd, (void*)ssl, SSL_get_version(ssl));
    
    Tcl_SetResult(interp, info, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::cipher_info -conn conn
int SslCipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) {
        Tcl_SetResult(interp, "No cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    const char *cipher_name = SSL_CIPHER_get_name(cipher);
    const char *proto = SSL_get_version(ssl);
    int pfs = SSL_CIPHER_get_kx_nid(cipher) == NID_kx_ecdhe || SSL_CIPHER_get_kx_nid(cipher) == NID_kx_dhe;
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("cipher", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(cipher_name, -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("protocol", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(proto, -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("pfs", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(pfs ? "yes" : "no", -1));
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::ssl::set_cert_pinning -ctx ctx -pins pins
int SslSetCertPinningCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -pins pins");
        return TCL_ERROR;
    }
    const char *ctx_name = Tcl_GetString(objv[2]);
    // pins parameter is not currently used but kept for future implementation
    // const char *pins = Tcl_GetString(objv[3]);
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    // Store pins for later verification (stub)
    Tcl_SetResult(interp, "ok", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::set_ocsp_stapling -ctx ctx -enable enable
int SslSetOcspStaplingCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-ctx ctx -enable enable");
        return TCL_ERROR;
    }
    const char *ctx_name = Tcl_GetString(objv[2]);
    const char *enable = Tcl_GetString(objv[3]);
    // Find SSL context
    SSL_CTX *ctx = NULL;
    for (int i = 0; i < ssl_context_count; i++) {
        if (strcmp(ssl_contexts[i].handle_name, ctx_name) == 0) {
            ctx = ssl_contexts[i].ctx;
            break;
        }
    }
    if (!ctx) {
        Tcl_SetResult(interp, "SSL context not found", TCL_STATIC);
        return TCL_ERROR;
    }
    // Enable/disable OCSP stapling (stub)
    if (strcmp(enable, "1") == 0 || strcmp(enable, "true") == 0) {
        SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, NULL); // No callback for now
    }
    Tcl_SetResult(interp, "ok", TCL_STATIC);
    return TCL_OK;
}

// tossl::ssl::get_peer_cert -conn conn
int SslGetPeerCertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    // Get peer certificate
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        Tcl_SetResult(interp, "", TCL_STATIC);
        return TCL_OK;
    }
    // Convert certificate to PEM format
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    Tcl_SetResult(interp, bptr->data, TCL_VOLATILE);
    BIO_free(bio);
    X509_free(cert);
    return TCL_OK;
}

// tossl::ssl::verify_peer -conn conn
int SslVerifyPeerCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    // Verify peer certificate
    long result = SSL_get_verify_result(ssl);
    const char *result_str = X509_verify_cert_error_string(result);
    char response[256];
    snprintf(response, sizeof(response), "%ld:%s", result, result_str);
    Tcl_SetResult(interp, response, TCL_VOLATILE);
    return TCL_OK;
}

// tossl::ssl::check_cert_status -conn conn
int SslCheckCertStatusCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get peer certificate
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        Tcl_SetResult(interp, "no_cert", TCL_STATIC);
        return TCL_OK;
    }
    
    // Check certificate status
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Check if certificate is expired
    ASN1_TIME *not_after = X509_getm_notAfter(cert);
    ASN1_TIME *not_before = X509_getm_notBefore(cert);
    time_t now = time(NULL);
    
    int is_expired = X509_cmp_time(not_after, &now) < 0;
    int is_not_yet_valid = X509_cmp_time(not_before, &now) > 0;
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("expired", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(is_expired ? "yes" : "no", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("not_yet_valid", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(is_not_yet_valid ? "yes" : "no", -1));
    
    // Check OCSP stapling
    const unsigned char *ocsp_response = NULL;
    int ocsp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_response);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("ocsp_stapled", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(ocsp_len > 0 ? "yes" : "no", -1));
    
    // Check certificate transparency
    STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    int has_ct = 0;
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
            if (OBJ_obj2nid(obj) == NID_ct_precert_scts) {
                has_ct = 1;
                break;
            }
        }
    }
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("certificate_transparency", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(has_ct ? "yes" : "no", -1));
    
    X509_free(cert);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::ssl::check_pfs -conn conn
int SslCheckPfsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get cipher information
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) {
        Tcl_SetResult(interp, "No cipher", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    
    // Check key exchange algorithm
    int kx_nid = SSL_CIPHER_get_kx_nid(cipher);
    int has_pfs = (kx_nid == NID_kx_ecdhe || kx_nid == NID_kx_dhe);
    
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("pfs", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(has_pfs ? "yes" : "no", -1));
    
    // Get key exchange name
    const char *kx_name = SSL_CIPHER_get_kx_nid(cipher) == NID_kx_ecdhe ? "ECDHE" :
                          SSL_CIPHER_get_kx_nid(cipher) == NID_kx_dhe ? "DHE" : "RSA";
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("key_exchange", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(kx_name, -1));
    
    // Check cipher strength
    int cipher_bits = SSL_CIPHER_get_bits(cipher, NULL);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("cipher_bits", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewIntObj(cipher_bits));
    
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// tossl::ssl::verify_cert_pinning -conn conn -pins pins
int SslVerifyCertPinningCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "-conn conn -pins pins");
        return TCL_ERROR;
    }
    const char *conn_name = Tcl_GetString(objv[2]);
    const char *pins = Tcl_GetString(objv[3]);
    
    // Find SSL connection
    SSL *ssl = NULL;
    for (int i = 0; i < ssl_connection_count; i++) {
        if (strcmp(ssl_connections[i].handle_name, conn_name) == 0) {
            ssl = ssl_connections[i].ssl;
            break;
        }
    }
    if (!ssl) {
        Tcl_SetResult(interp, "SSL connection not found", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Get peer certificate
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        Tcl_SetResult(interp, "no_cert", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Calculate certificate fingerprint (SHA-256)
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int fingerprint_len;
    // Use the certificate's DER encoding for fingerprint
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len > 0) {
        EVP_Digest(der, der_len, fingerprint, &fingerprint_len, EVP_sha256(), NULL);
        OPENSSL_free(der);
    } else {
        X509_free(cert);
        Tcl_SetResult(interp, "Failed to encode certificate", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Convert to base64
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_write(bio, fingerprint, fingerprint_len);
    BIO_flush(bio);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    char *fingerprint_b64 = malloc(bptr->length + 1);
    memcpy(fingerprint_b64, bptr->data, bptr->length);
    fingerprint_b64[bptr->length] = '\0';
    
    // Check if fingerprint matches any pin
    int pin_match = 0;
    char *pins_copy = strdup(pins);
    char *token = strtok(pins_copy, " ");
    while (token) {
        if (strcmp(token, fingerprint_b64) == 0) {
            pin_match = 1;
            break;
        }
        token = strtok(NULL, " ");
    }
    
    free(pins_copy);
    free(fingerprint_b64);
    BIO_free_all(bio);
    X509_free(cert);
    
    Tcl_Obj *result = Tcl_NewListObj(0, NULL);
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj("pin_match", -1));
    Tcl_ListObjAppendElement(interp, result, Tcl_NewStringObj(pin_match ? "yes" : "no", -1));
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

// Helper: Find TOSSL_SSL_CTX by SSL_CTX*
static TOSSL_SSL_CTX *FindTosslCtxBySslCtx(SSL_CTX *ctx) {
    for (int i = 0; i < ssl_context_count; i++) {
        if (ssl_contexts[i].ctx == ctx) return &ssl_contexts[i];
    }
    return NULL;
}
// ALPN selection callback for OpenSSL
static int TosslAlpnSelectCb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                             const unsigned char *in, unsigned int inlen, void *arg) {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    TOSSL_SSL_CTX *tctx = FindTosslCtxBySslCtx(ctx);
    if (!tctx || !tctx->alpn_callback || !tctx->interp) return SSL_TLSEXT_ERR_NOACK;
    // Build Tcl list of protocols
    Tcl_Obj *protoList = Tcl_NewListObj(0, NULL);
    unsigned int i = 0;
    while (i < inlen) {
        int len = in[i++];
        Tcl_ListObjAppendElement(tctx->interp, protoList, Tcl_NewStringObj((const char*)(in + i), len));
        i += len;
    }
    // Call Tcl callback: callback protocolList
    Tcl_Obj *cb = Tcl_NewStringObj(tctx->alpn_callback, -1);
    Tcl_Obj *args[2] = {cb, protoList};
    Tcl_Obj *result = NULL;
    int code = Tcl_EvalObjv(tctx->interp, 2, args, TCL_EVAL_GLOBAL);
    if (code != TCL_OK) return SSL_TLSEXT_ERR_NOACK;
    result = Tcl_GetObjResult(tctx->interp);
    // Get selected protocol
    int selectedLen = 0;
    const char *selected = Tcl_GetStringFromObj(result, &selectedLen);
    // Find and set selected protocol in offered list
    i = 0;
    while (i < inlen) {
        int len = in[i];
        if (len == selectedLen && memcmp(selected, in + i + 1, len) == 0) {
            *out = in + i + 1;
            *outlen = len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + len;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

// Register SSL commands
void TosslRegisterSslCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tossl::ssl::context", SslContextCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::connect", SslConnectCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::accept", SslAcceptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::read", SslReadCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::write", SslWriteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::close", SslCloseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::protocol_version", SslProtocolVersionCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::set_protocol_version", SslSetProtocolVersionCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::alpn_selected", SslAlpnSelectedCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::set_alpn_callback", SslSetAlpnCallbackCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::socket_info", SslSocketInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::cipher_info", SslCipherInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::set_cert_pinning", SslSetCertPinningCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::set_ocsp_stapling", SslSetOcspStaplingCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::get_peer_cert", SslGetPeerCertCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::verify_peer", SslVerifyPeerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::check_cert_status", SslCheckCertStatusCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::check_pfs", SslCheckPfsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ssl::verify_cert_pinning", SslVerifyCertPinningCmd, NULL, NULL);
} 