#include "tossl.h"

// Global variables for SSL/TLS handles (unused in current implementation)
#ifdef __GNUC__
__attribute__((unused))
#endif
static SslContextHandle *ssl_contexts = NULL;
#ifdef __GNUC__
__attribute__((unused))
#endif
static SslSocketHandle *ssl_sockets = NULL;
#ifdef __GNUC__
__attribute__((unused))
#endif
static SslSessionHandle *ssl_sessions = NULL;
#ifdef __GNUC__
__attribute__((unused))
#endif
static int ssl_context_count = 0;
#ifdef __GNUC__
__attribute__((unused))
#endif
static int ssl_socket_count = 0;
#ifdef __GNUC__
__attribute__((unused))
#endif
static int ssl_session_count = 0;

// Utility function to get file descriptor from Tcl channel
int GetFdFromChannel(Tcl_Interp *interp, const char *chanName) {
    Tcl_Channel chan = Tcl_GetChannel(interp, chanName, NULL);
    if (!chan) {
        return -1;
    }
    int fd;
    if (Tcl_GetChannelHandle(chan, TCL_READABLE, (ClientData*)&fd) != TCL_OK) {
        return -1;
    }
    return fd;
}

// Main initialization function
int Tossl_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == NULL) {
        return TCL_ERROR;
    }
    
    // Initialize OpenSSL 3.x
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    
    // Load default provider
    OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        Tcl_SetResult(interp, "Failed to load OpenSSL default provider", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Load legacy provider for backward compatibility
    OSSL_PROVIDER *legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) {
        // Legacy provider is optional, just log a warning
        // Tcl_SetResult(interp, "Warning: Failed to load OpenSSL legacy provider", TCL_STATIC);
    }
    
    // Create namespace
    Tcl_Namespace *ns = Tcl_CreateNamespace(interp, "tossl", NULL, NULL);
    if (!ns) {
        return TCL_ERROR;
    }
    // Register HTTP client commands
    if (Tossl_HttpInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Register JSON utilities
    if (Tossl_JsonInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Register ACME commands
    if (Tossl_AcmeInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Register implemented commands only
    Tcl_CreateObjCommand(interp, "tossl::hmac", HmacCmd, NULL, NULL);
    
    // Core crypto commands
    Tcl_CreateObjCommand(interp, "tossl::base64::encode", Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::base64::decode", Base64DecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::base64url::encode", Base64UrlEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::base64url::decode", Base64UrlDecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::hex::encode", HexEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::hex::decode", HexDecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest", DigestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::stream", DigestStreamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::compare", DigestCompareCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::digest::list", DigestListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rand::bytes", RandBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rand::key", RandKeyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rand::iv", RandIvCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::randbytes", RandBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pbkdf2", Pbkdf2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::scrypt", ScryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::argon2", Argon2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::pbkdf2", Pbkdf2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::scrypt", ScryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::kdf::argon2", Argon2Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::cipher::info", CipherInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::cipher::list", CipherListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::encrypt", EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::decrypt", DecryptCmd, NULL, NULL);
    
    // Key management commands
    Tcl_CreateObjCommand(interp, "tossl::key::parse", KeyParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::write", KeyWriteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::generate", KeyGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::getpub", KeyGetPubCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::convert", KeyConvertCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::key::fingerprint", KeyFingerprintCmd, NULL, NULL);
    
    // RSA commands
    Tcl_CreateObjCommand(interp, "tossl::rsa::generate", RsaGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::encrypt", RsaEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::decrypt", RsaDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::sign", RsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::verify", RsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::validate", RsaValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::rsa::components", RsaComponentsCmd, NULL, NULL);
    
    // DSA commands
    Tcl_CreateObjCommand(interp, "tossl::dsa::sign", DsaSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::dsa::verify", DsaVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::dsa::generate_params", DsaGenerateParamsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::dsa::validate", DsaValidateCmd, NULL, NULL);
    
    // EC commands
    Tcl_CreateObjCommand(interp, "tossl::ec::list_curves", EcListCurvesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::validate", EcValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::sign", EcSignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::verify", EcVerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::point_add", EcPointAddCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::point_multiply", EcPointMultiplyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ec::components", EcComponentsCmd, NULL, NULL);
    
    // Ed25519/X25519 commands
    Tcl_CreateObjCommand(interp, "tossl::ed25519::generate", Ed25519GenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ed25519::sign", Ed25519SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ed25519::verify", Ed25519VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x25519::generate", X25519GenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x25519::derive", X25519DeriveCmd, NULL, NULL);
    
    // X.509 commands
    Tcl_CreateObjCommand(interp, "tossl::x509::parse", X509ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::modify", X509ModifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::create", X509CreateCmd, NULL, NULL); // Register modern implementation
    Tcl_CreateObjCommand(interp, "tossl::x509::validate", X509ValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::fingerprint", X509FingerprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::verify", X509VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::time_validate", X509TimeValidateCmd, NULL, NULL);
    // Tcl_CreateObjCommand(interp, "tossl::x509::ct_extensions", X509CtExtensionsCmd, NULL, NULL);
    
    // Legacy cipher commands
    Tcl_CreateObjCommand(interp, "tossl::legacy::encrypt", LegacyEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::legacy::decrypt", LegacyDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::legacy::list", LegacyCipherListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::legacy::info", LegacyCipherInfoCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::legacy::keygen", LegacyKeyGenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::legacy::ivgen", LegacyIvGenCmd, NULL, NULL);
    
    // PBE commands
    Tcl_CreateObjCommand(interp, "tossl::pbe::encrypt", PbeEncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pbe::decrypt", PbeDecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pbe::saltgen", PbeSaltGenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pbe::keyderive", PbeKeyDeriveCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pbe::algorithms", PbeAlgorithmListCmd, NULL, NULL);
    
    // Key wrapping commands
    Tcl_CreateObjCommand(interp, "tossl::keywrap::wrap", KeyWrapCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::keywrap::unwrap", KeyUnwrapCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::keywrap::kekgen", KekGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::keywrap::algorithms", KekAlgorithmListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::keywrap::info", KeyWrapInfoCmd, NULL, NULL);
    
    // SM2 commands
    Tcl_CreateObjCommand(interp, "tossl::sm2::generate", Sm2GenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::sm2::sign", Sm2SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::sm2::verify", Sm2VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::sm2::encrypt", Sm2EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::sm2::decrypt", Sm2DecryptCmd, NULL, NULL);
    
    // Ed448 commands
    Tcl_CreateObjCommand(interp, "tossl::ed448::generate", Ed448GenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ed448::sign", Ed448SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ed448::verify", Ed448VerifyCmd, NULL, NULL);
    
    // X448 commands
    Tcl_CreateObjCommand(interp, "tossl::x448::generate", X448GenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x448::derive", X448DeriveCmd, NULL, NULL);
    
    // CSR commands
    Tcl_CreateObjCommand(interp, "tossl::csr::create", CsrCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::parse", CsrParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::validate", CsrValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::fingerprint", CsrFingerprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::csr::modify", CsrModifyCmd, NULL, NULL);

    // PKCS#7 commands
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::encrypt", Pkcs7EncryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::decrypt", Pkcs7DecryptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::sign", Pkcs7SignCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::verify", Pkcs7VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs7::info", Pkcs7InfoCmd, NULL, NULL);

    // PKCS#12 commands
    Tcl_CreateObjCommand(interp, "tossl::pkcs12::create", Pkcs12CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::pkcs12::parse", Pkcs12ParseCmd, NULL, NULL);

    // OCSP commands
    Tcl_CreateObjCommand(interp, "tossl::ocsp::create_request", OcspCreateRequestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ocsp::parse_response", OcspParseResponseCmd, NULL, NULL);

    // CRL commands
    Tcl_CreateObjCommand(interp, "tossl::crl::create", CrlCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::crl::parse", CrlParseCmd, NULL, NULL);

    // CA commands
    Tcl_CreateObjCommand(interp, "tossl::ca::generate", CaGenerateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::ca::sign", CaSignCmd, NULL, NULL);
    
    // Provide the package to Tcl
    Tcl_PkgProvide(interp, "tossl", "0.1");
    TosslRegisterSslCommands(interp);
    
    // Initialize HTTP module
    if (Tossl_HttpInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Initialize ACME module
    if (Tossl_AcmeInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Initialize JWT module
    if (Tossl_JwtInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Initialize OAuth2 module
    if (Tossl_Oauth2Init(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Initialize OIDC module
    if (Tossl_OidcInit(interp) != TCL_OK) {
        return TCL_ERROR;
    }
    
    // Provider management commands
    Tcl_CreateObjCommand(interp, "tossl::provider::load", ProviderLoadCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::provider::unload", ProviderUnloadCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::provider::list", ProviderListCmd, NULL, NULL);
    // FIPS support commands
    Tcl_CreateObjCommand(interp, "tossl::fips::enable", FipsEnableCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::fips::status", FipsStatusCmd, NULL, NULL);
    
    // Algorithm discovery commands
    Tcl_CreateObjCommand(interp, "tossl::algorithm::list", AlgorithmListCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::algorithm::info", AlgorithmInfoCmd, NULL, NULL);
    
    // URL encoding/decoding commands
    Tcl_CreateObjCommand(interp, "tossl::url::encode", UrlEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::url::decode", UrlDecodeCmd, NULL, NULL);
    
    // Time conversion/comparison commands
    Tcl_CreateObjCommand(interp, "tossl::time::convert", TimeConvertCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::time::compare", TimeCompareCmd, NULL, NULL);
    
    // Random number testing commands
    Tcl_CreateObjCommand(interp, "tossl::rand::test", RandomTestCmd, NULL, NULL);
    
    // Key/cert/cipher analysis commands
    Tcl_CreateObjCommand(interp, "tossl::key::analyze", KeyAnalysisCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::cipher::analyze", CipherAnalysisCmd, NULL, NULL);
    
    // Signature validation command
    Tcl_CreateObjCommand(interp, "tossl::signature::validate", SignatureValidateCmd, NULL, NULL);
    
    // ASN.1 commands
    Tcl_CreateObjCommand(interp, "tossl::asn1::parse", Asn1ParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::asn1::encode", Asn1EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::asn1::oid_to_text", Asn1OidToTextCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::asn1::text_to_oid", Asn1TextToOidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::asn1::sequence_create", Asn1SequenceCreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::asn1::set_create", Asn1SetCreateCmd, NULL, NULL);
    
    // Hardware acceleration detection commands
    Tcl_CreateObjCommand(interp, "tossl::hardware::detect", Tossl_HardwareAccelCmd, NULL, NULL);
    
    // Benchmarking commands
    Tcl_CreateObjCommand(interp, "tossl::benchmark", Tossl_BenchmarkCmd, NULL, NULL);
    
    // Side-channel protection commands
    Tcl_CreateObjCommand(interp, "tossl::sidechannel::protect", Tossl_SideChannelProtectCmd, NULL, NULL);
    
    // Cryptographic logging commands
    Tcl_CreateObjCommand(interp, "tossl::cryptolog", Tossl_CryptoLogCmd, NULL, NULL);
    
    // Certificate status checking commands
    Tcl_CreateObjCommand(interp, "tossl::cert::status", Tossl_CertStatusCmd, NULL, NULL);
    
    // Perfect forward secrecy testing commands
    Tcl_CreateObjCommand(interp, "tossl::pfs::test", Tossl_PfsTestCmd, NULL, NULL);
    
    return TCL_OK;
}



int ProviderLoadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "name");
        return TCL_ERROR;
    }
    const char *name = Tcl_GetString(objv[1]);
    OSSL_PROVIDER *prov = modern_load_provider(name);
    if (!prov) {
        Tcl_SetResult(interp, "Failed to load provider", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, (char *)"ok", TCL_STATIC);
    return TCL_OK;
}

int ProviderUnloadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "name");
        return TCL_ERROR;
    }
    // For now, just call unload on a new handle (not tracked)
    const char *name = Tcl_GetString(objv[1]);
    OSSL_PROVIDER *prov = modern_load_provider(name);
    if (!prov) {
        Tcl_SetResult(interp, "Provider not loaded", TCL_STATIC);
        return TCL_ERROR;
    }
    modern_unload_provider(prov);
    Tcl_SetResult(interp, (char *)"ok", TCL_STATIC);
    return TCL_OK;
}

int FipsEnableCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    if (!modern_enable_fips()) {
        Tcl_SetResult(interp, (char *)"Failed to enable FIPS mode", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, (char *)"FIPS mode enabled", TCL_STATIC);
    return TCL_OK;
}

int FipsStatusCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, "");
        return TCL_ERROR;
    }
    char *status_info = NULL;
    if (!modern_check_fips_status(&status_info)) {
        Tcl_SetResult(interp, (char *)"FIPS status check failed", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, status_info, TCL_VOLATILE);
    free(status_info);
    return TCL_OK;
} 

// Context structure for algorithm enumeration
struct AlgorithmListCtx {
    Tcl_Interp *interp;
    Tcl_Obj *list;
    const char *type;
};

// Callback for digest enumeration
static void digest_list_cb(EVP_MD *md, void *arg) {
    struct AlgorithmListCtx *ctx = (struct AlgorithmListCtx *)arg;
    if (strcmp(ctx->type, "digest") == 0) {
        const char *name = EVP_MD_get0_name(md);
        if (name) {
            // Check for duplicates
            int list_len;
            Tcl_ListObjLength(ctx->interp, ctx->list, &list_len);
            int found = 0;
            
            for (int i = 0; i < list_len; i++) {
                Tcl_Obj *element;
                Tcl_ListObjIndex(ctx->interp, ctx->list, i, &element);
                const char *existing_name = Tcl_GetString(element);
                if (strcmp(name, existing_name) == 0) {
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                Tcl_ListObjAppendElement(ctx->interp, ctx->list, Tcl_NewStringObj(name, -1));
            }
        }
    }
}

// Callback for cipher enumeration
static void cipher_list_cb(EVP_CIPHER *cipher, void *arg) {
    struct AlgorithmListCtx *ctx = (struct AlgorithmListCtx *)arg;
    if (strcmp(ctx->type, "cipher") == 0) {
        const char *name = EVP_CIPHER_get0_name(cipher);
        if (name) {
            // Check for duplicates
            int list_len;
            Tcl_ListObjLength(ctx->interp, ctx->list, &list_len);
            int found = 0;
            
            for (int i = 0; i < list_len; i++) {
                Tcl_Obj *element;
                Tcl_ListObjIndex(ctx->interp, ctx->list, i, &element);
                const char *existing_name = Tcl_GetString(element);
                if (strcmp(name, existing_name) == 0) {
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                Tcl_ListObjAppendElement(ctx->interp, ctx->list, Tcl_NewStringObj(name, -1));
            }
        }
    }
}

int AlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "type");
        return TCL_ERROR;
    }
    
    const char *type = Tcl_GetString(objv[1]);
    
    // Validate algorithm type
    if (strcmp(type, "digest") != 0 && strcmp(type, "cipher") != 0 && 
        strcmp(type, "mac") != 0 && strcmp(type, "kdf") != 0 && 
        strcmp(type, "keyexch") != 0 && strcmp(type, "signature") != 0 && 
        strcmp(type, "asym_cipher") != 0) {
        Tcl_SetResult(interp, "Unknown algorithm type", TCL_STATIC);
        return TCL_ERROR;
    }
    
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    
    if (strcmp(type, "digest") == 0) {
        // Use OpenSSL's digest enumeration
        struct AlgorithmListCtx ctx = { interp, list, type };
        EVP_MD_do_all_provided(NULL, digest_list_cb, &ctx);
    } else if (strcmp(type, "cipher") == 0) {
        // Use OpenSSL's cipher enumeration
        struct AlgorithmListCtx ctx = { interp, list, type };
        EVP_CIPHER_do_all_provided(NULL, cipher_list_cb, &ctx);
    } else {
        // For other types, return known algorithms (these don't have direct OpenSSL enumeration APIs)
        if (strcmp(type, "mac") == 0) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("hmac", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("cmac", -1));
        } else if (strcmp(type, "kdf") == 0) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("pbkdf2", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("scrypt", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("argon2", -1));
        } else if (strcmp(type, "keyexch") == 0) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("ecdh", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("dh", -1));
        } else if (strcmp(type, "signature") == 0) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("rsa", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("dsa", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("ecdsa", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("ed25519", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("ed448", -1));
        } else if (strcmp(type, "asym_cipher") == 0) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("rsa", -1));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("sm2", -1));
        }
    }
    
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

int AlgorithmInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm type");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *type = Tcl_GetString(objv[2]);
    
    // Validate algorithm type
    if (strcmp(type, "digest") != 0 && strcmp(type, "cipher") != 0 && 
        strcmp(type, "mac") != 0 && strcmp(type, "kdf") != 0 && 
        strcmp(type, "keyexch") != 0 && strcmp(type, "signature") != 0 && 
        strcmp(type, "asym_cipher") != 0) {
        Tcl_SetResult(interp, "Invalid algorithm type", TCL_STATIC);
        return TCL_ERROR;
    }
    
    // Check algorithm availability based on type
    int available = 0;
    const char *status = "unavailable";
    
    if (strcmp(type, "digest") == 0) {
        EVP_MD *md = EVP_MD_fetch(NULL, algorithm, NULL);
        if (md) {
            available = 1;
            EVP_MD_free(md);
        }
    } else if (strcmp(type, "cipher") == 0) {
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, algorithm, NULL);
        if (cipher) {
            available = 1;
            EVP_CIPHER_free(cipher);
        }
    } else if (strcmp(type, "mac") == 0) {
        // For MAC algorithms, check if the underlying digest is available
        if (strcmp(algorithm, "hmac") == 0) {
            // HMAC is always available if we have any digest
            EVP_MD *md = EVP_MD_fetch(NULL, "sha256", NULL);
            if (md) {
                available = 1;
                EVP_MD_free(md);
            }
        } else if (strcmp(algorithm, "cmac") == 0) {
            // CMAC requires a block cipher
            EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "aes-128-cbc", NULL);
            if (cipher) {
                available = 1;
                EVP_CIPHER_free(cipher);
            }
        }
    } else if (strcmp(type, "kdf") == 0) {
        // For KDF algorithms, check availability
        if (strcmp(algorithm, "pbkdf2") == 0) {
            // PBKDF2 is always available if we have any digest
            EVP_MD *md = EVP_MD_fetch(NULL, "sha256", NULL);
            if (md) {
                available = 1;
                EVP_MD_free(md);
            }
        } else if (strcmp(algorithm, "scrypt") == 0) {
            // Scrypt availability depends on OpenSSL build
            available = 1; // Assume available for now
        } else if (strcmp(algorithm, "argon2") == 0) {
            // Argon2 availability depends on OpenSSL build
            available = 1; // Assume available for now
        }
    } else if (strcmp(type, "keyexch") == 0) {
        // For key exchange algorithms
        if (strcmp(algorithm, "ecdh") == 0) {
            // ECDH requires EC support
            EVP_PKEY *pkey = EVP_PKEY_new();
            if (pkey) {
                EVP_PKEY_free(pkey);
                available = 1;
            }
        } else if (strcmp(algorithm, "dh") == 0) {
            // DH availability
            available = 1; // Assume available
        }
    } else if (strcmp(type, "signature") == 0) {
        // For signature algorithms
        if (strcmp(algorithm, "rsa") == 0 || strcmp(algorithm, "dsa") == 0 || 
            strcmp(algorithm, "ecdsa") == 0 || strcmp(algorithm, "ed25519") == 0 || 
            strcmp(algorithm, "ed448") == 0) {
            available = 1; // Assume available
        }
    } else if (strcmp(type, "asym_cipher") == 0) {
        // For asymmetric cipher algorithms
        if (strcmp(algorithm, "rsa") == 0 || strcmp(algorithm, "sm2") == 0) {
            available = 1; // Assume available
        }
    }
    
    if (available) {
        status = "available";
    }
    
    char info[256];
    snprintf(info, sizeof(info), "algorithm=%s, type=%s, status=%s", algorithm, type, status);
    Tcl_SetResult(interp, info, TCL_VOLATILE);
    return TCL_OK;
} 
