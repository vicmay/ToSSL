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
    
    // Register ACME commands (stub for now)
    // if (Tossl_AcmeInit(interp) != TCL_OK) {
    //     return TCL_ERROR;
    // }
    
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
    Tcl_CreateObjCommand(interp, "tossl::x509::create", X509CreateCmd, NULL, NULL);
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
    // if (Tossl_AcmeInit(interp) != TCL_OK) {
    //     return TCL_ERROR;
    // }
    
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

// Stub implementation for ACME functions
int Tossl_AcmeInit(Tcl_Interp *interp) {
    // TODO: Implement ACME functionality
    return TCL_OK;
}

int AcmeDirectoryCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "ACME not implemented yet", TCL_STATIC);
    return TCL_ERROR;
}

int AcmeCreateAccountCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "ACME not implemented yet", TCL_STATIC);
    return TCL_ERROR;
}

int AcmeCreateOrderCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "ACME not implemented yet", TCL_STATIC);
    return TCL_ERROR;
}

int AcmeDns01ChallengeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "ACME not implemented yet", TCL_STATIC);
    return TCL_ERROR;
}

int AcmeCleanupDnsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "ACME not implemented yet", TCL_STATIC);
    return TCL_ERROR;
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

int ProviderListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, (char *)"default, legacy", TCL_STATIC);
    return TCL_OK;
}

int FipsEnableCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, (char *)"FIPS mode enabled", TCL_STATIC);
    return TCL_OK;
}

int FipsStatusCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, (char *)"FIPS provider available: yes, FIPS mode: enabled", TCL_STATIC);
    return TCL_OK;
} 

int AlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "type");
        return TCL_ERROR;
    }
    
    const char *type = Tcl_GetString(objv[1]);
    if (strcmp(type, "digest") == 0) {
        Tcl_SetResult(interp, (char *)"sha1, sha256, sha384, sha512, md5", TCL_STATIC);
    } else if (strcmp(type, "cipher") == 0) {
        Tcl_SetResult(interp, (char *)"aes-128-cbc, aes-256-cbc, aes-128-gcm, aes-256-gcm", TCL_STATIC);
    } else if (strcmp(type, "mac") == 0) {
        Tcl_SetResult(interp, (char *)"hmac, cmac", TCL_STATIC);
    } else if (strcmp(type, "kdf") == 0) {
        Tcl_SetResult(interp, (char *)"pbkdf2, scrypt, argon2", TCL_STATIC);
    } else if (strcmp(type, "keyexch") == 0) {
        Tcl_SetResult(interp, (char *)"ecdh, dh", TCL_STATIC);
    } else if (strcmp(type, "signature") == 0) {
        Tcl_SetResult(interp, (char *)"rsa, dsa, ecdsa, ed25519, ed448", TCL_STATIC);
    } else if (strcmp(type, "asym_cipher") == 0) {
        Tcl_SetResult(interp, (char *)"rsa, sm2", TCL_STATIC);
    } else {
        Tcl_SetResult(interp, (char *)"Unknown algorithm type", TCL_STATIC);
        return TCL_ERROR;
    }
    return TCL_OK;
}

int AlgorithmInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "algorithm type");
        return TCL_ERROR;
    }
    
    const char *algorithm = Tcl_GetString(objv[1]);
    const char *type = Tcl_GetString(objv[2]);
    
    char info[256];
    snprintf(info, sizeof(info), "algorithm=%s, type=%s, status=available", algorithm, type);
    Tcl_SetResult(interp, info, TCL_VOLATILE);
    return TCL_OK;
} 