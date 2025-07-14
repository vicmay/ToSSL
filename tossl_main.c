#include "tossl.h"

// Global variables for SSL/TLS handles
static SslContextHandle *ssl_contexts = NULL;
static SslSocketHandle *ssl_sockets = NULL;
static SslSessionHandle *ssl_sessions = NULL;
static int ssl_context_count = 0;
static int ssl_socket_count = 0;
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
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create namespace
    Tcl_Namespace *ns = Tcl_CreateNamespace(interp, "tossl", NULL, NULL);
    if (!ns) {
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
    Tcl_CreateObjCommand(interp, "tossl::x509::create", X509CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::validate", X509ValidateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::fingerprint", X509FingerprintCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::verify", X509VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "tossl::x509::time_validate", X509TimeValidateCmd, NULL, NULL);
    
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
    return TCL_OK;
} 