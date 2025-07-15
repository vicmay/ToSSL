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
 *
 * This file incorporates work from the OpenSSL project,
 * developed by Eric Young and Tim Hudson.
 */

#ifndef TOSSL_H
#define TOSSL_H

#include <tcl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/macros.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/provider.h>
#include <openssl/ocsp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/ssl.h>

// Include modern OpenSSL 3.x API wrappers
#include "tossl_modern.h"

// KeyUsage bitmask values (OpenSSL defines these in x509v3.h, but for clarity):
#ifndef KU_DIGITAL_SIGNATURE
#define KU_DIGITAL_SIGNATURE    0x80
#define KU_NON_REPUDIATION     0x40
#define KU_KEY_ENCIPHERMENT    0x20
#define KU_DATA_ENCIPHERMENT   0x10
#define KU_KEY_AGREEMENT       0x08
#define KU_KEY_CERT_SIGN       0x04
#define KU_CRL_SIGN            0x02
#define KU_ENCIPHER_ONLY       0x01
#define KU_DECIPHER_ONLY       0x8000
#endif

// Common utility functions
void bin2hex(const unsigned char *in, int len, char *out);

// SSL/TLS handle structures
typedef struct SslContextHandle {
    SSL_CTX *ctx;
    char *handleName;
} SslContextHandle;

typedef struct SslSocketHandle {
    SSL *ssl;
    char *handleName;
    char *chanName;
    SslContextHandle *ctxHandle;
} SslSocketHandle;

typedef struct SslSessionHandle {
    SSL_SESSION *session;
    char *handleName;
} SslSessionHandle;

// Function prototypes for all command functions
// Core crypto functions
int HmacCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Base64EncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Base64DecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Base64UrlEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Base64UrlDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int HexEncodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int HexDecodeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DigestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DigestStreamCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DigestCompareCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DigestListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RandBytesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RandKeyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RandIvCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pbkdf2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int ScryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Argon2Cmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CipherListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Key management functions
int KeyParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyGetPubCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyConvertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyFingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// RSA functions
int RsaGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int RsaComponentsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// DSA functions
int DsaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DsaVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DsaGenerateParamsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int DsaValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// EC functions
int EcListCurvesCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcVerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcPointAddCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcPointMultiplyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int EcComponentsCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Ed25519/X25519 functions
int Ed25519GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Ed25519SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Ed25519VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X25519GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X25519DeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// X.509 functions
int X509ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509ModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509ValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509FingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X509TimeValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// CSR functions
int CsrCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CsrParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CsrValidateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CsrFingerprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CsrModifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// CA functions
int CaGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CaSignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// CRL functions
int CrlCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int CrlParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// OCSP functions
int OcspCreateRequestCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int OcspParseResponseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// PKCS functions
int Pkcs7EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs7DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs7InfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs7VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs7SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs12ParseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Pkcs12CreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// SSL/TLS functions
void TosslRegisterSslCommands(Tcl_Interp *interp);
int SslContextCreateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslContextFreeCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslConnectCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslAcceptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslReadCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslWriteCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslCloseCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslSessionExportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslSessionImportCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslSocketCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslSessionInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslPeerCertCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int SslSetProtocolVersionCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Legacy cipher functions
int LegacyEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int LegacyDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int LegacyCipherListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int LegacyCipherInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int LegacyKeyGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int LegacyIvGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// PBE functions
int PbeEncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int PbeDecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int PbeSaltGenCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int PbeKeyDeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int PbeAlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Key wrapping functions
int KeyWrapCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyUnwrapCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KekGenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KekAlgorithmListCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int KeyWrapInfoCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// SM2 functions
int Sm2GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Sm2SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Sm2VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Sm2EncryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Sm2DecryptCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Ed448 functions
int Ed448GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Ed448SignCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int Ed448VerifyCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// X448 functions
int X448GenerateCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int X448DeriveCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);



// JWK functions
int JwkExtractCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int JwkThumbprintCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

// Utility functions
int GetFdFromChannel(Tcl_Interp *interp, const char *chanName);

#endif // TOSSL_H 