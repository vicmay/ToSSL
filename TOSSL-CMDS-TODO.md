# TOSSL Commands - Test and Documentation Progress Tracker

This document tracks the progress of creating tests and documentation for all TOSSL commands.

## Task Instructions

For each TOSSL command, the following tasks must be completed:

**After each implementation, always run:**
    git add .; git commit -m "Update tests/docs for <command>"

1. **Create Test File**: Create a comprehensive test file in the `tests/` directory
   - Naming convention: `test_<command_name>.tcl`
   - Test basic functionality, error handling, edge cases, and performance
   - Include security validation where applicable

2. **Create Documentation**: Create comprehensive documentation in the `doc/` directory
   - Naming convention: `<command_name>.md`
   - Include overview, syntax, examples, error handling, and security considerations
   - Provide best practices and usage guidelines

3. **Run and Fix Tests**: Execute each test file and fix any errors
   - Run: `tclsh tests/test_<command_name>.tcl`
   - Debug and fix any failing tests
   - Ensure all tests pass before marking as complete

4. **Update Progress**: Mark completed commands in this tracking table
   - Update test status to ✅ when test file is created and passes
   - Update documentation status to ✅ when documentation is complete
   - Update progress summary counts

## Progress Summary
- **Total Commands**: 190
- **Tests Created**: 152/190 (80.0%)
- **Documentation Created**: 152/190 (80.0%)

## Command Status Tracking

| Command | Test Status | Test File | Doc Status | Doc File | Notes |
|---------|-------------|-----------|------------|----------|-------|
| `::tossl::randbytes` | ✅ | tests/test_randbytes.tcl | ✅ | doc/randbytes.md | |
| `::tossl::digest` | ✅ | tests/test_digest.tcl | ✅ | doc/digest.md | |
| `::tossl::encrypt` | ✅ | tests/test_encrypt.tcl | ✅ | doc/encrypt.md | |
| `::tossl::argon2` | ✅ | tests/test_argon2.tcl | ✅ | doc/argon2.md | |
| `::tossl::scrypt` | ✅ | tests/test_scrypt.tcl | ✅ | doc/scrypt.md | |
| `::tossl::pbkdf2` | ✅ | tests/test_pbkdf2.tcl | ✅ | doc/pbkdf2.md | |
| `::tossl::hmac` | ✅ | tests/test_hmac.tcl | ✅ | doc/hmac.md | |
| `::tossl::cryptolog` | ✅ | tests/test_cryptolog.tcl | ✅ | doc/cryptolog.md | |
| `::tossl::benchmark` | ✅ | tests/test_benchmark.tcl | ✅ | doc/benchmark.md | |
| `::tossl::decrypt` | ✅ | tests/test_decrypt.tcl | ✅ | doc/decrypt.md | |
| `::tossl::csr::modify` | ✅ | tests/test_csr_modify.tcl | ✅ | doc/csr_modify.md | |
| `::tossl::csr::fingerprint` | ✅ | tests/test_csr_fingerprint.tcl | ✅ | doc/csr_fingerprint.md | |
| `::tossl::csr::create` | ✅ | tests/test_csr_create.tcl | ✅ | doc/csr_create.md | |
| `::tossl::csr::validate` | ✅ | tests/test_csr_validate.tcl | ✅ | doc/csr_validate.md | |
| `::tossl::csr::parse` | ✅ | tests/test_csr_parse.tcl | ✅ | doc/csr_parse.md | |
| `::tossl::ec::point_multiply` | ✅ | tests/test_ec_point_multiply.tcl | ✅ | doc/ec_point_multiply.md | |
| `::tossl::ec::verify` | ✅ | tests/test_ec_verify.tcl | ✅ | doc/ec_verify.md | |
| `::tossl::ec::sign` | ✅ | tests/test_ec_sign.tcl | ✅ | doc/ec_sign.md | |
| `::tossl::ec::components` | ✅ | tests/test_ec_components.tcl | ✅ | doc/ec_components.md | |
| `::tossl::ec::point_add` | ✅ | tests/test_ec_point_add.tcl | ✅ | doc/ec_point_add.md | |
| `::tossl::ec::validate` | ✅ | tests/test_ec_validate.tcl | ✅ | doc/ec_validate.md | |
| `::tossl::ec::list_curves` | ✅ | tests/test_ec_list_curves.tcl | ✅ | doc/ec_list_curves.md | |
| `::tossl::dsa::verify` | ✅ | tests/test_dsa_verify.tcl | ✅ | doc/dsa_verify.md | |
| `::tossl::dsa::sign` | ✅ | tests/test_dsa_sign.tcl | ✅ | doc/dsa_sign.md | |
| `::tossl::dsa::validate` | ✅ | tests/test_dsa_validate.tcl | ✅ | doc/dsa_validate.md | |
| `::tossl::dsa::generate_params` | ✅ | tests/test_dsa_generate_params.tcl | ✅ | doc/dsa_generate_params.md | |
| `::tossl::http::get` | ✅ | tests/test_http_get.tcl | ✅ | doc/http_get.md | Enhanced functionality |
| `::tossl::http::upload` | ✅ | tests/test_http_upload.tcl | ✅ | doc/http_upload.md | |
| `::tossl::http::request` | ✅ | tests/test_http_request.tcl | ✅ | doc/http_request.md | |
| `::tossl::http::post` | ✅ | tests/test_http_post.tcl | ✅ | doc/http_post.md | Enhanced functionality |
| `::tossl::http::metrics` | ✅ | tests/test_http_metrics.tcl | ✅ | doc/http_metrics.md | |
| `::tossl::http::debug` | ✅ | tests/test_http_debug.tcl | ✅ | doc/http_debug.md | |

| `::tossl::digest::list` | ✅ | tests/test_digest_list.tcl | ✅ | doc/digest_list.md | |
| `::tossl::digest::stream` | ✅ | tests/test_digest_stream.tcl | ✅ | doc/digest_stream.md | |
| `::tossl::digest::compare` | ✅ | tests/test_digest_compare.tcl | ✅ | doc/digest_compare.md | |
| `::tossl::crl::create` | ✅ | tests/test_crl_create.tcl | ✅ | doc/crl_create.md | |
| `::tossl::crl::parse` | ✅ | tests/test_crl_parse.tcl | ✅ | doc/crl_parse.md | |
| `::tossl::key::analyze` | ✅ | tests/test_key_analyze.tcl | ✅ | doc/key_analyze.md | Command is actually ::tossl::key::parse |
| `::tossl::key::fingerprint` | ✅ | tests/test_key_fingerprint.tcl | ✅ | doc/key_fingerprint.md | |
| `::tossl::key::convert` | ✅ | tests/test_key_convert.tcl | ✅ | doc/key_convert.md | |
| `::tossl::key::getpub` | ✅ | tests/test_key_getpub.tcl | ✅ | doc/key_getpub.md | |
| `::tossl::key::generate` | ✅ | tests/test_key_generate.tcl | ✅ | doc/key_generate.md | |
| `::tossl::key::write` | ✅ | tests/test_key_write.tcl | ✅ | doc/key_write.md | |
| `::tossl::key::parse` | ✅ | tests/test_key_parse.tcl | ✅ | doc/key_parse.md | |
| `::tossl::fips::status` | ✅ | tests/test_fips_status.tcl | ✅ | doc/fips_status.md | |
| `::tossl::fips::enable` | ✅ | tests/test_fips_enable.tcl | ✅ | doc/fips_enable.md | |
| `::tossl::json::generate` | ✅ | tests/test_json_generate.tcl | ✅ | doc/json_generate.md | |
| `::tossl::json::parse` | ✅ | tests/test_json_parse.tcl | ✅ | doc/json_parse.md | |
| `::tossl::url::decode` | ✅ | tests/test_url_decode.tcl | ✅ | doc/url_decode.md | |
| `::tossl::url::encode` | ✅ | tests/test_url_encode.tcl | ✅ | doc/url_encode.md | |
| `::tossl::provider::list` | ✅ | tests/test_provider_list.tcl | ✅ | doc/provider_list.md | |
| `::tossl::provider::load` | ✅ | tests/test_provider_load.tcl | ✅ | doc/provider_load.md | |
| `::tossl::provider::unload` | ✅ | tests/test_provider_unload.tcl | ✅ | doc/provider_unload.md | |
| `::tossl::oauth2::load_token` | ✅ | tests/test_oauth2_load_token.tcl | ✅ | doc/oauth2_load_token.md | |
| `::tossl::oauth2::device_authorization` | ✅ | tests/test_oauth2_device_authorization.tcl | ✅ | doc/oauth2_device_authorization.md | |
| `::tossl::oauth2::create_code_challenge` | ✅ | tests/test_oauth2_create_code_challenge.tcl | ✅ | doc/oauth2_create_code_challenge.md | |
| `::tossl::oauth2::validate_state` | ✅ | tests/test_oauth2_validate_state.tcl | ✅ | doc/oauth2_validate_state.md | |
| `::tossl::oauth2::parse_token` | ✅ | tests/test_oauth2_parse_token.tcl | ✅ | doc/oauth2_parse_token.md | |
| `::tossl::oauth2::is_token_expired` | ✅ | tests/test_oauth2_is_token_expired.tcl | ✅ | doc/oauth2_is_token_expired.md | |
| `::tossl::oauth2::store_token` | ✅ | tests/test_oauth2_store_token.tcl | ✅ | doc/oauth2_store_token.md | |
| `::tossl::oauth2::auto_refresh` | ✅ | tests/test_oauth2_auto_refresh.tcl | ✅ | doc/oauth2_auto_refresh.md | |
| `::tossl::oauth2::refresh_token` | ✅ | tests/test_oauth2_refresh_token.tcl | ✅ | doc/oauth2_refresh_token.md | |
| `::tossl::oauth2::generate_code_verifier` | ✅ | tests/test_oauth2_generate_code_verifier.tcl | ✅ | doc/oauth2_generate_code_verifier.md | |
| `::tossl::oauth2::validate_introspection` | ✅ | tests/test_oauth2_validate_introspection.tcl | ✅ | doc/oauth2_validate_introspection.md | |
| `::tossl::oauth2::authorization_url` | ✅ | tests/test_oauth2_authorization_url.tcl | ✅ | doc/oauth2_authorization_url.md | |
| `::tossl::oauth2::generate_state` | ✅ | tests/test_oauth2_generate_state.tcl | ✅ | doc/oauth2_generate_state.md | |
| `::tossl::oauth2::introspect_token` | ✅ | tests/test_oauth2_introspect_token.tcl | ✅ | doc/oauth2_introspect_token.md | |
| `::tossl::oauth2::client_credentials` | ✅ | tests/test_oauth2_client_credentials.tcl | ✅ | doc/oauth2_client_credentials.md | |
| `::tossl::oauth2::exchange_code` | ✅ | tests/test_oauth2_exchange_code.tcl | ✅ | doc/oauth2_exchange_code.md | |
| `::tossl::oauth2::authorization_url_pkce` | ✅ | tests/test_oauth2_authorization_url_pkce.tcl | ✅ | doc/oauth2_authorization_url_pkce.md | |
| `::tossl::oauth2::poll_device_token` | ✅ | tests/test_oauth2_poll_device_token.tcl | ✅ | doc/oauth2_poll_device_token.md | |
| `::tossl::oauth2::exchange_code_pkce` | ✅ | tests/test_oauth2_exchange_code_pkce.tcl | ✅ | doc/oauth2_exchange_code_pkce.md | |
| `::tossl::pkcs12::create` | ✅ | tests/test_pkcs12_create.tcl | ✅ | doc/pkcs12_create.md | |
| `::tossl::pkcs12::parse` | ✅ | tests/test_pkcs12_parse.tcl | ✅ | doc/pkcs12_parse.md | |
| `::tossl::ocsp::create_request` | ✅ | tests/test_ocsp_create_request.tcl | ✅ | doc/ocsp_create_request.md | |
| `::tossl::ocsp::parse_response` | ✅ | tests/test_ocsp_parse_response.tcl | ✅ | doc/ocsp_parse_response.md | |
| `::tossl::legacy::info` | ✅ | tests/test_legacy_info.tcl | ✅ | doc/legacy_info.md | |
| `::tossl::legacy::list` | ✅ | tests/test_legacy_list.tcl | ✅ | doc/legacy_list.md | |
| `::tossl::legacy::ivgen` | ✅ | tests/test_legacy_ivgen.tcl | ✅ | doc/legacy_ivgen.md | |
| `::tossl::legacy::encrypt` | ✅ | tests/test_legacy_encrypt.tcl | ✅ | doc/legacy_encrypt.md | |
| `::tossl::legacy::keygen` | ✅ | tests/test_legacy_keygen.tcl | ✅ | doc/legacy_keygen.md | |
| `::tossl::legacy::decrypt` | ✅ | tests/test_legacy_decrypt.tcl | ✅ | doc/legacy_decrypt.md | |
| `::tossl::rand::test` | ✅ | tests/test_rand_test.tcl | ✅ | doc/rand_test.md | |
| `::tossl::rand::key` | ✅ | tests/test_rand_key.tcl | ✅ | doc/rand_key.md | -len parameter parsed but ignored |
| `::tossl::rand::iv` | ✅ | tests/test_rand_iv.tcl | ✅ | doc/rand_iv.md | |
| `::tossl::rand::bytes` | ✅ | tests/test_randbytes.tcl | ✅ | doc/randbytes.md | |
| `::tossl::kdf::argon2` | ✅ | tests/test_kdf_argon2.tcl | ✅ | doc/kdf_argon2.md | Known issue: implementation uses scrypt instead of Argon2 |
| `::tossl::kdf::scrypt` | ✅ | tests/test_scrypt.tcl | ✅ | doc/scrypt.md | |
| `::tossl::kdf::pbkdf2` | ✅ | tests/test_pbkdf2.tcl | ✅ | doc/pbkdf2.md | |
| `::tossl::cert::status` | ✅ | tests/test_cert_status.tcl | ✅ | doc/cert_status.md | |
| `::tossl::sidechannel::protect` | ✅ | tests/test_sidechannel_protect.tcl | ✅ | doc/sidechannel_protect.md | |
| `::tossl::hardware::detect` | ✅ | tests/test_hardware_detect.tcl | ✅ | doc/hardware_detect.md | |
| `::tossl::x509::time_validate` | ✅ | tests/test_x509_time_validate.tcl | ✅ | doc/x509_time_validate.md | |
| `::tossl::x509::fingerprint` | ✅ | tests/test_x509_fingerprint.tcl | ✅ | doc/x509_fingerprint.md | |
| `::tossl::x509::create` | ✅ | tests/test_x509_create.tcl | ✅ | doc/x509_create.md | |
| `::tossl::x509::modify` | ✅ | tests/test_x509_modify.tcl | ✅ | doc/x509_modify.md | |
| `::tossl::x509::verify` | ✅ | tests/test_x509_verify.tcl | ✅ | doc/x509_verify.md | |
| `::tossl::x509::validate` | ✅ | tests/test_x509_validate.tcl | ✅ | doc/x509_validate.md | |
| `::tossl::x509::parse` | ✅ | tests/test_x509_parse.tcl | ✅ | doc/x509_parse.md | |
| `::tossl::acme::cleanup_dns` | ✅ | tests/test_acme_cleanup_dns.tcl | ✅ | doc/acme_cleanup_dns.md | |
| `::tossl::acme::dns01_challenge` | ✅ | tests/test_acme_dns01_challenge.tcl | ✅ | doc/acme_dns01_challenge.md | |
| `::tossl::acme::create_account` | ✅ | tests/test_acme_create_account.tcl | ✅ | doc/acme_create_account.md | |
| `::tossl::acme::directory` | ✅ | tests/test_acme_directory.tcl | ✅ | doc/acme_directory.md | |
| `::tossl::acme::create_order` | ✅ | tests/test_acme_create_order.tcl | ✅ | doc/acme_create_order.md | |
| `::tossl::time::convert` | ✅ | tests/test_time_convert.tcl | ✅ | doc/time_convert.md | |
| `::tossl::time::compare` | ✅ | tests/test_time_compare.tcl | ✅ | doc/time_compare.md | |
| `::tossl::algorithm::info` | ✅ | tests/test_algorithm_info.tcl | ✅ | doc/algorithm_info.md | |
| `::tossl::algorithm::list` | ✅ | tests/test_algorithm_list.tcl | ✅ | doc/algorithm_list.md | |
| `::tossl::pbe::keyderive` | ✅ | tests/test_pbe_keyderive.tcl | ✅ | doc/pbe_keyderive.md | |
| `::tossl::pbe::encrypt` | ✅ | tests/test_pbe_encrypt.tcl | ✅ | doc/pbe_encrypt.md | Algorithm parameter ignored, no validation, decrypt has bug |
| `::tossl::pbe::algorithms` | ✅ | tests/test_pbe_algorithms.tcl | ✅ | doc/pbe_algorithms.md | |
| `::tossl::pbe::saltgen` | ✅ | tests/test_pbe_saltgen.tcl | ✅ | doc/pbe_saltgen.md | |
| `::tossl::pbe::decrypt` | ✅ | tests/test_pbe_decrypt.tcl | ✅ | doc/pbe_decrypt.md | Known strlen() bug affects binary data |
| `::tossl::pkcs7::info` | ✅ | tests/test_pkcs7_info.tcl | ✅ | doc/pkcs7_info.md | Now uses CMS API, OpenSSL 3.x compatible |
| `::tossl::pkcs7::verify` | ✅ | tests/test_pkcs7_verify.tcl | ✅ | doc/pkcs7_verify.md | Now uses CMS API, OpenSSL 3.x compatible |
| `::tossl::pkcs7::sign` | ✅ | tests/test_pkcs7_sign.tcl | ✅ | doc/pkcs7_sign.md | Now uses CMS API, OpenSSL 3.x compatible |
| `::tossl::pkcs7::encrypt` | ✅ | tests/test_pkcs7_encrypt.tcl | ✅ | doc/pkcs7_encrypt.md | Now uses CMS API, OpenSSL 3.x compatible |
| `::tossl::pkcs7::decrypt` | ✅ | tests/test_pkcs7_decrypt.tcl | ✅ | doc/pkcs7_decrypt.md | Now uses CMS API, OpenSSL 3.x compatible |
| `::tossl::x448::derive` | ✅ | tests/test_x448.tcl | ✅ | doc/x448_derive.md | Modern OpenSSL API, OpenSSL 3.x compatible |
| `::tossl::x448::generate` | ✅ | tests/test_x448.tcl | ✅ | doc/x448_generate.md | Modern OpenSSL API, OpenSSL 3.x compatible |
| `::tossl::base64url::decode` | ✅ | tests/test_base64url_decode.tcl | ✅ | doc/base64url_decode.md | RFC 4648, robust error handling |
| `::tossl::base64url::encode` | ✅ | tests/test_base64url_encode.tcl | ✅ | doc/base64url_encode.md | RFC 4648, no padding, URL-safe |
| `::tossl::pfs::test` | ✅ | tests/test_pfs_test.tcl | ✅ | doc/pfs_test.md | |
| `::tossl::ed448::verify` | ✅ | tests/test_ed448_verify.tcl | ✅ | doc/ed448_verify.md | |
| `::tossl::ed448::sign` | ✅ | tests/test_ed448_sign.tcl | ✅ | doc/ed448_sign.md | |
| `::tossl::ed448::generate` | ✅ | tests/test_ed448_generate.tcl | ✅ | doc/ed448_generate.md | |
| `::tossl::signature::validate` | ✅ | tests/test_signature_validate.tcl | ✅ | doc/signature_validate.md | Now fully working |
| `::tossl::ssl::verify_peer` | ✅ | tests/test_ssl_verify_peer.tcl | ✅ | doc/ssl_verify_peer.md | |
| `::tossl::ssl::accept` | ✅ | tests/test_ssl_accept.tcl | ✅ | doc/ssl_accept.md | |
| `::tossl::ssl::set_protocol_version` | ✅ | tests/test_ssl_set_protocol_version.tcl | ✅ | doc/ssl_set_protocol_version.md | |
| `::tossl::ssl::set_alpn_callback` | ✅ | tests/test_ssl_set_alpn_callback.tcl | ✅ | doc/ssl_set_alpn_callback.md | |
| `::tossl::ssl::verify_cert_pinning` | ✅ | tests/test_ssl_verify_cert_pinning.tcl | ✅ | doc/ssl_verify_cert_pinning.md | |
| `::tossl::ssl::read` | ✅ | tests/test_ssl_read.tcl | ✅ | doc/ssl_read.md | |
| `::tossl::ssl::check_pfs` | ✅ | tests/test_ssl_check_pfs.tcl | ✅ | doc/ssl_check_pfs.md | |
| `::tossl::ssl::cipher_info` | ✅ | tests/test_ssl_cipher_info.tcl | ✅ | doc/ssl_cipher_info.md | |
| `::tossl::ssl::get_peer_cert` | ✅ | tests/test_ssl_get_peer_cert.tcl | ✅ | doc/ssl_get_peer_cert.md | |
| `::tossl::ssl::set_ocsp_stapling` | ✅ | tests/test_ssl_set_ocsp_stapling.tcl | ✅ | doc/ssl_set_ocsp_stapling.md | |
| `::tossl::ssl::connect` | ✅ | tests/test_ssl_connect.tcl | ✅ | doc/ssl_connect.md | |
| `::tossl::ssl::set_cert_pinning` | ✅ | tests/test_ssl_set_cert_pinning.tcl | ✅ | doc/ssl_set_cert_pinning.md | Fully implemented with pinning enforcement |
| `::tossl::ssl::write` | ✅ | tests/test_ssl_write.tcl | ✅ | doc/ssl_write.md | Fully implemented and tested |
| `::tossl::ssl::alpn_selected` | ✅ | tests/test_ssl_alpn_selected.tcl | ✅ | doc/ssl_alpn_selected.md | Fully implemented and tested |
| `::tossl::ssl::socket_info` | ✅ | tests/test_ssl_socket_info.tcl | ✅ | doc/ssl_socket_info.md | Fully implemented and tested |
| `::tossl::ssl::context` | ✅ | tests/test_ssl_context.tcl | ✅ | doc/ssl_context.md | Fully implemented and tested |
| `::tossl::ssl::check_cert_status` | ✅ | tests/test_ssl_check_cert_status.tcl | ✅ | doc/ssl_check_cert_status.md | Fully implemented and tested |
| `::tossl::ssl::close` | ✅ | tests/test_ssl_close.tcl | ✅ | doc/ssl_close.md | Fully implemented and tested |
| `::tossl::ssl::protocol_version` | ✅ | tests/test_ssl_protocol_version.tcl | ✅ | doc/ssl_protocol_version.md | Fully implemented and tested |
| `::tossl::sm2::encrypt` | ✅ | tests/test_sm2_encrypt.tcl | ✅ | doc/sm2_encrypt.md | Fully implemented and tested (SM2 key extraction limitation noted) |
| `::tossl::sm2::verify` | ✅ | tests/test_sm2_verify.tcl | ✅ | doc/sm2_verify.md | |
| `::tossl::sm2::sign` | ✅ | tests/test_sm2_sign.tcl | ✅ | doc/sm2_sign.md | |
| `::tossl::sm2::decrypt` | ✅ | tests/test_sm2_decrypt.tcl | ✅ | doc/sm2_decrypt.md | |
| `::tossl::sm2::generate` | ✅ | tests/test_sm2_generate.tcl | ✅ | doc/sm2_generate.md | |
| `::tossl::asn1::sequence_create` | ✅ | tests/test_asn1_sequence_create.tcl | ✅ | doc/asn1_sequence_create.md | |
| `::tossl::asn1::text_to_oid` | ✅ | tests/test_asn1_text_to_oid.tcl | ✅ | doc/asn1_text_to_oid.md | |
| `::tossl::asn1::oid_to_text` | ✅ | tests/test_asn1_oid_to_text.tcl | ✅ | doc/asn1_oid_to_text.md | |
| `::tossl::asn1::encode` | ✅ | tests/test_asn1_encode.tcl | ✅ | doc/asn1_encode.md | |
| `::tossl::asn1::set_create` | ✅ | tests/test_asn1_set_create.tcl | ✅ | doc/asn1_set_create.md | |
| `::tossl::asn1::parse` | ✅ | tests/test_asn1_parse.tcl | ✅ | doc/asn1_parse.md | |
| `::tossl::keywrap::info` | ✅ | tests/test_keywrap_info.tcl | ✅ | doc/keywrap_info.md | |
| `::tossl::keywrap::kekgen` | ✅ | tests/test_keywrap_kekgen.tcl | ✅ | doc/keywrap_kekgen.md | |
| `::tossl::keywrap::unwrap` | ✅ | tests/test_keywrap_unwrap.tcl | ✅ | doc/keywrap_unwrap.md | |
| `::tossl::keywrap::algorithms` | ✅ | tests/test_keywrap_algorithms.tcl | ✅ | doc/keywrap_algorithms.md | |
| `::tossl::keywrap::wrap` | ✅ | tests/test_keywrap_wrap.tcl | ✅ | doc/keywrap_wrap.md | |
| `::tossl::cipher::analyze` | ✅ | tests/test_cipher_analyze.tcl | ✅ | doc/cipher_analyze.md | |
| `::tossl::cipher::list` | ✅ | tests/test_cipher_list.tcl | ✅ | doc/cipher_list.md | |
| `::tossl::cipher::info` | ✅ | tests/test_cipher_info.tcl | ✅ | doc/cipher_info.md | |
| `::tossl::ca::sign` | ✅ | tests/test_ca_sign.tcl | ✅ | doc/ca_sign.md | |
| `::tossl::ca::generate` | ✅ | tests/test_ca_generate.tcl | ✅ | doc/ca_generate.md | |
| `::tossl::jwt::decode` | ✅ | tests/test_jwt_decode.tcl | ✅ | doc/jwt_decode.md | |
| `::tossl::jwt::create` | ✅ | tests/test_jwt_create.tcl | ✅ | doc/jwt_create.md | |
| `::tossl::jwt::verify` | ❌ | | ❌ | | |
| `::tossl::jwt::validate` | ✅ | tests/test_jwt_validate.tcl | ✅ | doc/jwt_validate.md | JWT claim validation |
| `::tossl::jwt::extract_claims` | ❌ | | ❌ | | |
| `::tossl::base64::decode` | ❌ | | ❌ | | |
| `::tossl::base64::encode` | ❌ | | ❌ | | |
| `::tossl::hex::decode` | ❌ | | ❌ | | |
| `::tossl::hex::encode` | ❌ | | ❌ | | |
| `::tossl::x25519::derive` | ❌ | | ❌ | | |
| `::tossl::x25519::generate` | ❌ | | ❌ | | |
| `::tossl::rsa::verify` | ❌ | | ❌ | | |
| `::tossl::rsa::sign` | ❌ | | ❌ | | |
| `::tossl::rsa::encrypt` | ❌ | | ❌ | | |
| `::tossl::rsa::components` | ❌ | | ❌ | | |
| `::tossl::rsa::validate` | ❌ | | ❌ | | |
| `::tossl::rsa::decrypt` | ❌ | | ❌ | | |
| `::tossl::rsa::generate` | ❌ | | ❌ | | |
| `::tossl::ed25519::verify` | ❌ | | ❌ | | |
| `::tossl::ed25519::sign` | ❌ | | ❌ | | |
| `::tossl::ed25519::generate` | ❌ | | ❌ | | |

## Legend
- ❌ = Not started
- 🔄 = In progress  
- ✅ = Completed
- ⚠️ = Issues/Problems

## Notes
- Test files should be created in the `tests/` directory
- Documentation files should be created in the `doc/` directory
- Each command should have both a test file and a documentation file
- Test files should follow the naming convention: `test_<command_name>.tcl`
- Documentation files should follow the naming convention: `<command_name>.md`
