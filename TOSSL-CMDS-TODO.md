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
- **Total Commands**: 189
- **Tests Created**: 68/189 (36.0%)
- **Documentation Created**: 68/189 (36.0%)

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
| `::tossl::oauth2::poll_device_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::exchange_code_pkce` | ❌ | | ❌ | | |
| `::tossl::pkcs12::create` | ❌ | | ❌ | | |
| `::tossl::pkcs12::parse` | ❌ | | ❌ | | |
| `::tossl::ocsp::create_request` | ❌ | | ❌ | | |
| `::tossl::ocsp::parse_response` | ❌ | | ❌ | | |
| `::tossl::legacy::info` | ❌ | | ❌ | | |
| `::tossl::legacy::list` | ❌ | | ❌ | | |
| `::tossl::legacy::ivgen` | ❌ | | ❌ | | |
| `::tossl::legacy::encrypt` | ❌ | | ❌ | | |
| `::tossl::legacy::keygen` | ❌ | | ❌ | | |
| `::tossl::legacy::decrypt` | ❌ | | ❌ | | |
| `::tossl::rand::test` | ❌ | | ❌ | | |
| `::tossl::rand::key` | ❌ | | ❌ | | |
| `::tossl::rand::iv` | ❌ | | ❌ | | |
| `::tossl::rand::bytes` | ❌ | | ❌ | | |
| `::tossl::kdf::argon2` | ❌ | | ❌ | | |
| `::tossl::kdf::scrypt` | ❌ | | ❌ | | |
| `::tossl::kdf::pbkdf2` | ❌ | | ❌ | | |
| `::tossl::cert::status` | ❌ | | ❌ | | |
| `::tossl::sidechannel::protect` | ❌ | | ❌ | | |
| `::tossl::hardware::detect` | ❌ | | ❌ | | |
| `::tossl::x509::time_validate` | ❌ | | ❌ | | |
| `::tossl::x509::fingerprint` | ❌ | | ❌ | | |
| `::tossl::x509::create` | ❌ | | ❌ | | |
| `::tossl::x509::modify` | ❌ | | ❌ | | |
| `::tossl::x509::verify` | ❌ | | ❌ | | |
| `::tossl::x509::validate` | ❌ | | ❌ | | |
| `::tossl::x509::parse` | ❌ | | ❌ | | |
| `::tossl::acme::cleanup_dns` | ❌ | | ❌ | | |
| `::tossl::acme::dns01_challenge` | ❌ | | ❌ | | |
| `::tossl::acme::create_account` | ❌ | | ❌ | | |
| `::tossl::acme::directory` | ❌ | | ❌ | | |
| `::tossl::acme::create_order` | ❌ | | ❌ | | |
| `::tossl::time::convert` | ❌ | | ❌ | | |
| `::tossl::time::compare` | ❌ | | ❌ | | |
| `::tossl::algorithm::info` | ❌ | | ❌ | | |
| `::tossl::algorithm::list` | ❌ | | ❌ | | |
| `::tossl::pbe::keyderive` | ❌ | | ❌ | | |
| `::tossl::pbe::encrypt` | ❌ | | ❌ | | |
| `::tossl::pbe::algorithms` | ❌ | | ❌ | | |
| `::tossl::pbe::saltgen` | ❌ | | ❌ | | |
| `::tossl::pbe::decrypt` | ❌ | | ❌ | | |
| `::tossl::pkcs7::info` | ❌ | | ❌ | | |
| `::tossl::pkcs7::verify` | ❌ | | ❌ | | |
| `::tossl::pkcs7::sign` | ❌ | | ❌ | | |
| `::tossl::pkcs7::encrypt` | ❌ | | ❌ | | |
| `::tossl::pkcs7::decrypt` | ❌ | | ❌ | | |
| `::tossl::x448::derive` | ❌ | | ❌ | | |
| `::tossl::x448::generate` | ❌ | | ❌ | | |
| `::tossl::base64url::decode` | ❌ | | ❌ | | |
| `::tossl::base64url::encode` | ❌ | | ❌ | | |
| `::tossl::pfs::test` | ❌ | | ❌ | | |
| `::tossl::ed448::verify` | ❌ | | ❌ | | |
| `::tossl::ed448::sign` | ❌ | | ❌ | | |
| `::tossl::ed448::generate` | ❌ | | ❌ | | |
| `::tossl::signature::validate` | ❌ | | ❌ | | |
| `::tossl::ssl::verify_peer` | ❌ | | ❌ | | |
| `::tossl::ssl::accept` | ❌ | | ❌ | | |
| `::tossl::ssl::set_protocol_version` | ❌ | | ❌ | | |
| `::tossl::ssl::set_alpn_callback` | ❌ | | ❌ | | |
| `::tossl::ssl::verify_cert_pinning` | ❌ | | ❌ | | |
| `::tossl::ssl::read` | ❌ | | ❌ | | |
| `::tossl::ssl::check_pfs` | ❌ | | ❌ | | |
| `::tossl::ssl::cipher_info` | ❌ | | ❌ | | |
| `::tossl::ssl::get_peer_cert` | ❌ | | ❌ | | |
| `::tossl::ssl::set_ocsp_stapling` | ❌ | | ❌ | | |
| `::tossl::ssl::connect` | ❌ | | ❌ | | |
| `::tossl::ssl::set_cert_pinning` | ❌ | | ❌ | | |
| `::tossl::ssl::write` | ❌ | | ❌ | | |
| `::tossl::ssl::alpn_selected` | ❌ | | ❌ | | |
| `::tossl::ssl::socket_info` | ❌ | | ❌ | | |
| `::tossl::ssl::context` | ❌ | | ❌ | | |
| `::tossl::ssl::check_cert_status` | ❌ | | ❌ | | |
| `::tossl::ssl::close` | ❌ | | ❌ | | |
| `::tossl::ssl::protocol_version` | ❌ | | ❌ | | |
| `::tossl::sm2::encrypt` | ❌ | | ❌ | | |
| `::tossl::sm2::verify` | ❌ | | ❌ | | |
| `::tossl::sm2::sign` | ❌ | | ❌ | | |
| `::tossl::sm2::decrypt` | ❌ | | ❌ | | |
| `::tossl::sm2::generate` | ❌ | | ❌ | | |
| `::tossl::asn1::sequence_create` | ❌ | | ❌ | | |
| `::tossl::asn1::text_to_oid` | ❌ | | ❌ | | |
| `::tossl::asn1::oid_to_text` | ❌ | | ❌ | | |
| `::tossl::asn1::encode` | ❌ | | ❌ | | |
| `::tossl::asn1::set_create` | ❌ | | ❌ | | |
| `::tossl::asn1::parse` | ❌ | | ❌ | | |
| `::tossl::keywrap::info` | ❌ | | ❌ | | |
| `::tossl::keywrap::kekgen` | ❌ | | ❌ | | |
| `::tossl::keywrap::unwrap` | ❌ | | ❌ | | |
| `::tossl::keywrap::algorithms` | ❌ | | ❌ | | |
| `::tossl::keywrap::wrap` | ❌ | | ❌ | | |
| `::tossl::cipher::analyze` | ❌ | | ❌ | | |
| `::tossl::cipher::list` | ❌ | | ❌ | | |
| `::tossl::cipher::info` | ❌ | | ❌ | | |
| `::tossl::ca::sign` | ❌ | | ❌ | | |
| `::tossl::ca::generate` | ❌ | | ❌ | | |
| `::tossl::jwt::decode` | ❌ | | ❌ | | |
| `::tossl::jwt::create` | ❌ | | ❌ | | |
| `::tossl::jwt::verify` | ❌ | | ❌ | | |
| `::tossl::jwt::validate` | ❌ | | ❌ | | |
| `::tossl::jwt::extract_claims` | ❌ | | ❌ | | |
| `::tossl::base64::decode` | ❌ | | ❌ | | |
| `::tossl::base64::encode` | ❌ | | ❌ | | |
| `::tossl::hex::decode` | ❌ | | ❌ | | |
| `::tossl::hex::encode` | ❌ | | ❌ | | |
| `::tossl::x25519::derive` | ❌ | | ❌ | | |
| `::tossl::x25519::generate` | ❌ | | ❌ | | |
| `