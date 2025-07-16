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
- **Tests Created**: 14/190 (7.4%)
- **Documentation Created**: 14/190 (7.4%)

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
| `::tossl::csr::parse` | ❌ | | ❌ | | |
| `::tossl::ec::point_multiply` | ❌ | | ❌ | | |
| `::tossl::ec::verify` | ❌ | | ❌ | | |
| `::tossl::ec::sign` | ❌ | | ❌ | | |
| `::tossl::ec::components` | ❌ | | ❌ | | |
| `::tossl::ec::point_add` | ❌ | | ❌ | | |
| `::tossl::ec::validate` | ❌ | | ❌ | | |
| `::tossl::ec::list_curves` | ❌ | | ❌ | | |
| `::tossl::dsa::verify` | ❌ | | ❌ | | |
| `::tossl::dsa::sign` | ❌ | | ❌ | | |
| `::tossl::dsa::validate` | ❌ | | ❌ | | |
| `::tossl::dsa::generate_params` | ❌ | | ❌ | | |
| `::tossl::http::get` | ❌ | | ❌ | | |
| `::tossl::http::upload` | ❌ | | ❌ | | |
| `::tossl::http::request` | ❌ | | ❌ | | |
| `::tossl::http::get_enhanced` | ❌ | | ❌ | | |
| `::tossl::http::post` | ❌ | | ❌ | | |
| `::tossl::http::metrics` | ❌ | | ❌ | | |
| `::tossl::http::debug` | ❌ | | ❌ | | |
| `::tossl::http::post_enhanced` | ❌ | | ❌ | | |
| `::tossl::digest::list` | ❌ | | ❌ | | |
| `::tossl::digest::stream` | ❌ | | ❌ | | |
| `::tossl::digest::compare` | ❌ | | ❌ | | |
| `::tossl::crl::create` | ❌ | | ❌ | | |
| `::tossl::crl::parse` | ❌ | | ❌ | | |
| `::tossl::key::analyze` | ❌ | | ❌ | | |
| `::tossl::key::fingerprint` | ❌ | | ❌ | | |
| `::tossl::key::convert` | ❌ | | ❌ | | |
| `::tossl::key::getpub` | ❌ | | ❌ | | |
| `::tossl::key::generate` | ❌ | | ❌ | | |
| `::tossl::key::write` | ❌ | | ❌ | | |
| `::tossl::key::parse` | ❌ | | ❌ | | |
| `::tossl::fips::status` | ❌ | | ❌ | | |
| `::tossl::fips::enable` | ❌ | | ❌ | | |
| `::tossl::json::generate` | ❌ | | ❌ | | |
| `::tossl::json::parse` | ❌ | | ❌ | | |
| `::tossl::url::decode` | ❌ | | ❌ | | |
| `::tossl::url::encode` | ❌ | | ❌ | | |
| `::tossl::provider::list` | ❌ | | ❌ | | |
| `::tossl::provider::load` | ❌ | | ❌ | | |
| `::tossl::provider::unload` | ❌ | | ❌ | | |
| `::tossl::oauth2::load_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::device_authorization` | ❌ | | ❌ | | |
| `::tossl::oauth2::create_code_challenge` | ❌ | | ❌ | | |
| `::tossl::oauth2::validate_state` | ❌ | | ❌ | | |
| `::tossl::oauth2::parse_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::is_token_expired` | ❌ | | ❌ | | |
| `::tossl::oauth2::store_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::auto_refresh` | ❌ | | ❌ | | |
| `::tossl::oauth2::refresh_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::generate_code_verifier` | ❌ | | ❌ | | |
| `::tossl::oauth2::validate_introspection` | ❌ | | ❌ | | |
| `::tossl::oauth2::authorization_url` | ❌ | | ❌ | | |
| `::tossl::oauth2::generate_state` | ❌ | | ❌ | | |
| `::tossl::oauth2::introspect_token` | ❌ | | ❌ | | |
| `::tossl::oauth2::client_credentials` | ❌ | | ❌ | | |
| `::tossl::oauth2::exchange_code` | ❌ | | ❌ | | |
| `::tossl::oauth2::authorization_url_pkce` | ❌ | | ❌ | | |
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
| `