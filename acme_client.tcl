#!/usr/bin/env tclsh
# ACME Client for TOSSL
# Implements RFC 8555 (ACME) for automated certificate issuance
# Supports Let's Encrypt and other ACME-compliant CAs

if {[catch {package require tossl}]} {
    load ./libtossl.so
}
package require http
package require rl_json
package require tls

# Configure TLS for HTTPS requests to ACME servers
::tls::init -servername acme-staging-v02.api.letsencrypt.org
http::register https 443 ::tls::socket

namespace eval acme {
    variable VERSION "1.0"
    variable NONCE_CACHE_SIZE 10
    variable nonce_cache {}
    
    # ACME endpoints
    variable ENDPOINTS {
        letsencrypt {
            directory "https://acme-v02.api.letsencrypt.org/directory"
            staging "https://acme-staging-v02.api.letsencrypt.org/directory"
        }
    }
    
    # HTTP headers for ACME requests
    variable ACME_HEADERS {
        "Content-Type" "application/jose+json"
        "User-Agent" "ToSSL-ACME-Client/1.0"
    }
    
    # JWS algorithms supported
    variable JWS_ALGORITHMS {
        RS256 "RS256"
        ES256 "ES256"
    }
}

# Generate a new account key pair
proc acme::generate_account_key {type} {
    switch $type {
        "rsa" {
            set keys [tossl::key::generate -type rsa -bits 2048]
        }
        "ec" {
            set keys [tossl::key::generate -type ec -curve prime256v1]
        }
        default {
            error "Unsupported key type: $type (use 'rsa' or 'ec')"
        }
    }
    return $keys
}

# Create JWS (JSON Web Signature) for ACME requests
proc acme::create_jws {payload url nonce key_private} {
    # Extract JWK using the existing function
    set jwk [acme::extract_jwk $key_private]
    
    # Create JWS header
    set header_obj [rl_json::json object \
        alg   {string RS256} \
        nonce [list string $nonce] \
        url   [list string $url] \
        jwk   [list json [rl_json::json normalize $jwk]]]
    set header_json [rl_json::json normalize $header_obj]
    set header_b64 [acme::base64url_encode $header_json]
    
    # Ensure payload is a JSON string
    if {[catch {rl_json::json get $payload}]} {
        set payload_obj [rl_json::json object {*}[dict map {k v} $payload {set k $v}]]
        set payload_json [rl_json::json normalize $payload_obj]
    } else {
        set payload_json $payload
    }
    set payload_b64 [acme::base64url_encode $payload_json]
    
    # Create signature input as byte array
    set signature_input "${header_b64}.${payload_b64}"
    set signature_input_bytes [encoding convertto utf-8 $signature_input]
    
    # Sign with private key
    set signature [tossl::rsa::sign -privkey $key_private -alg sha256 $signature_input_bytes]
    set signature_b64 [acme::base64url_encode $signature]
    
    # Return JWS
    set jws_obj [rl_json::json object protected [list string $header_b64] payload [list string $payload_b64] signature [list string $signature_b64]]
    return [rl_json::json normalize $jws_obj]
}

# Extract JWK (JSON Web Key) from private key
proc acme::extract_jwk {key_private} {
    # Use TOSSL's JWK extraction
    set jwk_dict [tossl::jwk::extract -key $key_private]
    
    # Convert dict to JSON format expected by ACME
    set jwk_obj [rl_json::json object]
    dict for {key value} $jwk_dict {
        rl_json::json set jwk_obj $key $value
    }
    
    return $jwk_obj
}

# Base64URL encoding (RFC 4648)
proc acme::base64url_encode {data} {
    set b64 [tossl::base64::encode $data]
    # Remove padding and replace characters
    set b64 [string map {+ - / _ = ""} $b64]
    return $b64
}

# Base64URL decoding
proc acme::base64url_decode {data} {
    # Add padding back
    set len [string length $data]
    set pad [expr {4 - ($len % 4)}]
    if {$pad != 4} {
        append data [string repeat "=" $pad]
    }
    # Replace characters back
    set b64 [string map {- + _ /} $data]
    return [tossl::base64::decode $b64]
}

# Get ACME directory and extract endpoints
proc acme::get_directory {directory_url} {
    set token [http::geturl $directory_url -headers [list "User-Agent" "ToSSL-ACME-Client/1.0"]]
    set status [http::status $token]
    if {$status ne "ok"} {
        http::cleanup $token
        error "Failed to fetch directory: $status"
    }
    
    set data [http::data $token]
    http::cleanup $token
    
    set directory [rl_json::json get $data]
    return $directory
}

# Get nonce from ACME server
proc acme::get_nonce {directory_url} {
    set token [http::geturl $directory_url -headers [list "User-Agent" "ToSSL-ACME-Client/1.0"]]
    set status [http::status $token]
    if {$status ne "ok"} {
        http::cleanup $token
        error "Failed to get directory: $status"
    }
    
    set headers [http::meta $token]
    set nonce ""
    foreach {name value} $headers {
        if {[string tolower $name] eq "replay-nonce"} {
            set nonce $value
            break
        }
    }
    http::cleanup $token
    
    if {$nonce eq ""} {
        error "No nonce received from ACME server"
    }
    
    return $nonce
}

# Make authenticated ACME request
proc acme::acme_request {url payload key_private directory_url} {
    # Get nonce from the directory URL
    set nonce [acme::get_nonce $directory_url]
    
    # Create JWS
    set jws [acme::create_jws $payload $url $nonce $key_private]
    # Make HTTP request
    set token [http::geturl $url \
        -method POST \
        -headers [list \
            "Content-Type" "application/jose+json" \
            "User-Agent" "ToSSL-ACME-Client/1.0"] \
        -query $jws]
    
    set status [http::status $token]
    if {$status ne "ok"} {
        http::cleanup $token
        error "HTTP request failed: $status"
    }
    
    set response_code [http::ncode $token]
    set response_body [http::data $token]
    set response_headers [http::meta $token]
    
    http::cleanup $token
    
    return [dict create \
        code $response_code \
        body $response_body \
        headers $response_headers]
}

# Create new account
proc acme::create_account {key_private email directory} {
    set new_account_url [dict get $directory newAccount]
    set contact_array [rl_json::json array [list string mailto:$email]]
    set payload_obj [rl_json::json object termsOfServiceAgreed {boolean true} contact [list array [list string mailto:$email]]]
    set payload [rl_json::json normalize $payload_obj]
    
    set response [acme::acme_request \
        $new_account_url \
        $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 201} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to create account: [dict get $response code] - [dict get $response body]"
    }
}

# Create order for certificate
proc acme::create_order {key_private domains directory} {
    set new_order_url [dict get $directory newOrder]
    set identifiers {}
    foreach domain $domains {
        set identifier_obj [rl_json::json object type {string dns} value [list string $domain]]
        lappend identifiers $identifier_obj
    }
    set identifiers_array [rl_json::json array {*}$identifiers]
    set payload_obj [rl_json::json object identifiers {json $identifiers_array}]
    set payload [rl_json::json normalize $payload_obj]
    
    set response [acme::acme_request \
        $new_order_url \
        $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 201} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to create order: [dict get $response code] - [dict get $response body]"
    }
}

# Get authorization challenges
proc acme::get_authorization {auth_url key_private directory} {
    set payload ""
    
    set response [acme::acme_request $auth_url $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 200} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to get authorization: [dict get $response code] - [dict get $response body]"
    }
}

# Complete HTTP-01 challenge
proc acme::complete_http_challenge {challenge_url key_private key_authorization directory} {
    set payload_obj [rl_json::json object keyAuthorization {string $key_authorization}]; set payload [rl_json::json normalize $payload_obj]
    
    set response [acme::acme_request $challenge_url $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 200} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to complete HTTP challenge: [dict get $response code] - [dict get $response body]"
    }
}

# Generate key authorization for HTTP-01 challenge
proc acme::generate_key_authorization {token key_private} {
    # Extract JWK using TOSSL
    set jwk [acme::extract_jwk $key_private]
    set jwk_json [rl_json::json normalize $jwk]
    
    # Generate JWK thumbprint using TOSSL
    set jwk_thumbprint [tossl::jwk::thumbprint -jwk $jwk_json]
    
    # Create key authorization
    return "${token}.${jwk_thumbprint}"
}

# Finalize order and get certificate
proc acme::finalize_order {finalize_url key_private csr_pem directory} {
    set csr_der [acme::pem_to_der $csr_pem]
    set csr_b64 [acme::base64url_encode $csr_der]
    set payload_obj [rl_json::json object csr {string $csr_b64}]; set payload [rl_json::json normalize $payload_obj]
    
    set response [acme::acme_request $finalize_url $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 200} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to finalize order: [dict get $response code] - [dict get $response body]"
    }
}

# Download certificate
proc acme::download_certificate {cert_url key_private directory} {
    set payload ""
    
    set response [acme::acme_request $cert_url $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 200} {
        return [dict get $response body]
    } else {
        error "Failed to download certificate: [dict get $response code] - [dict get $response body]"
    }
}

# Convert PEM to DER
proc acme::pem_to_der {pem_data} {
    # Remove header/footer and decode base64
    set lines [split $pem_data "\n"]
    set der_data ""
    set in_cert 0
    
    foreach line $lines {
        if {[string match "*BEGIN*" $line]} {
            set in_cert 1
            continue
        }
        if {[string match "*END*" $line]} {
            break
        }
        if {$in_cert} {
            append der_data [string trim $line]
        }
    }
    
    return [tossl::base64::decode $der_data]
}

# Main ACME certificate request function
proc acme::request_certificate {domains email {key_type "rsa"} {directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"}} {
    puts "Starting ACME certificate request for domains: $domains"
    puts "Using ACME directory: $directory_url"
    
    # Generate account key
    puts "Generating account key..."
    set account_keys [acme::generate_account_key $key_type]
    set account_private [dict get $account_keys private]
    
    # Get directory and create account
    puts "Fetching ACME directory..."
    set directory [acme::get_directory $directory_url]
    puts "Creating ACME account..."
    set account [acme::create_account $account_private $email $directory]
    
    # Create order
    puts "Creating certificate order..."
    set order [acme::create_order $account_private $domains $directory]
    
    # Process each authorization
    foreach auth_url [dict get $order authorizations] {
        puts "Processing authorization: $auth_url"
        set auth [acme::get_authorization $auth_url $account_private $directory]
        set identifier [dict get [lindex [dict get $auth identifier] 0] value]
        
        # Find HTTP-01 challenge
        set http_challenge ""
        foreach challenge [dict get $auth challenges] {
            if {[dict get $challenge type] eq "http-01"} {
                set http_challenge $challenge
                break
            }
        }
        
        if {$http_challenge eq ""} {
            error "No HTTP-01 challenge found for domain: $identifier"
        }
        
        # Generate key authorization
        set token [dict get $http_challenge token]
        set key_auth [acme::generate_key_authorization $token $account_private]
        
        puts "HTTP-01 challenge for $identifier:"
        puts "  Token: $token"
        puts "  Key Authorization: $key_auth"
        puts "  Verification URL: http://$identifier/.well-known/acme-challenge/$token"
        puts ""
        puts "Please serve the key authorization at the verification URL, then press Enter to continue..."
        gets stdin
        
        # Complete challenge
        set challenge_url [dict get $http_challenge url]
        acme::complete_http_challenge $challenge_url $account_private $key_auth $directory
        
        # Wait for validation
        puts "Waiting for challenge validation..."
        while {1} {
            after 2000
            set auth_status [acme::get_authorization $auth_url $account_private $directory]
            set status [dict get $auth_status status]
            if {$status eq "valid"} {
                puts "Authorization validated successfully!"
                break
            } elseif {$status eq "invalid"} {
                error "Authorization failed: [dict get $auth_status]"
            }
        }
    }
    
    # Generate certificate key and CSR
    puts "Generating certificate key and CSR..."
    set cert_keys [acme::generate_account_key $key_type]
    set cert_private [dict get $cert_keys private]
    set cert_public [dict get $cert_keys public]
    
    # Create CSR (simplified - you'd need a proper CSR implementation)
    set csr_pem [acme::create_csr $domains $cert_private]
    
    # Finalize order
    puts "Finalizing order..."
    set final_order [acme::finalize_order [dict get $order finalize] $account_private $csr_pem $directory]
    
    # Wait for certificate
    puts "Waiting for certificate issuance..."
    while {1} {
        after 2000
        set order_status [acme::get_order_status [dict get $order url] $account_private $directory]
        set status [dict get $order_status status]
        if {$status eq "valid"} {
            puts "Certificate issued successfully!"
            break
        } elseif {$status eq "invalid"} {
            error "Certificate issuance failed: [dict get $order_status]"
        }
    }
    
    # Download certificate
    puts "Downloading certificate..."
    set certificate [acme::download_certificate [dict get $final_order certificate] $account_private $directory]
    
    # Save files
    set timestamp [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
    set cert_file "cert_${timestamp}.pem"
    set key_file "key_${timestamp}.pem"
    
    set f [open $cert_file w]
    puts -nonewline $f $certificate
    close $f
    
    set f [open $key_file w]
    puts -nonewline $f $cert_private
    close $f
    
    puts "Certificate saved to: $cert_file"
    puts "Private key saved to: $key_file"
    
    return [dict create \
        certificate $certificate \
        private_key $cert_private \
        cert_file $cert_file \
        key_file $key_file]
}

# Get order status
proc acme::get_order_status {order_url key_private directory} {
    set payload ""
    
    set response [acme::acme_request $order_url $payload $key_private [dict get $directory newNonce]]
    
    if {[dict get $response code] == 200} {
        return [rl_json::json get [dict get $response body]]
    } else {
        error "Failed to get order status: [dict get $response code] - [dict get $response body]"
    }
}

# Create CSR (Certificate Signing Request)
proc acme::create_csr {domains private_key} {
    # Get public key from private key
    set public_key [tossl::key::getpub $private_key]
    
    # Create subject (use first domain as CN)
    set primary_domain [lindex $domains 0]
    set subject "CN=$primary_domain"
    
    # Create key usage for server certificates
    set key_usage {digitalSignature keyEncipherment}
    
    # Create CSR using TOSSL (basic version without extensions)
    set csr [tossl::csr::create -subject $subject -pubkey $public_key -privkey $private_key]
    
    return $csr
}

# Example usage
if {[info exists argv] && [llength $argv] >= 2} {
    set domains [lindex $argv 0]
    set email [lindex $argv 1]
    set key_type "rsa"
    set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
    set use_staging 1
    set i 2
    while {$i < [llength $argv]} {
        set arg [lindex $argv $i]
        if {$arg eq "-production"} {
            set directory_url "https://acme-v02.api.letsencrypt.org/directory"
            set use_staging 0
        } elseif {$arg eq "-staging"} {
            set directory_url "https://acme-staging-v02.api.letsencrypt.org/directory"
            set use_staging 1
        } elseif {$arg in {rsa ec}} {
            set key_type $arg
        }
        incr i
    }

    puts "ACME Certificate Request Tool"
    puts "============================="
    puts "Domains: $domains"
    puts "Email: $email"
    puts "Key type: $key_type"
    puts "ACME Directory: $directory_url ([expr {$use_staging ? "STAGING" : "PRODUCTION"}])"
    puts ""

    if {[catch {
        acme::request_certificate $domains $email $key_type $directory_url
    } result]} {
        puts "Error: $result"
        exit 1
    }
} else {
    puts "Usage: tclsh acme_client.tcl <domains> <email> ?key_type? ?-staging|-production?"
    puts "  domains: space-separated list of domain names"
    puts "  email: contact email address"
    puts "  key_type: rsa or ec (default: rsa)"
    puts "  -staging: Use Let's Encrypt staging (default, safe for testing)"
    puts "  -production: Use Let's Encrypt production (real certs, be careful!)"
    puts ""
    puts "Example:"
    puts "  tclsh acme_client.tcl \"example.com www.example.com\" user@example.com -staging"
    puts "  tclsh acme_client.tcl \"example.com\" user@example.com ec -production"
} 