#!/usr/bin/env tclsh
# ACME Certificate Request Example using TOSSL
# This example demonstrates the basic workflow for requesting a certificate from Let's Encrypt

if {[catch {package require tossl}]} {
    load ./libtossl.so
}
package require http
package require tls

# Simple ACME client example
namespace eval acme_example {
    variable account_key ""
    variable account_url ""
    variable directory_url "https://acme-v02.api.letsencrypt.org/directory"
}

# Generate account key
proc acme_example::generate_account_key {} {
    puts "Generating RSA account key..."
    set keys [tossl::key::generate -type rsa -bits 2048]
    set account_key [dict get $keys private]
    puts "Account key generated successfully"
    return $keys
}

# Get ACME directory
proc acme_example::get_directory {} {
    variable directory_url
    puts "Fetching ACME directory from $directory_url"
    
    # Configure TLS for HTTPS
    ::tls::init -servername acme-v02.api.letsencrypt.org
    http::register https 443 ::tls::socket
    
    set token [http::geturl $directory_url]
    set status [http::status $token]
    if {$status ne "ok"} {
        http::cleanup $token
        error "Failed to fetch directory: $status"
    }
    
    set data [http::data $token]
    http::cleanup $token
    
    puts "Directory fetched successfully"
    return $data
}

# Create account
proc acme_example::create_account {email} {
    variable account_key
    variable account_url
    
    puts "Creating ACME account for $email"
    
    # This is a simplified version - in practice you'd need proper JWS signing
    # For demonstration, we'll show the structure
    
    set payload "{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:$email\"]}"
    
    puts "Account creation payload: $payload"
    puts "Note: This would need to be signed with the account key"
    
    # In a real implementation, you would:
    # 1. Create JWS header with account key
    # 2. Sign the payload
    # 3. Send to new-acct endpoint
    
    puts "Account creation would proceed here..."
    return "https://acme-v02.api.letsencrypt.org/acme/acct/example"
}

# Create certificate order
proc acme_example::create_order {domains} {
    puts "Creating certificate order for domains: $domains"
    
    set identifiers {}
    foreach domain $domains {
        lappend identifiers "{\"type\":\"dns\",\"value\":\"$domain\"}"
    }
    
    set payload "{\"identifiers\":\[[join $identifiers ,]\]}"
    puts "Order creation payload: $payload"
    
    # In a real implementation, you would:
    # 1. Sign this payload with account key
    # 2. Send to new-order endpoint
    # 3. Get back order with authorization URLs
    
    puts "Order creation would proceed here..."
    return "https://acme-v02.api.letsencrypt.org/acme/order/example"
}

# Generate certificate key and CSR
proc acme_example::generate_certificate_key {domains} {
    puts "Generating certificate key pair..."
    set keys [tossl::key::generate -type rsa -bits 2048]
    set cert_private [dict get $keys private]
    set cert_public [dict get $keys public]
    
    puts "Certificate key generated successfully"
    
    # Create a simple CSR (Certificate Signing Request)
    puts "Creating Certificate Signing Request..."
    
    # In practice, you'd create a proper CSR with:
    # - Subject: CN=primary_domain
    # - Subject Alternative Names: all domains
    # - Signed with the certificate private key
    
    set primary_domain [lindex $domains 0]
    puts "CSR would be created for: $primary_domain"
    puts "With SANs: $domains"
    
    return [dict create \
        private_key $cert_private \
        public_key $cert_public \
        csr "placeholder_csr"]
}

# Demonstrate HTTP-01 challenge
proc acme_example::demonstrate_http_challenge {domain token} {
    puts "HTTP-01 Challenge for domain: $domain"
    puts "Token: $token"
    
    # Generate key authorization (simplified)
    set key_authorization "${token}.example_thumbprint"
    puts "Key Authorization: $key_authorization"
    
    puts "Challenge URL: http://$domain/.well-known/acme-challenge/$token"
    puts "Expected response: $key_authorization"
    
    puts ""
    puts "To complete this challenge, you would:"
    puts "1. Serve the key authorization at the challenge URL"
    puts "2. Wait for Let's Encrypt to verify it"
    puts "3. Notify the ACME server that the challenge is ready"
    
    return $key_authorization
}

# Finalize certificate order
proc acme_example::finalize_order {csr} {
    puts "Finalizing certificate order..."
    puts "CSR: $csr"
    
    # In practice, you would:
    # 1. Encode the CSR in base64url
    # 2. Sign the finalize payload with account key
    # 3. Send to finalize endpoint
    # 4. Wait for certificate issuance
    
    puts "Order finalization would proceed here..."
    return "https://acme-v02.api.letsencrypt.org/acme/cert/example"
}

# Download certificate
proc acme_example::download_certificate {cert_url} {
    puts "Downloading certificate from: $cert_url"
    
    # In practice, you would:
    # 1. Make authenticated request to cert URL
    # 2. Download the certificate chain
    
    puts "Certificate download would proceed here..."
    
    # Return a sample certificate (this is just for demonstration)
    return "-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----"
}

# Save certificate and key to files
proc acme_example::save_certificate {certificate private_key {prefix "acme"}} {
    set timestamp [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
    set cert_file "${prefix}_cert_${timestamp}.pem"
    set key_file "${prefix}_key_${timestamp}.pem"
    
    # Save certificate
    set f [open $cert_file w]
    puts -nonewline $f $certificate
    close $f
    
    # Save private key
    set f [open $key_file w]
    puts -nonewline $f $private_key
    close $f
    
    puts "Certificate saved to: $cert_file"
    puts "Private key saved to: $key_file"
    
    return [dict create \
        cert_file $cert_file \
        key_file $key_file]
}

# Main workflow demonstration
proc acme_example::demonstrate_workflow {domains email} {
    puts "ACME Certificate Request Workflow Demonstration"
    puts "=============================================="
    puts "Domains: $domains"
    puts "Email: $email"
    puts ""
    
    # Step 1: Generate account key
    set account_keys [acme_example::generate_account_key]
    set account_private [dict get $account_keys private]
    
    # Step 2: Get ACME directory
    set directory [acme_example::get_directory]
    puts "Directory endpoints available"
    
    # Step 3: Create account
    set account_url [acme_example::create_account $email]
    
    # Step 4: Create order
    set order_url [acme_example::create_order $domains]
    
    # Step 5: Demonstrate HTTP-01 challenge
    set token "example_token_12345"
    set key_auth [acme_example::demonstrate_http_challenge [lindex $domains 0] $token]
    
    puts ""
    puts "Press Enter to continue with certificate generation..."
    gets stdin
    
    # Step 6: Generate certificate key and CSR
    set cert_data [acme_example::generate_certificate_key $domains]
    set cert_private [dict get $cert_data private_key]
    set csr [dict get $cert_data csr]
    
    # Step 7: Finalize order
    set cert_url [acme_example::finalize_order $csr]
    
    # Step 8: Download certificate
    set certificate [acme_example::download_certificate $cert_url]
    
    # Step 9: Save files
    set files [acme_example::save_certificate $certificate $cert_private]
    
    puts ""
    puts "Workflow demonstration completed!"
    puts "Certificate and key files have been saved."
    puts ""
    puts "Next steps:"
    puts "1. Implement proper JWS signing for ACME requests"
    puts "2. Add proper CSR generation with SANs"
    puts "3. Implement challenge validation"
    puts "4. Add error handling and retry logic"
    
    return [dict create \
        account_key $account_private \
        certificate $certificate \
        cert_private $cert_private \
        files $files]
}

# Command line interface
if {[info exists argv] && [llength $argv] >= 2} {
    set domains [lindex $argv 0]
    set email [lindex $argv 1]
    
    puts "ACME Certificate Request Example"
    puts "==============================="
    puts "This is a demonstration of the ACME workflow using TOSSL"
    puts "Note: This example does not make actual ACME requests"
    puts "It demonstrates the structure and steps involved"
    puts ""
    
    if {[catch {
        acme_example::demonstrate_workflow $domains $email
    } result]} {
        puts "Error: $result"
        exit 1
    }
} else {
    puts "Usage: tclsh acme_example.tcl <domains> <email>"
    puts "  domains: space-separated list of domain names"
    puts "  email: contact email address"
    puts ""
    puts "Example:"
    puts "  tclsh acme_example.tcl \"example.com www.example.com\" user@example.com"
    puts ""
    puts "Note: This is a demonstration script that shows the ACME workflow"
    puts "structure. It does not make actual requests to Let's Encrypt."
} 