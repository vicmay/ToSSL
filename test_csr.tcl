load ./libtossl.so
# Generate RSA key pair
set keypair [tossl::key::generate -type rsa -bits 2048]
puts "DEBUG: keypair = $keypair"
set privkey [dict get $keypair private]
set pubkey [dict get $keypair public]
# Subject as dict for full DN
set subject [dict create CN test.example.com O ExampleOrg OU TestDept L TestCity ST TestState C US emailAddress test@example.com]
# Extensions as list of dicts
set extensions [list \
    [dict create oid subjectAltName value {DNS:test.example.com,DNS:www.test.example.com} critical 0] \
    [dict create oid keyUsage value {digitalSignature,keyEncipherment} critical 1]
]
# Attributes as list of dicts
set attributes [list \
    [dict create oid challengePassword value mypassword]
]
# Create CSR with full compliance
set csr [tossl::csr::create -key $privkey -subject $subject -extensions $extensions -attributes $attributes]
puts "CSR created successfully"
puts [tossl::csr::parse $csr]
puts "CSR valid: [tossl::csr::validate $csr]"
puts "CSR fingerprint: [tossl::csr::fingerprint $csr sha256]"
