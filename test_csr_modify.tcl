load ./libtossl.so; set keypair [tossl::key::generate -type rsa -bits 2048]; set privkey [dict get $keypair private]; set pubkey [dict get $keypair public]; set subject [dict create CN test.example.com]
set csr [tossl::csr::create -key $privkey -subject $subject]; puts "Original CSR:"; puts [tossl::csr::parse $csr]; set modified_csr [tossl::csr::modify $csr -subject "CN=modified.example.com,O=ExampleOrg" -key $privkey]
puts "Modified CSR:"; puts [tossl::csr::parse $modified_csr]
puts "CSR valid: [tossl::csr::validate $modified_csr]"
