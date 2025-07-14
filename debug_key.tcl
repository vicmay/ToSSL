load ./libtossl.so; set privkey [tossl::key::generate rsa 2048]; puts "PRIVATE KEY:"; puts $privkey; set pubkey [tossl::key::getpub $privkey]; puts "PUBLIC KEY:"; puts $pubkey
