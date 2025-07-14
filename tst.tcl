load ./libtossl.so; set cert [string trim [read [open "tmpcert.pem"]]]; puts [tossl::x509::parse $cert]
