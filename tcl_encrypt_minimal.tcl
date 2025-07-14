if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set key [binary format H* 00112233445566778899aabbccddeeff]
set iv  [binary format H* 0102030405060708090a0b0c0d0e0f10]
set plain "Test message!"
puts "Minimal encrypt test (standalone):"
puts "key type: [tcl::unsupported::representation $key] length: [string length $key]"
puts "iv type: [tcl::unsupported::representation $iv] length: [string length $iv]"
puts "plain type: [tcl::unsupported::representation $plain] length: [string length $plain]"
puts "args: -alg aes-128-cbc -key $key -iv $iv $plain"
set cipher [eval [list tossl::encrypt -alg aes-128-cbc -key $key -iv $iv $plain]]
puts "Minimal encrypt test succeeded." 