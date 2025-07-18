# debug_ed448_cli.tcl
load ./libtossl.so

set priv [read [open "test_ed448_priv.pem"]]
set pub [read [open "test_ed448_pub.pem"]]
set data "test message"
set rc [catch {set sig [tossl::ed448::sign $priv $data]} err]
if {$rc != 0} {
    puts stderr "FAIL: could not sign: $err"
    exit 1
}
set rc [catch {set ok [tossl::ed448::verify $pub $data $sig]} err]
if {$rc == 0} {
    puts "verify result: $ok"
} else {
    puts stderr "FAIL: verify error: $err"
    exit 2
} 