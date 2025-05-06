#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file incorporates work from the OpenSSL project,
# developed by Eric Young and Tim Hudson.
#
# Export a ToSSL-generated RSA private key to PEM for OpenSSL CLI testing
if {[catch {package require tossl}]} {
    load ./libtossl.so
}
set keys [tossl::key::generate]
set priv [dict get $keys private]
set f [open "test_rsa_priv.pem" w]
puts $f $priv
close $f
puts "Wrote test_rsa_priv.pem"
