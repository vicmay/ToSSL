#!/bin/bash
cd /home/user/CascadeProjects/ToSSL
./test_openpgp_signatures.tcl 2>&1 | tee debug_output.log
