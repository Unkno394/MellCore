#!/bin/sh
HF_HIGH_DIAGNOSE_DHCP=1 exec sh "$(CDPATH= cd -- "$(dirname "$0")/../../high-ubuntu-ssh/scripts" && pwd)/publish-ssh.sh" "$1" "$2" 22
