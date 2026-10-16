#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
# A repeated Deploy for an already healthy Debian VM is a no-op.  In particular, do not tear
# down its working DNAT rule and then mistake its reserved port for a conflicting publication.
if sh "$script_dir/check-publication.sh" "$1" >/dev/null 2>&1; then
  exit 0
fi
HF_HIGH_DIAGNOSE_DHCP=1 exec sh "$(CDPATH= cd -- "$(dirname "$0")/../../high-ubuntu-ssh/scripts" && pwd)/publish-ssh.sh" "$1" "$2" 22
